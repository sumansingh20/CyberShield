import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import User from "@/src/core/lib/models/User"
import OTP from "@/src/core/lib/models/OTP"
import { isOTPExpired } from "@/src/core/lib/utils/otp"

export async function POST(req: NextRequest) {
  try {
    await connectDB()

    const { userId, emailOTP, phoneOTP, newPassword } = await req.json()

    if (!userId || !emailOTP || !phoneOTP || !newPassword) {
      return NextResponse.json({ error: "All fields are required" }, { status: 400 })
    }

    if (newPassword.length < 8) {
      return NextResponse.json({ error: "Password must be at least 8 characters long" }, { status: 400 })
    }

    // Find OTP document
    // @ts-ignore - Mongoose type union issue
    const otpDoc = await OTP.findOne({
      userId,
      purpose: "forgot-password",
    })

    if (!otpDoc) {
      return NextResponse.json({ error: "OTP not found or expired" }, { status: 400 })
    }

    // Check if OTP is expired
    if (isOTPExpired(otpDoc.expiresAt)) {
      // @ts-ignore - Mongoose type union issue
      await OTP.deleteOne({ _id: otpDoc._id })
      return NextResponse.json({ error: "OTP expired" }, { status: 400 })
    }

    // Check attempts
    if (otpDoc.attempts >= otpDoc.maxAttempts) {
      // @ts-ignore - Mongoose type union issue
      await OTP.deleteOne({ _id: otpDoc._id })
      return NextResponse.json({ error: "Maximum attempts exceeded" }, { status: 400 })
    }

    // Verify OTPs
    if (otpDoc.emailOTP !== emailOTP || otpDoc.phoneOTP !== phoneOTP) {
      otpDoc.attempts += 1
      await otpDoc.save()

      return NextResponse.json({ error: "Invalid OTP" }, { status: 400 })
    }

    // Update password
    // @ts-ignore - Mongoose type union issue
    const user = await User.findById(userId)
    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 })
    }

    user.password = newPassword
    user.passwordChangedAt = new Date()
    
    // Reset login attempts if account was locked
    if (user.loginAttempts > 0) {
      await user.resetLoginAttempts()
    }
    
    await user.save()

    // Delete OTP
    // @ts-ignore - Mongoose type union issue
    await OTP.deleteOne({ _id: otpDoc._id })

    return NextResponse.json({
      message: "Password reset successfully",
    })
  } catch (error) {
    console.error("Reset password error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
