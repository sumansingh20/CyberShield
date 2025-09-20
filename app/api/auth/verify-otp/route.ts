import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import User from "@/lib/models/User"
import OTP from "@/lib/models/OTP"
import { generateTokens } from "@/lib/utils/jwt"
import { isOTPExpired } from "@/lib/utils/otp"

export async function POST(req: NextRequest) {
  try {
    await connectDB()

    const { userId, emailOTP, phoneOTP, purpose } = await req.json()

    // Validate required fields
    if (!userId || !emailOTP || !phoneOTP || !purpose) {
      return NextResponse.json({ error: "All fields are required" }, { status: 400 })
    }

    let otpDoc

    // Development mode - use mock OTPs
    if (!await connectDB() && userId.startsWith('mock-user-')) {
      if (!global.mockOTPs) {
        return NextResponse.json({ error: "OTP not found or expired" }, { status: 400 })
      }

      otpDoc = global.mockOTPs.get(userId)
      if (!otpDoc) {
        return NextResponse.json({ error: "OTP not found or expired" }, { status: 400 })
      }
    } else {
      // Production mode - find OTP document in database
      // @ts-ignore - Mongoose type union issue
      otpDoc = await OTP.findOne({ userId, purpose })
      if (!otpDoc) {
        return NextResponse.json({ error: "OTP not found or expired" }, { status: 400 })
      }
    }

    // Check if OTP is expired
    if (isOTPExpired(otpDoc.expiresAt)) {
      if (!userId.startsWith('mock-user-')) {
        // @ts-ignore - Mongoose type union issue
        await OTP.deleteOne({ _id: otpDoc._id })
      } else {
        global.mockOTPs?.delete(userId)
      }
      return NextResponse.json({ error: "OTP expired" }, { status: 400 })
    }

    // Check attempts
    if (otpDoc.attempts >= otpDoc.maxAttempts) {
      if (!userId.startsWith('mock-user-')) {
        // @ts-ignore - Mongoose type union issue
        await OTP.deleteOne({ _id: otpDoc._id })
      } else {
        global.mockOTPs?.delete(userId)
      }
      return NextResponse.json({ error: "Maximum attempts exceeded" }, { status: 400 })
    }

    // Verify OTPs
    if (otpDoc.emailOTP !== emailOTP || otpDoc.phoneOTP !== phoneOTP) {
      // For mock users in development
      if (userId.startsWith('mock-user-')) {
        otpDoc.attempts += 1
        if (otpDoc.attempts >= otpDoc.maxAttempts) {
          global.mockOTPs?.delete(userId)
          return NextResponse.json({ error: "Maximum attempts exceeded" }, { status: 400 })
        }
        global.mockOTPs?.set(userId, otpDoc)
      } else {
        // For real users in database
        otpDoc.attempts += 1
        await otpDoc.save()
      }

      return NextResponse.json({ 
        error: `Invalid OTP. ${otpDoc.maxAttempts - otpDoc.attempts} attempts remaining.`,
        attemptsLeft: otpDoc.maxAttempts - otpDoc.attempts
      }, { status: 400 })
    }

    // Find user
    // @ts-ignore - Mongoose type union issue
    const user = await User.findById(userId)
    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 })
    }

    // Update user verification status if needed
    if (purpose === "registration") {
      user.isVerified = true
      await user.save()
    }

    // Generate tokens
    const tokens = generateTokens({
      userId: user._id.toString(),
      email: user.email,
      role: user.role,
    })

    // Delete OTP
    // @ts-ignore - Mongoose type union issue
    await OTP.deleteOne({ _id: otpDoc._id })

    return NextResponse.json({
      message: "OTP verified successfully",
      user: {
        id: user._id,
        username: user.username,
        email: user.email,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName,
        phone: user.phone,
      },
      ...tokens,
    })
  } catch (error) {
    console.error("OTP verification error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
