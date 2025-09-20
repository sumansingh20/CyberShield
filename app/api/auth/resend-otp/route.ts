import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import User from "@/lib/models/User"
import OTP from "@/lib/models/OTP"
import { generateOTP } from "@/lib/utils/otp"
import { sendOTPEmail } from "@/lib/utils/email"
import { sendOTPSMS } from "@/lib/utils/sms"
import { rateLimit } from "@/lib/middleware/rate-limit"

async function resendOTPHandler(req: NextRequest) {
  try {
    await connectDB()

    const { userId, purpose } = await req.json()

    // Validate required fields
    if (!userId || !purpose) {
      return NextResponse.json({ error: "User ID and purpose are required" }, { status: 400 })
    }

    // Validate purpose
    const validPurposes = ["login", "registration", "forgot-password"]
    if (!validPurposes.includes(purpose)) {
      return NextResponse.json({ error: "Invalid purpose" }, { status: 400 })
    }

    // Find user
    // @ts-ignore - Mongoose type union issue
    const user = await User.findById(userId)
    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 })
    }

    // Check if there's an existing recent OTP (rate limiting)
    // @ts-ignore - Mongoose type union issue
    const existingOTP = await OTP.findOne({ 
      userId, 
      purpose,
      createdAt: { $gt: new Date(Date.now() - 60000) } // Within last minute
    })

    if (existingOTP) {
      return NextResponse.json({ 
        error: "Please wait before requesting a new OTP" 
      }, { status: 429 })
    }

    // Generate new OTPs
    const emailOTP = generateOTP()
    const phoneOTP = generateOTP()

    // Delete existing OTPs for this user and purpose
    // @ts-ignore - Mongoose type union issue
    await OTP.deleteMany({ userId, purpose })

    // Save new OTP
    const otpDoc = new OTP({
      userId,
      email: user.email,
      phone: user.phone,
      emailOTP,
      phoneOTP,
      purpose,
    })

    await otpDoc.save()

    // Send OTPs
    await Promise.all([
      sendOTPEmail(user.email, emailOTP, purpose),
      sendOTPSMS(user.phone, phoneOTP, purpose),
    ])

    return NextResponse.json({
      message: "New OTP codes sent successfully",
      success: true
    })
  } catch (error) {
    console.error("Resend OTP error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = rateLimit()(resendOTPHandler)