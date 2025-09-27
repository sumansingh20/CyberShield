import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import User from "@/src/core/lib/models/User"
import OTP from "@/src/core/lib/models/OTP"
import { generateOTP } from "@/src/core/lib/utils/otp"
import { sendOTPEmail } from "@/src/core/lib/utils/email"
import { sendOTPSMS } from "@/src/core/lib/utils/sms"

export async function POST(req: NextRequest) {
  try {
    await connectDB()

    const { email } = await req.json()

    const user = await User.findOne({ email })

    if (!user) {
      // Don't reveal if user exists
      return NextResponse.json({
        message: "If the email exists, an OTP has been sent",
      })
    }

    // Generate OTPs
    const emailOTP = generateOTP()
    const phoneOTP = generateOTP()

    // Delete existing OTPs
    await OTP.deleteMany({ userId: user._id, purpose: "forgot-password" })

    // Save new OTP
    const otpDoc = new OTP({
      userId: user._id,
      email: user.email,
      phone: user.phone,
      emailOTP,
      phoneOTP,
      purpose: "forgot-password",
    })

    await otpDoc.save()

    // Send OTPs
    await Promise.all([
      sendOTPEmail(user.email, emailOTP, "password reset"),
      sendOTPSMS(user.phone, phoneOTP, "password reset"),
    ])

    return NextResponse.json({
      message: "If the email exists, an OTP has been sent",
      userId: user._id,
    })
  } catch (error) {
    console.error("Forgot password error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
