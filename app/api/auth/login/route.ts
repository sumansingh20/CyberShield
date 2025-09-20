import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import User from "@/lib/models/User"
import OTP from "@/lib/models/OTP"
import { generateOTP } from "@/lib/utils/otp"
import { sendOTPEmail } from "@/lib/utils/email"
import { sendOTPSMS } from "@/lib/utils/sms"
import { rateLimit } from "@/lib/middleware/rate-limit"
import { withCSRF } from "@/lib/middleware/csrf"

async function loginHandler(req: NextRequest) {
  try {
    await connectDB()

    const { email, password, recaptchaToken } = await req.json()

    // Skip reCAPTCHA in development mode
    if (process.env.NODE_ENV !== 'development' && process.env.RECAPTCHA_SECRET_KEY && recaptchaToken) {
      const recaptchaResponse = await fetch(
        `https://www.google.com/recaptcha/api/siteverify?secret=${process.env.RECAPTCHA_SECRET_KEY}&response=${recaptchaToken}`,
        { method: "POST" },
      )
      const recaptchaData = await recaptchaResponse.json()

      if (!recaptchaData.success) {
        return NextResponse.json({ error: "reCAPTCHA verification failed" }, { status: 400 })
      }
    } else {
      console.log('🔧 Development Mode: Skipping reCAPTCHA verification')
    }

    // Find user (only when database is connected)
    // @ts-ignore - Mongoose type union issue
    const user = await User.findOne({ email })

    if (!user || !(await user.comparePassword(password))) {
      return NextResponse.json({ error: "Invalid credentials" }, { status: 401 })
    }

    if (!user.isVerified) {
      return NextResponse.json({ error: "Please verify your account first" }, { status: 401 })
    }

    // Generate OTPs for 2FA
    const emailOTP = generateOTP()
    const phoneOTP = generateOTP()

    // Delete existing OTPs
    // @ts-ignore - Mongoose type union issue
    await OTP.deleteMany({ userId: user._id, purpose: "login" })

    // Save new OTP
    const otpDoc = new OTP({
      userId: user._id,
      email: user.email,
      phone: user.phone,
      emailOTP,
      phoneOTP,
      purpose: "login",
    })

    await otpDoc.save()

    // Send OTPs
    await Promise.all([sendOTPEmail(user.email, emailOTP, "login"), sendOTPSMS(user.phone, phoneOTP, "login")])

    return NextResponse.json({
      message: "OTP sent to your email and phone",
      userId: user._id,
      requiresOTP: true,
    })
  } catch (error) {
    console.error("Login error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = rateLimit()(withCSRF(loginHandler))
