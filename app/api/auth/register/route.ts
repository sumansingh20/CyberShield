import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import User from "@/lib/models/User"
import OTP from "@/lib/models/OTP"
import { generateOTP, formatPhoneNumber } from "@/lib/utils/otp"
import { sendOTPEmail } from "@/lib/utils/email"
import { sendOTPSMS } from "@/lib/utils/sms"
import { rateLimit } from "@/lib/middleware/rate-limit"

async function registerHandler(req: NextRequest) {
  try {
    const db = await connectDB()

    const { username, email, phone, password, recaptchaToken, firstName, lastName, agreeToTerms } = await req.json()

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

    // Development mode - mock registration
    if (!db) {
      console.log(`[DEV] Mock registration for: ${email}`)
      
      // Generate mock OTPs
      const emailOTP = Math.floor(100000 + Math.random() * 900000).toString()
      const phoneOTP = Math.floor(100000 + Math.random() * 900000).toString()
      console.log(`[DEV] Email OTP for ${email}: ${emailOTP}`)
      console.log(`[DEV] Phone OTP for ${phone}: ${phoneOTP}`)
      
      // Store mock user data in memory
      const mockUserId = `mock-user-${Date.now()}`
      const mockOTP = {
        userId: mockUserId,
        email,
        phone,
        emailOTP,
        phoneOTP,
        purpose: 'registration',
        expiresAt: new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
        attempts: 0,
        maxAttempts: 3
      }
      
      // Store in global for development
      if (!global.mockOTPs) {
        global.mockOTPs = new Map()
      }
      global.mockOTPs.set(mockUserId, mockOTP)
      
      return NextResponse.json({
        message: "Registration successful! Check console for OTP (development mode)",
        userId: mockUserId,
        email
      })
    }

    // Check if user already exists (only when database is connected)
    // @ts-ignore - Mongoose type union issue
    const existingUser = await User.findOne({
      $or: [{ email }, { username }],
    })

    if (existingUser) {
      // Check if they tried to register with the same email but different username
      if (existingUser.email === email) {
        // If they provided the correct password, treat it as a login attempt
        if (await existingUser.comparePassword(password)) {
          // User exists and password matches - send login OTPs
          const emailOTP = generateOTP()
          const phoneOTP = generateOTP()

          // Delete existing OTPs
          // @ts-ignore - Mongoose type union issue
          await OTP.deleteMany({ userId: existingUser._id, purpose: "login" })

          // Save new OTP
          const otpDoc = new OTP({
            userId: existingUser._id,
            email: existingUser.email,
            phone: existingUser.phone,
            emailOTP,
            phoneOTP,
            purpose: "login",
          })

          await otpDoc.save()

          // Send OTPs
          await Promise.all([
            sendOTPEmail(existingUser.email, emailOTP, "login"),
            sendOTPSMS(existingUser.phone, phoneOTP, "login")
          ])

          return NextResponse.json({
            message: "Account already exists. Proceeding with login.",
            userId: existingUser._id,
            requiresOTP: true,
            isExistingUser: true
          })
        }
      }
      
      // Username taken or wrong password
      return NextResponse.json({ 
        error: existingUser.email === email 
          ? "This email is already registered. Please login instead." 
          : "This username is already taken. Please choose another." 
      }, { status: 400 })
    }

    // Create user
    const user = new User({
      username,
      email,
      phone: formatPhoneNumber(phone),
      password,
      firstName,
      lastName,
      agreeToTerms,
    })

    await user.save()

    // Generate OTPs
    const emailOTP = generateOTP()
    const phoneOTP = generateOTP()

    // Save OTP
    const otpDoc = new OTP({
      userId: user._id,
      email,
      phone: user.phone,
      emailOTP,
      phoneOTP,
      purpose: "registration",
    })

    await otpDoc.save()

    // Send OTPs
    await Promise.all([sendOTPEmail(email, emailOTP, "registration"), sendOTPSMS(user.phone, phoneOTP, "registration")])

    return NextResponse.json({
      message: "Registration successful. Please verify your OTP.",
      userId: user._id,
    })
  } catch (error) {
    console.error("Registration error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = rateLimit()(registerHandler)
