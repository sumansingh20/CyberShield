import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import User from "@/src/core/lib/models/User"
import Activity from "@/src/core/lib/models/Activity"
import SystemSettings from "@/src/core/lib/models/SystemSettings"
import { generateTokens } from "@/src/core/lib/utils/jwt"
import { verifyRecaptcha } from "@/src/core/lib/utils/recaptcha"
import { z } from "zod"

// Validation schema for registration
const registerSchema = z.object({
  username: z.string()
    .min(3, "Username must be at least 3 characters long")
    .max(30, "Username cannot exceed 30 characters")
    .regex(/^[a-zA-Z0-9_-]+$/, "Username can only contain letters, numbers, underscores and hyphens"),
  email: z.string().email("Invalid email address"),
  password: z.string()
    .min(8, "Password must be at least 8 characters long")
    .regex(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/, "Password must contain at least one uppercase letter, one lowercase letter, and one number"),
  firstName: z.string()
    .min(1, "First name is required")
    .max(50, "First name cannot exceed 50 characters"),
  lastName: z.string()
    .min(1, "Last name is required")
    .max(50, "Last name cannot exceed 50 characters"),
  phone: z.string().optional(),
  agreeToTerms: z.boolean().refine(val => val === true, "You must agree to terms"),
  // reCAPTCHA is optional - only required for production Vercel deployment
  recaptchaToken: z.string().optional().nullable()
})

async function registerHandler(req: NextRequest) {
  try {
    console.log("🔍 Registration attempt started...")
    
    // Parse and validate request body
    const body = await req.json()
    console.log("🔍 Received registration data:", JSON.stringify(body, null, 2))
    
    const validation = registerSchema.safeParse(body)
    
    if (!validation.success) {
      console.log("❌ Validation failed:", validation.error.errors)
      return NextResponse.json({
        success: false,
        message: "Invalid input data",
        errors: validation.error.errors
      }, { status: 400 })
    }

    console.log("✅ Validation passed")
    const { username, email, password, firstName, lastName, phone, agreeToTerms, recaptchaToken } = validation.data

    // Simple reCAPTCHA - only in production Vercel
    console.log("🔒 Checking reCAPTCHA...", { 
      hasToken: !!recaptchaToken, 
      nodeEnv: process.env.NODE_ENV,
      isVercel: process.env.VERCEL === '1'
    })
    
    // Only require reCAPTCHA in production Vercel deployment
    if (process.env.VERCEL === '1' && process.env.NODE_ENV === 'production') {
      if (!recaptchaToken) {
        return NextResponse.json({
          success: false,
          message: "reCAPTCHA verification is required"
        }, { status: 400 })
      }
      
      const recaptchaVerification = await verifyRecaptcha(recaptchaToken)
      if (!recaptchaVerification.success) {
        console.log("❌ reCAPTCHA verification failed:", recaptchaVerification.error)
        return NextResponse.json({
          success: false,
          message: "reCAPTCHA verification failed. Please try again."
        }, { status: 400 })
      }
      console.log("✅ reCAPTCHA verified successfully")
    } else {
      console.log("🔧 Development/Local: Skipping reCAPTCHA")
    }

    // Connect to database
    await connectDB()
    console.log("✅ Database connected")

    // Skip system settings check for now - enable registration by default in development
    // TODO: Re-enable system settings check after debugging
    /*
    const systemSettings = await SystemSettings.getInstance()
    if (!systemSettings.registrationEnabled) {
      return NextResponse.json({
        success: false,
        message: "Registration is currently disabled"
      }, { status: 403 })
    }
    */

    // Check if user already exists
    console.log("🔍 Checking for existing users...")
    const existingUserByEmail = await User.findOne({ email })
    if (existingUserByEmail) {
      console.log("❌ User with email already exists:", email)
      return NextResponse.json({
        success: false,
        message: "A user with this email already exists"
      }, { status: 409 })
    }

    const existingUserByUsername = await User.findOne({ username })
    if (existingUserByUsername) {
      console.log("❌ User with username already exists:", username)
      return NextResponse.json({
        success: false,
        message: "This username is already taken"
      }, { status: 409 })
    }

    console.log("✅ No existing users found, proceeding with creation...")

    // Create new user
    const newUser = await User.create({
      username,
      email,
      password,
      firstName,
      lastName,
      phone: phone || undefined,
      role: 'user', // Regular users get 'user' role
      isVerified: false, // Email verification required
      agreeToTerms,
      emailNotifications: true,
      smsNotifications: false,
      loginAlerts: true,
      sessionTimeout: '30'
    })

    // Generate verification token
    const verificationToken = newUser.generateVerificationToken()
    await newUser.save()

    // Log registration activity
    const userIP = req.headers.get('x-forwarded-for') || 
                  req.headers.get('x-real-ip') || 
                  '127.0.0.1'
    
    const userAgent = req.headers.get('user-agent') || 'Unknown'

    await Activity.create({
      userId: newUser._id,
      toolName: 'register',
      action: 'User registration',
      status: 'success',
      duration: 0,
      ipAddress: userIP,
      userAgent: userAgent
    }).catch(console.error)

    // TODO: Send verification email with verificationToken
    // For now, we'll auto-verify in development
    if (process.env.NODE_ENV === 'development') {
      await newUser.updateOne({ 
        isVerified: true,
        verificationToken: undefined
      })
    }

    return NextResponse.json({
      success: true,
      message: process.env.NODE_ENV === 'development' 
        ? "Registration successful! You can now log in."
        : "Registration successful! Please check your email to verify your account.",
      user: {
        id: newUser._id.toString(),
        email: newUser.email,
        username: newUser.username,
        firstName: newUser.firstName,
        lastName: newUser.lastName,
        role: newUser.role,
        isVerified: newUser.isVerified
      },
      requiresVerification: process.env.NODE_ENV !== 'development'
    }, { status: 201 })

  } catch (error) {
    console.error("❌ Registration error:", error)
    console.error("Error stack:", error instanceof Error ? error.stack : "No stack trace")
    
    // Handle specific MongoDB errors
    if (error instanceof Error) {
      if (error.message.includes('duplicate key')) {
        console.log("❌ Duplicate key error detected")
        return NextResponse.json({
          success: false,
          message: "A user with this email or username already exists"
        }, { status: 409 })
      }
      
      if (error.message.includes('validation')) {
        console.log("❌ MongoDB validation error detected")
        return NextResponse.json({
          success: false,
          message: "Database validation error: " + error.message
        }, { status: 400 })
      }
    }

    return NextResponse.json({
      success: false,
      message: "An error occurred during registration",
      debug: process.env.NODE_ENV === 'development' ? error instanceof Error ? error.message : 'Unknown error' : undefined
    }, { status: 500 })
  }
}

export const POST = registerHandler
