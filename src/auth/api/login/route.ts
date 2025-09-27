import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import User from "@/src/core/lib/models/User"
import Activity from "@/src/core/lib/models/Activity"
import { generateTokens } from "@/src/core/lib/utils/jwt"
import { signJWT } from "@/src/core/lib/utils/jwt-helper"
import { z } from "zod"

// Validation schema for login
const loginSchema = z.object({
  email: z.string().email("Invalid email address"),
  password: z.string().min(1, "Password is required")
})

async function loginHandler(req: NextRequest) {
  try {
    // Parse and validate request body
    const body = await req.json()
    const validation = loginSchema.safeParse(body)
    
    if (!validation.success) {
      return NextResponse.json({
        success: false,
        message: "Invalid input data",
        errors: validation.error.errors
      }, { status: 400 })
    }

    const { email, password } = validation.data

    // Connect to database
    await connectDB()

    // Find user with password field included
    const user = await User.findOne({ email }).select('+password')
    
    if (!user) {
      return NextResponse.json({
        success: false,
        message: "Invalid email or password"
      }, { status: 401 })
    }

    // Check if account is locked
    if (user.isLocked) {
      return NextResponse.json({
        success: false,
        message: "Account is temporarily locked due to too many failed login attempts"
      }, { status: 423 })
    }

    // Check if user is verified
    if (!user.isVerified) {
      return NextResponse.json({
        success: false,
        message: "Please verify your email address before logging in"
      }, { status: 403 })
    }

    // Compare password
    const isPasswordValid = await user.comparePassword(password)
    
    if (!isPasswordValid) {
      // Increment login attempts
      await user.incLoginAttempts()
      return NextResponse.json({
        success: false,
        message: "Invalid email or password"
      }, { status: 401 })
    }

    // Reset login attempts on successful login
    if (user.loginAttempts > 0) {
      await user.resetLoginAttempts()
    }

    // Check if 2FA is enabled
    if (user.twoFactorEnabled) {
      // Generate temporary token for 2FA verification
      const tempToken = signJWT(
        { 
          userId: user._id.toString(),
          email: user.email,
          type: 'temp-2fa'
        },
        { expiresIn: '10m' } // 10 minutes to complete 2FA
      )

      // Log 2FA required
      const userIP = req.headers.get('x-forwarded-for') || 
                    req.headers.get('x-real-ip') || 
                    '127.0.0.1'
      const userAgent = req.headers.get('user-agent') || 'Unknown'

      await Activity.create({
        userId: user._id,
        toolName: 'login',
        action: 'Login successful, 2FA required',
        status: 'info',
        duration: 0,
        ipAddress: userIP,
        userAgent: userAgent
      }).catch(console.error)

      return NextResponse.json({
        success: true,
        requiresTwoFactor: true,
        message: "2FA verification required",
        tempToken,
        user: {
          id: user._id.toString(),
          email: user.email,
          username: user.username,
          firstName: user.firstName,
          lastName: user.lastName,
        }
      })
    }

    // Update last login for non-2FA users
    await user.updateOne({ 
      lastLoginAt: new Date(),
      lastActiveAt: new Date()
    })

    // Generate JWT tokens for non-2FA users
    const tokens = await generateTokens({
      userId: user._id.toString(),
      email: user.email,
      role: user.role
    })

    // Log login activity
    const userIP = req.headers.get('x-forwarded-for') || 
                  req.headers.get('x-real-ip') || 
                  '127.0.0.1'
    
    const userAgent = req.headers.get('user-agent') || 'Unknown'

    await Activity.create({
      userId: user._id,
      toolName: 'login',
      action: 'User login',
      status: 'success',
      duration: 0,
      ipAddress: userIP,
      userAgent: userAgent
    }).catch(console.error) // Non-critical, so don't fail login if this fails

    // Create response
    const response = NextResponse.json({
      success: true,
      message: "Login successful",
      user: {
        id: user._id.toString(),
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        avatar: user.avatar,
        isVerified: user.isVerified,
        twoFactorEnabled: user.twoFactorEnabled
      },
      tokens
    })

    // Set HTTP-only cookies
    const isProduction = process.env.NODE_ENV === 'production'
    
    response.cookies.set({
      name: 'accessToken',
      value: tokens.accessToken,
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: 15 * 60 // 15 minutes
    })

    response.cookies.set({
      name: 'refreshToken',
      value: tokens.refreshToken,
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 // 7 days
    })

    return response

  } catch (error) {
    console.error("Login error:", error)
    return NextResponse.json({
      success: false,
      message: "An error occurred during login"
    }, { status: 500 })
  }
}

export const POST = loginHandler
