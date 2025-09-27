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
  password: process.env.NODE_ENV === 'development' 
    ? z.string().min(1, "Password is required")
    : z.string().min(1, "Password is required")
})

async function loginHandler(req: NextRequest) {
  try {
    console.log("🔍 Login attempt started...")
    
    // Parse and validate request body
    let body;
    try {
      body = await req.json();
      console.log("🔍 Parsed login data:", JSON.stringify(body, null, 2));
      
      // Handle double-encoded JSON (if body is a string, parse it again)
      if (typeof body === 'string') {
        console.log("🔧 Double-encoded JSON detected, parsing again...");
        body = JSON.parse(body);
        console.log("🔍 Re-parsed login data:", JSON.stringify(body, null, 2));
      }
    } catch (parseError) {
      console.log("❌ JSON parsing error:", parseError);
      return NextResponse.json({
        success: false,
        message: "Invalid JSON format"
      }, { status: 400 });
    }
    
    const validation = loginSchema.safeParse(body)
    
    if (!validation.success) {
      console.log("❌ Login validation failed:", validation.error.errors)
      return NextResponse.json({
        success: false,
        message: "Invalid input data",
        errors: validation.error.errors
      }, { status: 400 })
    }

    const { email, password } = validation.data

    // In production without database access, use fallback authentication
    if (process.env.NODE_ENV === 'production' && !process.env.MONGODB_URI) {
      console.log("🔧 Using fallback authentication for production...")
      
      // Simple test user authentication for demo purposes
      const testUsers = [
        {
          email: 'suman@cybershield.com',
          password: 'suman01@',
          user: {
            id: 'demo-user-1',
            email: 'suman@cybershield.com',
            username: 'suman',
            firstName: 'Suman',
            lastName: 'Singh',
            role: 'admin',
            avatar: null,
            isVerified: true,
            twoFactorEnabled: false
          }
        },
        {
          email: 'suman@iitp.ac.in',
          password: 'suman01@',
          user: {
            id: 'demo-user-2',
            email: 'suman@iitp.ac.in',
            username: 'suman_iitp',
            firstName: 'Suman',
            lastName: 'Singh',
            role: 'admin',
            avatar: null,
            isVerified: true,
            twoFactorEnabled: false
          }
        }
      ]
      
      const testUser = testUsers.find(user => user.email === email && user.password === password)
      
      if (!testUser) {
        return NextResponse.json({
          success: false,
          message: "Invalid email or password"
        }, { status: 401 })
      }
      
      // Generate demo tokens (simplified)
      const demoTokens = {
        accessToken: `demo-access-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
        refreshToken: `demo-refresh-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
      }
      
      const response = NextResponse.json({
        success: true,
        message: "Login successful (Demo Mode)",
        user: testUser.user,
        tokens: demoTokens
      })

      // Set HTTP-only cookies for demo
      response.cookies.set({
        name: 'accessToken',
        value: demoTokens.accessToken,
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 15 * 60 // 15 minutes
      })

      response.cookies.set({
        name: 'refreshToken',
        value: demoTokens.refreshToken,
        httpOnly: true,
        secure: true,
        sameSite: 'lax',
        path: '/',
        maxAge: 7 * 24 * 60 * 60 // 7 days
      })

      return response
    }

    // Try to connect to database
    let user = null;
    try {
      await connectDB()
      console.log("✅ Database connected successfully")

      // Find user with password field included
      user = await User.findOne({ email }).select('+password')
      
    } catch (dbError) {
      console.error("❌ Database connection failed:", dbError)
      
      // Fallback to demo mode if database fails
      if (email === 'suman@cybershield.com' || email === 'suman@iitp.ac.in') {
        console.log("🔧 Database failed, using demo user...")
        
        if (password !== 'suman01@') {
          return NextResponse.json({
            success: false,
            message: "Invalid email or password"
          }, { status: 401 })
        }
        
        const demoUser = {
          id: email === 'suman@iitp.ac.in' ? 'demo-user-2' : 'demo-user-1',
          email: email,
          username: email === 'suman@iitp.ac.in' ? 'suman_iitp' : 'suman',
          firstName: 'Suman',
          lastName: 'Singh',
          role: 'admin',
          avatar: null,
          isVerified: true,
          twoFactorEnabled: false
        }
        
        // Generate demo tokens
        const demoTokens = {
          accessToken: `demo-access-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
          refreshToken: `demo-refresh-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`
        }
        
        const response = NextResponse.json({
          success: true,
          message: "Login successful (Demo Mode - DB Fallback)",
          user: demoUser,
          tokens: demoTokens
        })

        // Set cookies
        response.cookies.set({
          name: 'accessToken',
          value: demoTokens.accessToken,
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path: '/',
          maxAge: 15 * 60
        })

        response.cookies.set({
          name: 'refreshToken',
          value: demoTokens.refreshToken,
          httpOnly: true,
          secure: process.env.NODE_ENV === 'production',
          sameSite: 'lax',
          path: '/',
          maxAge: 7 * 24 * 60 * 60
        })

        return response
      }
      
      return NextResponse.json({
        success: false,
        message: "Database connection failed. Please try again later."
      }, { status: 500 })
    }
    
    // In development mode, create test user if it doesn't exist
    if (!user && process.env.NODE_ENV === 'development' && (email === 'suman@cybershield.com' || email === 'suman@iitp.ac.in')) {
      console.log("Creating test user for development...")
      try {
        const username = email === 'suman@iitp.ac.in' ? 'suman_iitp' : 'suman';
        user = await User.create({
          username: username,
          email: email,
          password: 'suman01@',
          firstName: 'Suman',
          lastName: 'Singh',
          role: 'admin',
          isVerified: true,
          agreeToTerms: true,
          emailNotifications: true,
          smsNotifications: false,
          loginAlerts: true,
          sessionTimeout: '30'
        })
        console.log("Test user created successfully!")
      } catch (createError) {
        console.log("Test user creation failed:", createError)
      }
    }
    
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

    // Check if user is verified (bypass in development for testing)
    if (!user.isVerified && process.env.NODE_ENV !== 'development') {
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
