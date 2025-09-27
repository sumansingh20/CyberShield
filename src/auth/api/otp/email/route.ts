import { NextRequest, NextResponse } from 'next/server'
import { sendEmailOTP, verifyEmailOTP } from '@/src/core/lib/utils/email-otp'
import { z } from 'zod'

const emailOTPSchema = z.object({
  email: z.string().email('Invalid email address')
})

const verifyEmailOTPSchema = z.object({
  email: z.string().email('Invalid email address'),
  code: z.string()
    .length(6, 'OTP must be 6 digits')
    .regex(/^\d{6}$/, 'OTP must contain only digits')
})

// POST - Send Email OTP
export async function POST(req: NextRequest) {
  try {
    // Get email from request body or from JWT token
    let email: string;
    
    try {
      const body = await req.json()
      
      if (body.email) {
        // Validate email if provided
        const validation = emailOTPSchema.safeParse(body)
        if (!validation.success) {
          return NextResponse.json({
            success: false,
            message: 'Invalid email address',
            errors: validation.error.errors
          }, { status: 400 })
        }
        email = validation.data.email
      } else {
        // Extract from JWT token if no email in body
        const token = req.headers.get('authorization')?.replace('Bearer ', '')
        if (!token) {
          return NextResponse.json({
            success: false,
            message: 'Email address or authentication token required'
          }, { status: 400 })
        }

        // For now, we'll require email in the request body
        return NextResponse.json({
          success: false,
          message: 'Email address is required'
        }, { status: 400 })
      }
    } catch (error) {
      return NextResponse.json({
        success: false,
        message: 'Invalid request format'
      }, { status: 400 })
    }

    // Check required environment variables
    if (!process.env.GMAIL_USER || !process.env.GMAIL_APP_PASSWORD) {
      console.error('Missing Gmail configuration')
      return NextResponse.json({
        success: false,
        message: 'Email service is currently unavailable'
      }, { status: 500 })
    }

    console.log(`📧 Attempting to send Email OTP to: ${email}`)
    
    // Send Email OTP
    const result = await sendEmailOTP(email)
    
    if (result.success) {
      console.log(`✅ Email OTP sent to ${email}`)
      return NextResponse.json({
        success: true,
        message: 'Email OTP sent successfully. Check your inbox.',
        otpId: result.otpId
      })
    } else {
      console.error(`❌ Email OTP failed for ${email}:`, result)
      return NextResponse.json({
        success: false,
        message: result.message || 'Failed to send Email OTP'
      }, { status: 500 })
    }

  } catch (error: any) {
    console.error('Email OTP API error:', error)
    
    return NextResponse.json({
      success: false,
      message: process.env.NODE_ENV === 'production' 
        ? 'Email service is temporarily unavailable' 
        : error.message || 'Failed to send Email OTP'
    }, { status: 500 })
  }
}

// PUT - Verify Email OTP
export async function PUT(req: NextRequest) {
  try {
    const body = await req.json()
    
    // Validate request body
    const validation = verifyEmailOTPSchema.safeParse(body)
    if (!validation.success) {
      return NextResponse.json({
        success: false,
        message: 'Invalid email address or OTP format',
        errors: validation.error.errors
      }, { status: 400 })
    }

    const { email, code } = validation.data
    
    console.log(`📧 Attempting to verify Email OTP for: ${email}`)
    
    // Verify OTP
    const result = await verifyEmailOTP(email, code)
    
    if (result.success) {
      console.log(`✅ Email OTP verified successfully for ${email}`)
      return NextResponse.json({
        success: true,
        message: 'Email OTP verified successfully'
      })
    } else {
      console.error(`❌ Email OTP verification failed for ${email}:`, result)
      return NextResponse.json({
        success: false,
        message: result.message || 'Invalid or expired OTP code'
      }, { status: 400 })
    }

  } catch (error: any) {
    console.error('Email OTP verification error:', error)
    
    return NextResponse.json({
      success: false,
      message: process.env.NODE_ENV === 'production' 
        ? 'Verification service is temporarily unavailable' 
        : error.message || 'Failed to verify Email OTP'
    }, { status: 500 })
  }
}

// GET - Check Email OTP service status
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url)
    const email = searchParams.get('email')
    
    if (email) {
      // Validate email if provided
      const validation = emailOTPSchema.safeParse({ email })
      if (!validation.success) {
        return NextResponse.json({
          success: false,
          message: 'Invalid email address format'
        }, { status: 400 })
      }
    }

    // Check if email service is configured
    const isConfigured = !!(process.env.GMAIL_USER && process.env.GMAIL_APP_PASSWORD)

    return NextResponse.json({
      success: true,
      message: 'Email OTP service status',
      configured: isConfigured,
      service: 'gmail-smtp',
      ...(email && { email })
    })

  } catch (error: any) {
    console.error('Email OTP status check error:', error)
    
    return NextResponse.json({
      success: false,
      message: 'Failed to check Email OTP status'
    }, { status: 500 })
  }
}
