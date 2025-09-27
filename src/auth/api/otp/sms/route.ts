import { NextRequest, NextResponse } from 'next/server'
import { sendSMSOTP, sendSMSOTPVerify, verifySMSOTP } from '@/src/core/lib/utils/sms-otp'
import { z } from 'zod'

const phoneOTPSchema = z.object({
  phone: z.string()
    .min(10, 'Phone number must be at least 10 digits')
    .regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format')
})

const verifyOTPSchema = z.object({
  phone: z.string()
    .min(10, 'Phone number must be at least 10 digits')
    .regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format'),
  code: z.string()
    .length(6, 'OTP must be 6 digits')
    .regex(/^\d{6}$/, 'OTP must contain only digits')
})

// POST - Send SMS OTP
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    
    // Validate request body
    const validation = phoneOTPSchema.safeParse(body)
    if (!validation.success) {
      return NextResponse.json({
        success: false,
        message: 'Invalid phone number format',
        errors: validation.error.errors
      }, { status: 400 })
    }

    const { phone } = validation.data
    
    // Check required environment variables
    if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_VERIFY_SERVICE_SID) {
      console.error('Missing Twilio configuration')
      return NextResponse.json({
        success: false,
        message: 'SMS service is currently unavailable'
      }, { status: 500 })
    }

    console.log(`📱 Attempting to send SMS OTP to: ${phone}`)
    
    // Try to send SMS OTP using Twilio Verify
    const result = await sendSMSOTPVerify(phone)
    
    if (result.success) {
      console.log(`✅ SMS OTP sent to ${phone}, SID: ${result.sid}`)
      return NextResponse.json({
        success: true,
        message: 'SMS OTP sent successfully',
        sid: result.sid
      })
    } else {
      console.error(`❌ SMS OTP failed for ${phone}:`, result)
      return NextResponse.json({
        success: false,
        message: result.message || 'Failed to send SMS OTP'
      }, { status: 500 })
    }

  } catch (error: any) {
    console.error('SMS OTP API error:', error)
    
    return NextResponse.json({
      success: false,
      message: process.env.NODE_ENV === 'production' 
        ? 'SMS service is temporarily unavailable' 
        : error.message || 'Failed to send SMS OTP'
    }, { status: 500 })
  }
}

// PUT - Verify SMS OTP
export async function PUT(req: NextRequest) {
  try {
    const body = await req.json()
    
    // Validate request body
    const validation = verifyOTPSchema.safeParse(body)
    if (!validation.success) {
      return NextResponse.json({
        success: false,
        message: 'Invalid phone number or OTP format',
        errors: validation.error.errors
      }, { status: 400 })
    }

    const { phone, code } = validation.data
    
    // Check required environment variables
    if (!process.env.TWILIO_ACCOUNT_SID || !process.env.TWILIO_AUTH_TOKEN || !process.env.TWILIO_VERIFY_SERVICE_SID) {
      console.error('Missing Twilio configuration')
      return NextResponse.json({
        success: false,
        message: 'SMS verification service is currently unavailable'
      }, { status: 500 })
    }

    console.log(`📱 Attempting to verify SMS OTP for: ${phone}`)
    
    // Verify OTP using Twilio Verify
    const result = await verifySMSOTP(phone, code)
    
    if (result.success) {
      console.log(`✅ SMS OTP verified successfully for ${phone}`)
      return NextResponse.json({
        success: true,
        message: 'OTP verified successfully',
        status: result.status
      })
    } else {
      console.error(`❌ SMS OTP verification failed for ${phone}:`, result)
      return NextResponse.json({
        success: false,
        message: result.message || 'Invalid OTP code'
      }, { status: 400 })
    }

  } catch (error: any) {
    console.error('SMS OTP verification error:', error)
    
    return NextResponse.json({
      success: false,
      message: process.env.NODE_ENV === 'production' 
        ? 'Verification service is temporarily unavailable' 
        : error.message || 'Failed to verify SMS OTP'
    }, { status: 500 })
  }
}

// GET - Check SMS OTP status (optional endpoint)
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url)
    const phone = searchParams.get('phone')
    
    if (!phone) {
      return NextResponse.json({
        success: false,
        message: 'Phone number is required'
      }, { status: 400 })
    }

    // Validate phone number
    const validation = phoneOTPSchema.safeParse({ phone })
    if (!validation.success) {
      return NextResponse.json({
        success: false,
        message: 'Invalid phone number format'
      }, { status: 400 })
    }

    return NextResponse.json({
      success: true,
      message: 'SMS OTP service is available',
      phone: phone,
      service: 'twilio-verify'
    })

  } catch (error: any) {
    console.error('SMS OTP status check error:', error)
    
    return NextResponse.json({
      success: false,
      message: 'Failed to check SMS OTP status'
    }, { status: 500 })
  }
}
