import { NextRequest, NextResponse } from 'next/server'
import { sendVoiceOTP, sendVoiceOTPVerify, generateVoiceOTP } from '@/src/core/lib/utils/voice-otp'
import { z } from 'zod'

const phoneOTPSchema = z.object({
  phone: z.string()
    .min(10, 'Phone number must be at least 10 digits')
    .regex(/^\+?[1-9]\d{1,14}$/, 'Invalid phone number format')
})

// In-memory storage for voice OTP (production should use Redis)
const voiceOTPs = new Map<string, { otp: string; expires: number }>()

// POST - Send Voice OTP
export async function POST(req: NextRequest) {
  try {
    const body = await req.json()
    const validation = phoneOTPSchema.safeParse(body)
    
    if (!validation.success) {
      return NextResponse.json({
        success: false,
        message: 'Invalid phone number',
        errors: validation.error.errors
      }, { status: 400 })
    }

    const { phone } = validation.data
    
    // Generate OTP
    const otp = generateVoiceOTP()
    
    // Store OTP with 5-minute expiration
    const expires = Date.now() + 5 * 60 * 1000 // 5 minutes
    voiceOTPs.set(phone, { otp, expires })
    
    console.log(`📞 Attempting voice OTP to: ${phone}`)

    // Method 1: Try Twilio Verify Service (recommended)
    const verifyResult = await sendVoiceOTPVerify(phone)
    
    if (verifyResult.success) {
      console.log(`✅ Voice OTP sent via Verify service to ${phone}`)
      
      return NextResponse.json({
        success: true,
        message: 'Voice OTP call initiated to your phone',
        verificationSid: verifyResult.sid,
        method: 'twilio-verify'
      })
    }

    // Method 2: Fallback to custom voice call
    console.log('📞 Verify service failed, trying custom voice call...')
    const customResult = await sendVoiceOTP(phone, otp)
    
    if (customResult.success) {
      console.log(`✅ Custom voice OTP sent to ${phone}`)
      
      return NextResponse.json({
        success: true,
        message: 'Voice OTP call initiated to your phone',
        callSid: customResult.callSid,
        method: 'custom-voice'
      })
    }

    // Both methods failed
    console.error(`❌ Both voice OTP methods failed for ${phone}`)
    
    return NextResponse.json({
      success: false,
      message: 'Failed to send voice OTP. Please check your phone number and try again.',
      details: 'Both Twilio Verify and custom voice calls failed'
    }, { status: 500 })

  } catch (error) {
    console.error('Voice OTP error:', error)
    return NextResponse.json({
      success: false,
      message: 'Failed to send voice OTP'
    }, { status: 500 })
  }
}

// PUT - Verify Voice OTP
export async function PUT(req: NextRequest) {
  try {
    const body = await req.json()
    const { phone, otp } = body
    
    if (!phone || !otp) {
      return NextResponse.json({
        success: false,
        message: 'Phone number and OTP are required'
      }, { status: 400 })
    }

    console.log(`📞 Verifying voice OTP for: ${phone}`)

    // Method 1: Try Twilio Verify Service first
    const smsVerified = await verifySMSOTP(phone, otp)
    if (smsVerified) {
      console.log(`✅ Voice OTP verified via Twilio Verify for ${phone}`)
      
      return NextResponse.json({
        success: true,
        message: 'Voice OTP verified successfully',
        method: 'twilio-verify'
      })
    }

    // Method 2: Check stored OTP for custom voice calls
    const storedData = voiceOTPs.get(phone)
    if (!storedData) {
      return NextResponse.json({
        success: false,
        message: 'No OTP found for this phone number. Please request a new one.'
      }, { status: 400 })
    }

    if (Date.now() > storedData.expires) {
      voiceOTPs.delete(phone) // Clean up expired OTP
      return NextResponse.json({
        success: false,
        message: 'OTP has expired. Please request a new one.'
      }, { status: 400 })
    }

    if (storedData.otp !== otp) {
      return NextResponse.json({
        success: false,
        message: 'Invalid OTP. Please try again.'
      }, { status: 400 })
    }

    // OTP is valid - remove it (single use)
    voiceOTPs.delete(phone)
    
    console.log(`✅ Voice OTP verified successfully for ${phone}`)

    return NextResponse.json({
      success: true,
      message: 'Voice OTP verified successfully',
      method: 'custom-voice'
    })

  } catch (error) {
    console.error('Voice OTP verification error:', error)
    return NextResponse.json({
      success: false,
      message: 'Failed to verify voice OTP'
    }, { status: 500 })
  }
}

// GET - Check voice OTP status
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

    const storedData = voiceOTPs.get(phone)
    const hasActiveOTP = storedData && Date.now() <= storedData.expires

    return NextResponse.json({
      success: true,
      hasActiveOTP,
      expiresIn: hasActiveOTP ? Math.max(0, Math.floor((storedData!.expires - Date.now()) / 1000)) : 0
    })

  } catch (error) {
    console.error('Voice OTP status error:', error)
    return NextResponse.json({
      success: false,
      message: 'Failed to check voice OTP status'
    }, { status: 500 })
  }
}
