import { NextRequest, NextResponse } from 'next/server'
import { ProductionOTPService } from '@/src/core/lib/services/productionOTP'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { action, phoneNumber, sessionId, otp } = body

    const otpService = new ProductionOTPService()

    switch (action) {
      case 'send':
        if (!phoneNumber) {
          return NextResponse.json({ error: 'Phone number is required' }, { status: 400 })
        }

        const sendResult = await otpService.sendOTP(phoneNumber)
        return NextResponse.json(sendResult)

      case 'verify':
        if (!sessionId || !otp) {
          return NextResponse.json({ error: 'Session ID and OTP are required' }, { status: 400 })
        }

        const verifyResult = await otpService.verifyOTP(sessionId, otp)
        return NextResponse.json(verifyResult)

      case 'resend':
        if (!sessionId) {
          return NextResponse.json({ error: 'Session ID is required' }, { status: 400 })
        }

        const resendResult = await otpService.resendOTP(sessionId)
        return NextResponse.json(resendResult)

      case 'info':
        if (!sessionId) {
          return NextResponse.json({ error: 'Session ID is required' }, { status: 400 })
        }

        const sessionInfo = otpService.getSessionInfo(sessionId)
        if (!sessionInfo) {
          return NextResponse.json({ error: 'Invalid or expired session' }, { status: 404 })
        }

        return NextResponse.json({
          success: true,
          data: sessionInfo
        })

      default:
        return NextResponse.json({ error: 'Invalid action' }, { status: 400 })
    }
  } catch (error) {
    console.error('OTP API Error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 }
    )
  }
}
