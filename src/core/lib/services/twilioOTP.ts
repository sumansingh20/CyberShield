import twilio from 'twilio'
import crypto from 'crypto'

// Twilio client setup
const twilioClient = twilio(
  process.env.TWILIO_ACCOUNT_SID,
  process.env.TWILIO_AUTH_TOKEN
)

interface OTPSession {
  phoneNumber: string
  otp: string
  expiresAt: Date
  attempts: number
  verified: boolean
}

// In-memory storage for OTP sessions (in production, use Redis or database)
const otpSessions = new Map<string, OTPSession>()

export class TwilioOTPService {
  private static instance: TwilioOTPService
  private readonly OTP_LENGTH = 6
  private readonly OTP_EXPIRY_MINUTES = 10
  private readonly MAX_ATTEMPTS = 3

  public static getInstance(): TwilioOTPService {
    if (!TwilioOTPService.instance) {
      TwilioOTPService.instance = new TwilioOTPService()
    }
    return TwilioOTPService.instance
  }

  private generateOTP(): string {
    const digits = '0123456789'
    let otp = ''
    for (let i = 0; i < this.OTP_LENGTH; i++) {
      otp += digits[crypto.randomInt(0, digits.length)]
    }
    return otp
  }

  private formatPhoneNumber(phoneNumber: string): string {
    // Remove all non-digit characters
    let cleaned = phoneNumber.replace(/\D/g, '')
    
    // Add country code if not present
    if (cleaned.length === 10) {
      cleaned = '1' + cleaned // Assume US/Canada
    }
    
    return '+' + cleaned
  }

  public async sendOTP(phoneNumber: string): Promise<{ success: boolean; message: string; sessionId?: string }> {
    try {
      const formattedPhone = this.formatPhoneNumber(phoneNumber)
      const otp = this.generateOTP()
      const expiresAt = new Date(Date.now() + this.OTP_EXPIRY_MINUTES * 60 * 1000)
      const sessionId = crypto.randomUUID()

      // Store OTP session
      otpSessions.set(sessionId, {
        phoneNumber: formattedPhone,
        otp,
        expiresAt,
        attempts: 0,
        verified: false
      })

      // Send SMS via Twilio
      const message = await twilioClient.messages.create({
        body: `Your CyberShield verification code is: ${otp}. This code expires in ${this.OTP_EXPIRY_MINUTES} minutes.`,
        from: process.env.TWILIO_PHONE_NUMBER,
        to: formattedPhone
      })

      console.log(`OTP sent to ${formattedPhone}: ${message.sid}`)

      return {
        success: true,
        message: 'OTP sent successfully',
        sessionId
      }
    } catch (error) {
      console.error('Error sending OTP:', error)
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Failed to send OTP'
      }
    }
  }

  public async verifyOTP(sessionId: string, otp: string): Promise<{ success: boolean; message: string }> {
    try {
      const session = otpSessions.get(sessionId)
      
      if (!session) {
        return {
          success: false,
          message: 'Invalid or expired session'
        }
      }

      // Check if OTP is expired
      if (new Date() > session.expiresAt) {
        otpSessions.delete(sessionId)
        return {
          success: false,
          message: 'OTP has expired. Please request a new one.'
        }
      }

      // Check if already verified
      if (session.verified) {
        return {
          success: false,
          message: 'OTP already verified'
        }
      }

      // Check attempts
      if (session.attempts >= this.MAX_ATTEMPTS) {
        otpSessions.delete(sessionId)
        return {
          success: false,
          message: 'Maximum verification attempts exceeded. Please request a new OTP.'
        }
      }

      // Increment attempts
      session.attempts++

      // Verify OTP
      if (session.otp === otp.trim()) {
        session.verified = true
        return {
          success: true,
          message: 'OTP verified successfully'
        }
      } else {
        return {
          success: false,
          message: `Invalid OTP. ${this.MAX_ATTEMPTS - session.attempts} attempts remaining.`
        }
      }
    } catch (error) {
      console.error('Error verifying OTP:', error)
      return {
        success: false,
        message: 'Failed to verify OTP'
      }
    }
  }

  public async resendOTP(sessionId: string): Promise<{ success: boolean; message: string; newSessionId?: string }> {
    try {
      const session = otpSessions.get(sessionId)
      
      if (!session) {
        return {
          success: false,
          message: 'Invalid session'
        }
      }

      // Delete old session
      otpSessions.delete(sessionId)

      // Send new OTP
      const result = await this.sendOTP(session.phoneNumber)
      
      return {
        success: result.success,
        message: result.success ? 'New OTP sent successfully' : result.message,
        newSessionId: result.sessionId
      }
    } catch (error) {
      console.error('Error resending OTP:', error)
      return {
        success: false,
        message: 'Failed to resend OTP'
      }
    }
  }

  public getSessionInfo(sessionId: string): { phoneNumber?: string; attemptsLeft?: number; expiresAt?: Date } | null {
    const session = otpSessions.get(sessionId)
    if (!session) return null

    return {
      phoneNumber: session.phoneNumber,
      attemptsLeft: this.MAX_ATTEMPTS - session.attempts,
      expiresAt: session.expiresAt
    }
  }

  public cleanupExpiredSessions(): void {
    const now = new Date()
    for (const [sessionId, session] of otpSessions.entries()) {
      if (now > session.expiresAt) {
        otpSessions.delete(sessionId)
      }
    }
  }
}

// Cleanup expired sessions every 5 minutes
setInterval(() => {
  TwilioOTPService.getInstance().cleanupExpiredSessions()
}, 5 * 60 * 1000)
