import crypto from 'crypto'

interface OTPSession {
  phoneNumber: string
  otp: string
  expiresAt: Date
  attempts: number
  verified: boolean
}

// In-memory storage for OTP sessions (can be replaced with Redis in production)
const otpSessions = new Map<string, OTPSession>()

export class ProductionOTPService {
  private readonly OTP_LENGTH = 6
  private readonly OTP_EXPIRY_MINUTES = 10
  private readonly MAX_ATTEMPTS = 3

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

      // In production, integrate with real SMS service
      // For now, log the OTP for testing
      console.log(`[CyberShield] OTP for ${formattedPhone}: ${otp}`)
      
      // You can integrate with services like:
      // - Twilio
      // - AWS SNS
      // - SendGrid
      // - TextMagic
      // - Vonage (Nexmo)
      
      await this.sendSMSViaService(formattedPhone, otp)

      return {
        success: true,
        message: 'Verification code sent to your phone',
        sessionId
      }
    } catch (error) {
      console.error('Error sending OTP:', error)
      return {
        success: false,
        message: error instanceof Error ? error.message : 'Failed to send verification code'
      }
    }
  }

  private async sendSMSViaService(phoneNumber: string, otp: string): Promise<void> {
    // Production implementation options:
    
    // Option 1: AWS SNS
    /*
    const sns = new AWS.SNS({ region: 'us-east-1' })
    await sns.publish({
      PhoneNumber: phoneNumber,
      Message: `Your CyberShield verification code is: ${otp}. Valid for ${this.OTP_EXPIRY_MINUTES} minutes.`
    }).promise()
    */

    // Option 2: Twilio (if you add the package back)
    /*
    const twilioClient = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN)
    await twilioClient.messages.create({
      body: `Your CyberShield verification code is: ${otp}. Valid for ${this.OTP_EXPIRY_MINUTES} minutes.`,
      from: process.env.TWILIO_PHONE_NUMBER,
      to: phoneNumber
    })
    */

    // Option 3: HTTP API integration (example)
    /*
    await fetch('https://api.smsservice.com/send', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.SMS_API_KEY}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        to: phoneNumber,
        message: `Your CyberShield verification code is: ${otp}. Valid for ${this.OTP_EXPIRY_MINUTES} minutes.`
      })
    })
    */

    // For development/testing - just log the OTP
    console.log(`[SMS] Would send to ${phoneNumber}: Your CyberShield verification code is: ${otp}. Valid for ${this.OTP_EXPIRY_MINUTES} minutes.`)
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
          message: 'Verification code has expired. Please request a new one.'
        }
      }

      // Check if already verified
      if (session.verified) {
        return {
          success: false,
          message: 'Verification code already used'
        }
      }

      // Check attempts
      if (session.attempts >= this.MAX_ATTEMPTS) {
        otpSessions.delete(sessionId)
        return {
          success: false,
          message: 'Too many verification attempts. Please request a new code.'
        }
      }

      // Increment attempts
      session.attempts++

      // Verify OTP
      if (session.otp === otp.trim()) {
        session.verified = true
        return {
          success: true,
          message: 'Phone number verified successfully'
        }
      } else {
        return {
          success: false,
          message: `Invalid verification code. ${this.MAX_ATTEMPTS - session.attempts} attempts remaining.`
        }
      }
    } catch (error) {
      console.error('Error verifying OTP:', error)
      return {
        success: false,
        message: 'Failed to verify code'
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
        message: result.success ? 'New verification code sent' : result.message,
        newSessionId: result.sessionId
      }
    } catch (error) {
      console.error('Error resending OTP:', error)
      return {
        success: false,
        message: 'Failed to resend verification code'
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
  new ProductionOTPService().cleanupExpiredSessions()
}, 5 * 60 * 1000)
