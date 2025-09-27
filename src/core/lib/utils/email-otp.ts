import nodemailer from 'nodemailer'
import crypto from 'crypto'

// In-memory OTP storage (for development/testing)
// In production, you should use Redis or database
const otpStore = new Map<string, { code: string; expires: number; otpId: string }>()

// Generate 6-digit OTP
function generateOTP(): string {
  return crypto.randomInt(100000, 999999).toString()
}

// Create Gmail transporter
function createEmailTransporter() {
  const gmailUser = process.env.GMAIL_USER
  const gmailPassword = process.env.GMAIL_APP_PASSWORD

  if (!gmailUser || !gmailPassword) {
    throw new Error('Gmail credentials not configured')
  }

  return nodemailer.createTransport({
    service: 'gmail',
    auth: {
      user: gmailUser,
      pass: gmailPassword
    }
  })
}

// Send Email OTP
export async function sendEmailOTP(email: string): Promise<{
  success: boolean
  message?: string
  otpId?: string
}> {
  try {
    // Generate OTP
    const otpCode = generateOTP()
    const otpId = crypto.randomUUID()
    const expiryTime = Date.now() + (5 * 60 * 1000) // 5 minutes

    // Store OTP
    otpStore.set(email, {
      code: otpCode,
      expires: expiryTime,
      otpId: otpId
    })

    // Create transporter
    const transporter = createEmailTransporter()

    // Email HTML template
    const htmlTemplate = `
      <!DOCTYPE html>
      <html>
      <head>
          <meta charset="utf-8">
          <meta name="viewport" content="width=device-width, initial-scale=1.0">
          <title>CyberShield - Your OTP Code</title>
          <style>
              body { font-family: Arial, sans-serif; margin: 0; padding: 20px; background-color: #f5f5f5; }
              .container { max-width: 600px; margin: 0 auto; background-color: white; padding: 30px; border-radius: 10px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }
              .header { text-align: center; margin-bottom: 30px; }
              .logo { color: #2563eb; font-size: 28px; font-weight: bold; margin-bottom: 10px; }
              .otp-code { background-color: #2563eb; color: white; font-size: 32px; font-weight: bold; text-align: center; padding: 20px; border-radius: 8px; letter-spacing: 8px; margin: 20px 0; }
              .info { background-color: #f3f4f6; padding: 15px; border-radius: 6px; margin: 20px 0; }
              .footer { text-align: center; margin-top: 30px; color: #6b7280; font-size: 14px; }
              .security-tips { margin-top: 20px; font-size: 14px; color: #6b7280; }
          </style>
      </head>
      <body>
          <div class="container">
              <div class="header">
                  <div class="logo">🛡️ CyberShield</div>
                  <h2>Your One-Time Password</h2>
              </div>
              
              <p>Hello,</p>
              <p>You requested a One-Time Password (OTP) for your CyberShield account. Here's your verification code:</p>
              
              <div class="otp-code">${otpCode}</div>
              
              <div class="info">
                  <strong>⏰ This code will expire in 5 minutes</strong><br>
                  <strong>📧 Email:</strong> ${email}<br>
                  <strong>🕐 Generated at:</strong> ${new Date().toLocaleString()}
              </div>
              
              <p>Enter this code in your CyberShield application to complete the verification process.</p>
              
              <div class="security-tips">
                  <strong>🔒 Security Tips:</strong><br>
                  • Never share this code with anyone<br>
                  • CyberShield will never ask for your OTP via phone or email<br>
                  • If you didn't request this code, please ignore this email<br>
                  • This code can only be used once
              </div>
              
              <div class="footer">
                  <p>This is an automated message from CyberShield Security Platform</p>
                  <p>© 2025 CyberShield. All rights reserved.</p>
              </div>
          </div>
      </body>
      </html>
    `

    // Send email
    const mailOptions = {
      from: `"CyberShield Security" <${process.env.GMAIL_USER}>`,
      to: email,
      subject: `🛡️ CyberShield - Your OTP Code: ${otpCode}`,
      html: htmlTemplate,
      text: `Your CyberShield OTP code is: ${otpCode}. This code will expire in 5 minutes. Never share this code with anyone.`
    }

    await transporter.sendMail(mailOptions)

    console.log(`✅ Email OTP sent successfully to: ${email}`)
    console.log(`🔑 OTP ID: ${otpId}`)

    return {
      success: true,
      message: 'Email OTP sent successfully',
      otpId: otpId
    }

  } catch (error: any) {
    console.error('❌ Email OTP sending failed:', error)
    
    // Handle specific Gmail errors
    if (error.code === 'EAUTH') {
      return {
        success: false,
        message: 'Gmail authentication failed. Please check app password.'
      }
    }
    
    if (error.code === 'ECONNECTION') {
      return {
        success: false,
        message: 'Failed to connect to Gmail servers. Please try again later.'
      }
    }

    return {
      success: false,
      message: error.message || 'Failed to send email OTP'
    }
  }
}

// Verify Email OTP
export async function verifyEmailOTP(email: string, otpCode: string): Promise<{
  success: boolean
  message?: string
}> {
  try {
    // Get stored OTP
    const storedOTP = otpStore.get(email)
    
    if (!storedOTP) {
      return {
        success: false,
        message: 'No OTP found for this email. Please request a new one.'
      }
    }

    // Check if OTP is expired
    if (Date.now() > storedOTP.expires) {
      otpStore.delete(email) // Clean up expired OTP
      return {
        success: false,
        message: 'OTP has expired. Please request a new one.'
      }
    }

    // Verify OTP code
    if (storedOTP.code !== otpCode) {
      return {
        success: false,
        message: 'Invalid OTP code. Please check and try again.'
      }
    }

    // OTP is valid - remove it from store (single use)
    otpStore.delete(email)

    console.log(`✅ Email OTP verified successfully for: ${email}`)

    return {
      success: true,
      message: 'Email OTP verified successfully'
    }

  } catch (error: any) {
    console.error('❌ Email OTP verification failed:', error)
    
    return {
      success: false,
      message: error.message || 'Failed to verify email OTP'
    }
  }
}

// Clean up expired OTPs (optional cleanup function)
export function cleanupExpiredOTPs() {
  const now = Date.now()
  for (const [email, otp] of otpStore.entries()) {
    if (now > otp.expires) {
      otpStore.delete(email)
      console.log(`🧹 Cleaned up expired OTP for: ${email}`)
    }
  }
}

// Get OTP store size (for monitoring)
export function getOTPStoreSize(): number {
  return otpStore.size
}
