import nodemailer from "nodemailer"

const isDevelopment = process.env.NODE_ENV === "development"
const emailHost = process.env.SMTP_HOST
const emailUser = process.env.SMTP_USER
const emailPass = process.env.SMTP_PASS

let transporter: any = null

if (!isDevelopment && emailHost && emailUser && emailPass) {
  transporter = nodemailer.createTransport({
    host: emailHost,
    port: Number.parseInt(process.env.SMTP_PORT || "587"),
    secure: false,
    auth: {
      user: emailUser,
      pass: emailPass,
    },
  })
} else if (!isDevelopment) {
  console.warn("Email service not properly configured")
}

export async function sendOTPEmail(email: string, otp: string, purpose: string) {
  if (isDevelopment) {
    console.log(`[EMAIL] Sending OTP to ${email}: Your OTP for ${purpose} is: ${otp}`)
    console.log(`[EMAIL] OTP Code: ${otp}`)
    return Promise.resolve()
  }

  if (!transporter) {
    console.warn("Email service not configured, cannot send OTP")
    return Promise.resolve()
  }

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">CyberShield OTP Verification</h2>
      <p>Your OTP for ${purpose} is:</p>
      <div style="text-align: center; margin: 30px 0;">
        <span style="background: #007bff; color: white; padding: 12px 24px; font-size: 24px; font-weight: bold; border-radius: 4px; letter-spacing: 2px;">${otp}</span>
      </div>
      <p>This OTP will expire in 10 minutes.</p>
      <p>If you didn't request this, please ignore this email.</p>
    </div>
  `

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || emailUser,
      to: email,
      subject: `CyberShield OTP - ${purpose}`,
      html,
    })
  } catch (error) {
    console.error("Failed to send OTP email:", error)
  }
}

export async function sendPasswordResetEmail(email: string, resetToken: string) {
  if (isDevelopment) {
    const resetUrl = `${process.env.NEXT_PUBLIC_APP_URL}/reset-password?token=${resetToken}`
    console.log(`[EMAIL] Password reset link for ${email}: ${resetUrl}`)
    return Promise.resolve()
  }

  if (!transporter) {
    console.warn("Email service not configured, cannot send password reset email")
    return Promise.resolve()
  }

  const resetUrl = `${process.env.NEXT_PUBLIC_APP_URL}/reset-password?token=${resetToken}`

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">CyberShield Password Reset</h2>
      <p>You requested a password reset. Click the link below to reset your password:</p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="${resetUrl}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">Reset Password</a>
      </div>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>
    </div>
  `

  try {
    await transporter.sendMail({
      from: process.env.SMTP_FROM || emailUser,
      to: email,
      subject: "CyberShield Password Reset Request",
      html,
    })
  } catch (error) {
    console.error("Failed to send password reset email:", error)
  }
}
