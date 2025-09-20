import nodemailer from "nodemailer"

const isDevelopment = process.env.NODE_ENV === "development"
const emailHost = process.env.EMAIL_HOST
const emailUser = process.env.EMAIL_USER
const emailPass = process.env.EMAIL_PASS

let transporter: any = null

if (!isDevelopment && emailHost && emailUser && emailPass) {
  transporter = nodemailer.createTransport({
    host: emailHost,
    port: Number.parseInt(process.env.EMAIL_PORT || "587"),
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
  // Always use development mode for testing
  console.log(`[EMAIL] Sending OTP to ${email}: Your OTP for ${purpose} is: ${otp}`)
  console.log(`[EMAIL] OTP Code: ${otp}`)
  return Promise.resolve()
}

export async function sendPasswordResetEmail(email: string, resetToken: string) {
  const resetUrl = `${process.env.NEXTAUTH_URL}/reset-password?token=${resetToken}`

  const html = `
    <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
      <h2 style="color: #333;">Password Reset Request</h2>
      <p>You requested a password reset. Click the link below to reset your password:</p>
      <div style="text-align: center; margin: 30px 0;">
        <a href="${resetUrl}" style="background: #007bff; color: white; padding: 12px 24px; text-decoration: none; border-radius: 4px;">Reset Password</a>
      </div>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>
    </div>
  `

  await transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: "Password Reset Request",
    html,
  })
}
