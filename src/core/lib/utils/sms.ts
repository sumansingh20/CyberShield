import twilio from "twilio"

// Make Twilio optional in development
const isDevelopment = process.env.NODE_ENV === "development"
const accountSid = process.env.TWILIO_ACCOUNT_SID
const authToken = process.env.TWILIO_AUTH_TOKEN

let client: any = null

if (!isDevelopment && accountSid && authToken && accountSid.startsWith('AC')) {
  client = twilio(accountSid, authToken)
} else if (!isDevelopment) {
  console.warn("Twilio not properly configured")
}

export async function sendOTPSMS(phone: string, otp: string, purpose: string) {
  // Always use development mode for testing
  console.log(`[SMS] Sending OTP to ${phone}: Your CyberShield OTP for ${purpose} is: ${otp}`)
  console.log(`[SMS] OTP Code: ${otp}`)
  return Promise.resolve()
}
