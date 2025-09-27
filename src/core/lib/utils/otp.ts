import crypto from "crypto"

export function generateOTP(length = 6): string {
  const digits = "0123456789"
  let otp = ""

  for (let i = 0; i < length; i++) {
    otp += digits[crypto.randomInt(0, digits.length)]
  }

  return otp
}

export function isOTPExpired(expiresAt: Date): boolean {
  return new Date() > expiresAt
}

export function formatPhoneNumber(phone: string): string {
  // Remove all non-digit characters
  const cleaned = phone.replace(/\D/g, "")

  // Add country code if not present
  if (!cleaned.startsWith("1") && cleaned.length === 10) {
    return `+1${cleaned}`
  }

  if (!cleaned.startsWith("+")) {
    return `+${cleaned}`
  }

  return cleaned
}
