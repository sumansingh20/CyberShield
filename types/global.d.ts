declare global {
  var mockOTPs: Map<string, {
    userId: string
    email: string
    phone: string
    emailOTP: string
    phoneOTP: string
    purpose: string
    expiresAt: Date
    attempts: number
    maxAttempts: number
  }> | undefined
}