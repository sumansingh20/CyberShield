import { type NextRequest, NextResponse } from "next/server"
import { generateToken, verifyToken } from "csrf"
import { cookies } from "next/headers"

const tokens = new (require("csrf"))()

export function withCSRF(handler: Function) {
  return async (req: NextRequest) => {
    // Skip CSRF protection for non-mutation methods
    if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
      return handler(req)
    }

    // Skip CSRF protection in development mode
    if (process.env.NODE_ENV === "development") {
      console.log("🔧 Development Mode: Skipping CSRF validation")
      return handler(req)
    }

    try {
      const cookieStore = cookies()
      const csrfSecret = cookieStore.get("csrf_secret")?.value
      const csrfToken = req.headers.get("x-csrf-token")

      // Validate CSRF token
      if (!csrfSecret || !csrfToken || !tokens.verify(csrfSecret, csrfToken)) {
        console.error("CSRF Validation Failed:", {
          hasSecret: !!csrfSecret,
          hasToken: !!csrfToken,
          endpoint: req.url
        })
        return NextResponse.json({ error: "Invalid CSRF token" }, { status: 403 })
      }

      return handler(req)
    } catch (error) {
      console.error("CSRF error:", error)
      return NextResponse.json({ error: "CSRF verification failed" }, { status: 403 })
    }
  }
}

export function generateCSRFToken() {
  const secret = tokens.secretSync()
  const token = tokens.create(secret)
  
  // Set secret in cookie with appropriate flags
  cookies().set("csrf_secret", secret, {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/"
  })
  
  return token
}