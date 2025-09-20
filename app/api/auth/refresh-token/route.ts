import { type NextRequest, NextResponse } from "next/server"
import { verifyRefreshToken, generateTokens, blacklistToken } from "@/lib/utils/jwt"
import { withCSRF } from "@/lib/middleware/csrf"
import { rateLimit } from "@/lib/middleware/rate-limit"

async function refreshTokenHandler(req: NextRequest) {
  try {
    const token = req.headers.get("authorization")?.replace("Bearer ", "")

    if (!token) {
      return NextResponse.json({ error: "Refresh token required" }, { status: 401 })
    }

    try {
      const payload = verifyRefreshToken(token)
      
      // Generate new tokens
      const newTokens = generateTokens({
        userId: payload.userId,
        email: payload.email,
        role: payload.role,
      })

      // Blacklist the old refresh token
      blacklistToken(token, 7 * 24 * 60 * 60 * 1000) // 7 days

      return NextResponse.json(newTokens)
    } catch (error: any) {
      if (error.message === 'Token has been revoked') {
        return NextResponse.json({ error: "Token has been revoked" }, { status: 401 })
      }
      if (error.message === 'Refresh token has expired') {
        return NextResponse.json({ error: "Refresh token expired" }, { status: 401 })
      }
      throw error
    }
  } catch (error) {
    console.error("Token refresh error:", error)
    return NextResponse.json({ error: "Invalid refresh token" }, { status: 401 })
  }
}

export const POST = rateLimit()(withCSRF(refreshTokenHandler))