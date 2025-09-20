import { type NextRequest, NextResponse } from "next/server"
import { verifyAccessToken } from "@/lib/utils/jwt"

export function withAuth(handler: Function) {
  return async (req: NextRequest) => {
    try {
      const token = req.headers.get("authorization")?.replace("Bearer ", "")

      if (!token) {
        return NextResponse.json({ error: "Access token required" }, { status: 401 })
      }

      const payload = verifyAccessToken(token)

      // Add user info to request
      ;(req as any).user = payload

      return handler(req)
    } catch (error) {
      console.error("Auth error:", error)
      return NextResponse.json({ error: "Invalid or expired token" }, { status: 401 })
    }
  }
}

export function withAdminAuth(handler: Function) {
  return withAuth(async (req: NextRequest) => {
    const user = (req as any).user

    if (user.role !== "admin") {
      return NextResponse.json({ error: "Admin access required" }, { status: 403 })
    }

    return handler(req)
  })
}
