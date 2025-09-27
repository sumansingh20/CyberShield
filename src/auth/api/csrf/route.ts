import { type NextRequest, NextResponse } from "next/server"

export const dynamic = "force-dynamic"
export const revalidate = 300 // revalidate the data at most every 5 minutes
import { generateCSRFToken } from "@/src/core/lib/middleware/csrf"

export async function GET(req: NextRequest) {
  try {
    const token = await generateCSRFToken()
    return NextResponse.json({ token })
  } catch (error) {
    console.error("CSRF token generation error:", error)
    return NextResponse.json({ error: "Failed to generate CSRF token" }, { status: 500 })
  }
}
