import { NextRequest, NextResponse } from "next/server"

export async function POST(req: NextRequest) {
  // Simple implementation that returns unauthorized for now
  // This prevents the 404 error we're seeing
  return NextResponse.json(
    { error: "Refresh token not implemented" },
    { status: 401 }
  )
}