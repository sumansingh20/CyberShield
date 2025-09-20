import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"

export const dynamic = "force-static"
export const revalidate = 0

export async function GET(req: NextRequest) {
  try {
    // Test database connection
    const db = await connectDB()
    const isConnected = db?.connection?.readyState === 1

    return NextResponse.json({
      status: "healthy",
      database: isConnected ? "connected" : "disconnected",
      timestamp: new Date().toISOString()
    })
  } catch (error) {
    console.error("Health check error:", error)
    return NextResponse.json({
      status: "unhealthy",
      error: "Failed to connect to database",
      timestamp: new Date().toISOString()
    }, { status: 500 })
  }
}