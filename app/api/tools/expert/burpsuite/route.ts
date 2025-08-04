import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import ScanLog from "@/lib/models/ScanLog"
import { withAuth } from "@/lib/middleware/auth"
import { runBurpSuite } from "@/lib/utils/expert-tools"

async function burpSuiteHandler(req: NextRequest) {
  try {
    const dbConnection = await connectDB()

    const { url } = await req.json()
    const user = (req as any).user

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    const result = await runBurpSuite(url)

    // Only log if database is available and we have a valid user ID
    if (dbConnection && user.userId && typeof user.userId === 'object') {
      try {
        const scanLog = new ScanLog({
          userId: user.userId,
          toolName: "burpsuite",
          input: url,
          output: result.output || "No output available",
          status: result.status,
          executionTime: result.executionTime,
        })

        await scanLog.save()
      } catch (dbError) {
        console.warn("Failed to log scan to database:", dbError)
        // Continue without logging - don't fail the request
      }
    } else {
      console.log("📝 Skipping database logging - MongoDB not available or invalid user")
    }

    return NextResponse.json({
      success: true,
      result,
    })
  } catch (error) {
    console.error("Burp Suite error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(burpSuiteHandler)
