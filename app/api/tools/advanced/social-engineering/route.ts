import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import ScanLog from "@/lib/models/ScanLog"
import { withAuth } from "@/lib/middleware/auth"
import { runSocialEngineering } from "@/lib/utils/security-tools"

async function socialEngineeringHandler(req: NextRequest) {
  try {
    const dbConnection = await connectDB()

    const { target, method } = await req.json()
    const user = (req as any).user

    if (!target || !method) {
      return NextResponse.json({ error: "Target and method are required" }, { status: 400 })
    }

    const result = await runSocialEngineering(target, method)

    // Only log if database is available and we have a valid user ID
    if (dbConnection && user.userId && typeof user.userId === 'object') {
      try {
        const scanLog = new ScanLog({
          userId: user.userId,
          toolName: "setoolkit",
          input: `${target} (method: ${method})`,
          output: result.output,
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
      result: {
        output: result.output,
        error: result.error,
        executionTime: result.executionTime,
        status: result.status,
      },
    })
  } catch (error) {
    console.error("Social engineering error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(socialEngineeringHandler)
