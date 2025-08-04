import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import ScanLog from "@/lib/models/ScanLog"
import { withAuth } from "@/lib/middleware/auth"
import { runForensics } from "@/lib/utils/security-tools"

async function forensicsHandler(req: NextRequest) {
  try {
    await connectDB()

    const { imagePath } = await req.json()
    const user = (req as any).user

    if (!imagePath) {
      return NextResponse.json({ error: "Image path is required" }, { status: 400 })
    }

    const result = await runForensics(imagePath)

    // Log the scan
    const scanLog = new ScanLog({
      userId: user.userId,
      toolName: "file",
      input: imagePath,
      output: result.output,
      status: result.status,
      executionTime: result.executionTime,
    })

    await scanLog.save()

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
    console.error("Digital forensics error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(forensicsHandler)
