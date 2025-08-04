import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import ScanLog from "@/lib/models/ScanLog"
import { withAuth } from "@/lib/middleware/auth"
import { runMobileSecurity } from "@/lib/utils/security-tools"

async function mobileSecurityHandler(req: NextRequest) {
  try {
    await connectDB()

    const { apkPath } = await req.json()
    const user = (req as any).user

    if (!apkPath) {
      return NextResponse.json({ error: "APK path is required" }, { status: 400 })
    }

    const result = await runMobileSecurity(apkPath)

    // Log the scan
    const scanLog = new ScanLog({
      userId: user.userId,
      toolName: "apktool",
      input: apkPath,
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
    console.error("Mobile security error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(mobileSecurityHandler)
