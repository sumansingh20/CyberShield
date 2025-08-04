import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import ScanLog from "@/lib/models/ScanLog"
import { withAuth } from "@/lib/middleware/auth"
import { runCryptography } from "@/lib/utils/security-tools"

async function cryptographyHandler(req: NextRequest) {
  try {
    await connectDB()

    const { text, method } = await req.json()
    const user = (req as any).user

    if (!text || !method) {
      return NextResponse.json({ error: "Text and method are required" }, { status: 400 })
    }

    const result = await runCryptography(text, method)

    // Log the scan
    const scanLog = new ScanLog({
      userId: user.userId,
      toolName: "crypto-analysis",
      input: `${method}: ${text.substring(0, 50)}...`,
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
    console.error("Cryptography error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(cryptographyHandler)
