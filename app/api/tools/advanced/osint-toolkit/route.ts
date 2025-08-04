import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import ScanLog from "@/lib/models/ScanLog"
import { withAuth } from "@/lib/middleware/auth"
import { runOSINT } from "@/lib/utils/security-tools"

async function osintHandler(req: NextRequest) {
  try {
    await connectDB()

    const { target } = await req.json()
    const user = (req as any).user

    if (!target) {
      return NextResponse.json({ error: "Target domain is required" }, { status: 400 })
    }

    // Validate domain format
    const domainRegex = /^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/
    if (!domainRegex.test(target)) {
      return NextResponse.json({ error: "Invalid domain format" }, { status: 400 })
    }

    const result = await runOSINT(target)

    // Log the scan
    const scanLog = new ScanLog({
      userId: user.userId,
      toolName: "theHarvester",
      input: target,
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
    console.error("OSINT error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(osintHandler)
