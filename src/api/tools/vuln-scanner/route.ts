import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import ScanLog from "@/src/core/lib/models/ScanLog"
import { withAuth } from "@/src/core/lib/middleware/auth"
import { runVulnScan } from "@/src/core/lib/utils/security-tools"

async function vulnScanHandler(req: NextRequest) {
  try {
    await connectDB()

    const { target } = await req.json()
    const user = (req as any).user

    if (!target) {
      return NextResponse.json({ error: "Target is required" }, { status: 400 })
    }

    // Validate target format (allow URLs, IPs, domains, and CIDR ranges)
    const targetRegex = /^(https?:\/\/)?[a-zA-Z0-9.\-_/:]+$/
    
    if (!targetRegex.test(target)) {
      return NextResponse.json({ error: "Invalid target format. Use URL, IP address, or domain" }, { status: 400 })
    }

    const result = await runVulnScan(target)

    // Log the scan
    const scanLog = new ScanLog({
      userId: user.userId,
      toolName: "nikto",
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
    console.error("Vulnerability scan error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(vulnScanHandler)
