import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import ScanLog from "@/src/core/lib/models/ScanLog"
import { withAuth } from "@/src/core/lib/middleware/auth"
import { runNmapScan } from "@/src/core/lib/utils/security-tools"

async function nmapHandler(req: NextRequest) {
  try {
    const dbConnection = await connectDB()

    const { target } = await req.json()

    if (!target) {
      return NextResponse.json({ error: "Target is required" }, { status: 400 })
    }

    // Validate target format (allow IPs, domains, CIDR ranges, and ports)
    const targetRegex = /^[a-zA-Z0-9.\-_/:]+$/
    if (!targetRegex.test(target)) {
      return NextResponse.json({ error: "Invalid target format" }, { status: 400 })
    }

    const result = await runNmapScan(target)

    // Only log if database is available
    if (dbConnection) {
      try {
        const scanLog = new ScanLog({
          userId: null, // No user required
          toolName: "nmap",
          input: target,
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
      console.log("📝 Skipping database logging - MongoDB not available")
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
    console.error("Nmap scan error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = nmapHandler
