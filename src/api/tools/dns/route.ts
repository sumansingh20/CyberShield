import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import ScanLog from "@/src/core/lib/models/ScanLog"
import { withAuth } from "@/src/core/lib/middleware/auth"
import { runDNSLookup } from "@/src/core/lib/utils/security-tools"

async function dnsHandler(req: NextRequest) {
  try {
    const dbConnection = await connectDB()

    const { domain } = await req.json()

    if (!domain) {
      return NextResponse.json({ error: "Domain is required" }, { status: 400 })
    }

    const result = await runDNSLookup(domain)

    // Only log if database is available
    if (dbConnection) {
      try {
        const scanLog = new ScanLog({
          userId: null, // No user required
          toolName: "dns-lookup",
          input: domain,
          output: result.output,
          status: result.status,
          executionTime: result.executionTime,
        })

        await scanLog.save()
      } catch (dbError) {
        console.warn("Failed to log scan to database:", dbError)
      }
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
    console.error("DNS lookup error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = dnsHandler
