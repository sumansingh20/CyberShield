import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import ScanLog from "@/lib/models/ScanLog"
import { withAuth } from "@/lib/middleware/auth"
import { runDirectoryBuster } from "@/lib/utils/security-tools"

async function directoryBusterHandler(req: NextRequest) {
  try {
    await connectDB()

    const { url, wordlist } = await req.json()
    const user = (req as any).user

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 })
    }

    // Validate URL format
    const urlRegex = /^https?:\/\/[a-zA-Z0-9.-]+/
    if (!urlRegex.test(url)) {
      return NextResponse.json({ error: "Invalid URL format. Please use http:// or https://" }, { status: 400 })
    }

    const result = await runDirectoryBuster(url, wordlist)

    // Log the scan
    const scanLog = new ScanLog({
      userId: user.userId,
      toolName: "gobuster",
      input: `${url} ${wordlist ? `(wordlist: ${wordlist})` : ""}`,
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
    console.error("Directory buster error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(directoryBusterHandler)
