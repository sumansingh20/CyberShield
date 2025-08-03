import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import ScanLog from "@/lib/models/ScanLog"
import { withAuth } from "@/lib/middleware/auth"
import { runMetasploit } from "@/lib/utils/expert-tools"

async function metasploitHandler(req: NextRequest) {
  try {
    await connectDB()

    const { target, exploit } = await req.json()
    const user = (req as any).user

    if (!target || !exploit) {
      return NextResponse.json({ error: "Target and exploit are required" }, { status: 400 })
    }

    const result = await runMetasploit(target, exploit)

    const scanLog = new ScanLog({
      userId: user.userId,
      toolName: "metasploit",
      input: `${target} - ${exploit}`,
      output: result.output,
      status: result.status,
      executionTime: result.executionTime,
    })

    await scanLog.save()

    return NextResponse.json({
      success: true,
      result,
    })
  } catch (error) {
    console.error("Metasploit error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(metasploitHandler)
