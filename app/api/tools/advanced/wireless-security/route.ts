import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import ScanLog from "@/lib/models/ScanLog"
import { withAuth } from "@/lib/middleware/auth"
import { runWirelessScan } from "@/lib/utils/security-tools"

async function wirelessHandler(req: NextRequest) {
  try {
    await connectDB()

    const { networkInterface } = await req.json()
    const user = (req as any).user

    const result = await runWirelessScan(networkInterface)

    // Log the scan
    const scanLog = new ScanLog({
      userId: user.userId,
      toolName: "iwlist",
      input: networkInterface || "wlan0",
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
    console.error("Wireless scan error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

export const POST = withAuth(wirelessHandler)
