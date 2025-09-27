import { NextRequest, NextResponse } from "next/server"
import { authMiddleware } from "@/src/core/lib/middleware/auth"
import connectDB from "@/src/core/lib/mongodb"
import { ScanLog } from "@/src/core/lib/models/ScanLog"
import mongoose from "mongoose"

export async function GET(req: NextRequest) {
  try {
    const authResult = await authMiddleware(req)
    if (!authResult.success) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    await connectDB()

    const userId = new mongoose.Types.ObjectId(authResult.userId)
    
    // Get all scan logs for this user
    const activities = await ScanLog.find({ userId })
      .sort({ createdAt: -1 })
      .limit(10)
      .lean()

    // Transform activities into a simpler format
    const simplifiedActivities = activities.map(activity => ({
      id: (activity as any)._id.toString(),
      toolName: activity.toolName,
      toolCategory: activity.toolCategory,
      status: activity.status,
      target: activity.input?.target?.host || 'Unknown',
      timestamp: activity.createdAt,
      duration: activity.metrics?.duration || 0,
      vulnerabilities: {
        total: activity.statistics?.totalVulnerabilities || 0,
        critical: activity.statistics?.criticalCount || 0,
        high: activity.statistics?.highCount || 0,
        medium: activity.statistics?.mediumCount || 0,
        low: activity.statistics?.lowCount || 0
      }
    }))

    return NextResponse.json({ activities: simplifiedActivities })
  } catch (error) {
    console.error("Error fetching activity:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
