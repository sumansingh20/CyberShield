import { type NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import Activity from "@/src/core/lib/models/Activity"
import User from "@/src/core/lib/models/User" // Import User model to register it

export const dynamic = "force-dynamic"

export async function GET(req: NextRequest) {
  try {
    console.log("🚀 Dashboard activity API called")
    
    await connectDB()

    // Ensure User model is registered by referencing it
    console.log("User model registered:", User.modelName)

    // Get recent activities with user details
    const activities = await Activity.find()
      .populate('userId', 'username email firstName lastName')
      .sort({ timestamp: -1 })
      .limit(50)
      .lean()

    console.log("📊 Found activities:", activities.length)

    // Format activities for frontend
    const formattedActivities = activities.map((activity: any) => ({
      id: activity._id.toString(),
      tool: activity.toolName || 'Unknown Tool',
      category: 'Security', // Default category
      target: activity.ipAddress || 'Unknown',
      status: activity.status || 'unknown',
      summary: activity.action || 'Unknown Action',
      findings: {
        total: 0,
        critical: 0,
        high: 0
      },
      executionTime: activity.duration || 0,
      timestamp: activity.timestamp || activity.createdAt,
      ipAddress: activity.ipAddress || 'Unknown',
      userAgent: activity.userAgent || 'Unknown',
      user: activity.userId ? {
        id: activity.userId._id?.toString(),
        username: activity.userId.username || 'Unknown User',
        email: activity.userId.email || '',
        name: activity.userId.firstName && activity.userId.lastName 
          ? `${activity.userId.firstName} ${activity.userId.lastName}`
          : activity.userId.username || 'Unknown User'
      } : null
    }))

    console.log("✅ Returning response with activities:", formattedActivities.length)

    console.log("✅ Returning response with activities:", formattedActivities.length)
    return NextResponse.json({
      success: true,
      activities: formattedActivities,
      total: formattedActivities.length
    })

  } catch (error) {
    console.error("Dashboard activity error:", error)
    
    return NextResponse.json({
      success: false,
      message: "Failed to fetch dashboard activity",
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}