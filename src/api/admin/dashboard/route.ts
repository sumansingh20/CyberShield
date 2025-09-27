import { NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import User from "@/src/core/lib/models/User"
import Activity from "@/src/core/lib/models/Activity"
import SystemSettings from "@/src/core/lib/models/SystemSettings"
import { verifyAccessToken } from "@/src/core/lib/utils/jwt"

export async function GET(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json({ error: "Authorization token required" }, { status: 401 })
    }

    const decoded = await verifyAccessToken(token)
    if (decoded.role !== 'admin') {
      return NextResponse.json({ error: "Admin access required" }, { status: 403 })
    }

    await connectDB()

    // Get dashboard stats
    const [
      totalUsers,
      activeUsers,
      totalActivities,
      recentActivities,
      userStats
    ] = await Promise.all([
      User.countDocuments(),
      User.countDocuments({ lastActiveAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) } }),
      Activity.countDocuments(),
      Activity.find()
        .populate('userId', 'username email firstName lastName')
        .sort({ createdAt: -1 })
        .limit(10),
      User.aggregate([
        {
          $group: {
            _id: '$role',
            count: { $sum: 1 }
          }
        }
      ])
    ])

    // Get or create system settings
    let systemSettings = await SystemSettings.findOne()
    if (!systemSettings) {
      systemSettings = await SystemSettings.create({})
    }

    // Get tool usage statistics
    const toolStats = await Activity.aggregate([
      {
        $group: {
          _id: '$toolName',
          count: { $sum: 1 },
          successCount: {
            $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
          },
          errorCount: {
            $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] }
          }
        }
      },
      { $sort: { count: -1 } },
      { $limit: 10 }
    ])

    // Get daily activity for the last 7 days
    const sevenDaysAgo = new Date()
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7)
    
    const dailyActivity = await Activity.aggregate([
      {
        $match: {
          createdAt: { $gte: sevenDaysAgo }
        }
      },
      {
        $group: {
          _id: {
            $dateToString: { format: "%Y-%m-%d", date: "$createdAt" }
          },
          count: { $sum: 1 }
        }
      },
      { $sort: { "_id": 1 } }
    ])

    return NextResponse.json({
      success: true,
      data: {
        overview: {
          totalUsers,
          activeUsers,
          totalActivities,
          registrationsToday: await User.countDocuments({
            createdAt: { $gte: new Date(new Date().setHours(0, 0, 0, 0)) }
          })
        },
        recentActivities: recentActivities.map((activity: any) => ({
          id: activity._id,
          user: activity.userId ? {
            id: activity.userId._id,
            username: activity.userId.username,
            email: activity.userId.email,
            name: `${activity.userId.firstName} ${activity.userId.lastName}`
          } : null,
          toolName: activity.toolName,
          action: activity.action,
          status: activity.status,
          duration: activity.duration,
          createdAt: activity.createdAt
        })),
        userStats,
        toolStats,
        dailyActivity,
        systemSettings: {
          maintenanceMode: systemSettings.maintenanceMode,
          registrationEnabled: systemSettings.registrationEnabled,
          maxUsersPerDay: systemSettings.maxUsersPerDay,
          securityLevel: systemSettings.securityLevel
        }
      }
    })

  } catch (error) {
    console.error("Admin dashboard error:", error)
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    )
  }
}
