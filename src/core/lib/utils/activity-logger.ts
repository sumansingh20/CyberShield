import { connectDB } from "@/src/core/lib/mongodb"
import Activity from "@/src/core/lib/models/Activity"

interface ActivityLogData {
  userId: string
  toolName: string
  target?: string
  action: string
  status: 'success' | 'error' | 'warning' | 'info'
  duration: number
  ipAddress?: string
  userAgent?: string
  results?: any
  errorMessage?: string
}

export async function logActivity(data: ActivityLogData) {
  try {
    await connectDB()
    
    const activity = new Activity({
      userId: data.userId,
      toolName: data.toolName,
      target: data.target,
      action: data.action,
      status: data.status,
      duration: data.duration || 0,
      ipAddress: data.ipAddress || '',
      userAgent: data.userAgent || '',
      results: data.results,
      errorMessage: data.errorMessage
    })

    await activity.save()
    
    return {
      success: true,
      activityId: activity._id?.toString() || ''
    }
  } catch (error) {
    console.error('Failed to log activity:', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error'
    }
  }
}

export async function getUserActivity(userId: string, limit: number = 50) {
  try {
    await connectDB()
    
    const activities = await Activity.find({ userId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .lean()

    return {
      success: true,
      activities: activities.map(activity => ({
        ...activity,
        _id: activity._id?.toString(),
        userId: activity.userId?.toString()
      }))
    }
  } catch (error) {
    console.error('Failed to get user activity:', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      activities: []
    }
  }
}

export async function getSystemActivity(limit: number = 100) {
  try {
    await connectDB()
    
    const activities = await Activity.find({})
      .sort({ timestamp: -1 })
      .limit(limit)
      .populate('userId', 'username email role')
      .lean()

    return {
      success: true,
      activities: activities.map(activity => ({
        ...activity,
        _id: activity._id?.toString(),
        userId: activity.userId?.toString() || ''
      }))
    }
  } catch (error) {
    console.error('Failed to get system activity:', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      activities: []
    }
  }
}

export async function getActivityStats(userId?: string) {
  try {
    await connectDB()
    
    const matchStage = userId ? { userId } : {}
    
    const stats = await Activity.aggregate([
      { $match: matchStage },
      {
        $group: {
          _id: null,
          totalScans: { $sum: 1 },
          successfulScans: {
            $sum: { $cond: [{ $eq: ['$status', 'completed'] }, 1, 0] }
          },
          failedScans: {
            $sum: { $cond: [{ $eq: ['$status', 'failed'] }, 1, 0] }
          },
          totalFindings: { $sum: '$findings' },
          avgExecutionTime: { $avg: '$executionTime' },
          scansByCategory: {
            $push: '$toolCategory'
          },
          scansByTool: {
            $push: '$toolName'
          }
        }
      }
    ])

    if (stats.length === 0) {
      return {
        success: true,
        stats: {
          totalScans: 0,
          successfulScans: 0,
          failedScans: 0,
          totalFindings: 0,
          avgExecutionTime: 0,
          scansByCategory: {},
          scansByTool: {}
        }
      }
    }

    const result = stats[0]
    
    // Count occurrences
    const scansByCategory = result.scansByCategory.reduce((acc: Record<string, number>, category: string) => {
      acc[category] = (acc[category] || 0) + 1
      return acc
    }, {})
    
    const scansByTool = result.scansByTool.reduce((acc: Record<string, number>, tool: string) => {
      acc[tool] = (acc[tool] || 0) + 1
      return acc
    }, {})

    return {
      success: true,
      stats: {
        totalScans: result.totalScans,
        successfulScans: result.successfulScans,
        failedScans: result.failedScans,
        totalFindings: result.totalFindings,
        avgExecutionTime: result.avgExecutionTime || 0,
        scansByCategory,
        scansByTool
      }
    }
  } catch (error) {
    console.error('Failed to get activity stats:', error)
    return {
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      stats: null
    }
  }
}
