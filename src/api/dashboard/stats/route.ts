import { NextRequest, NextResponse } from "next/server"
import { authMiddleware } from "@/src/core/lib/middleware/auth"
import connectDB from "@/src/core/lib/mongodb"
import { ScanLog } from "@/src/core/lib/models/ScanLog"
import mongoose from "mongoose"

interface DashboardStats {
  totalScans: number
  successfulScans: number
  failedScans: number
  avgExecutionTime: number
  securityScore: number
  criticalVulnerabilities: number
  highVulnerabilities: number
  mediumVulnerabilities: number
  lowVulnerabilities: number
  infoFindings: number
  scansByCategory: Record<string, number>
  scansByTool: Record<string, number>
  scanTrends: {
    date: string
    count: number
  }[]
  vulnerabilityTrends: {
    date: string
    critical: number
    high: number
    medium: number
    low: number
  }[]
  recentActivity: {
    toolName: string
    toolCategory: string
    target: string
    status: string
    findings: number
    executionTime: number
    timestamp: Date
  }[]
}

export async function GET(req: NextRequest) {
  try {
    const authResult = await authMiddleware(req)
    if (!authResult.success) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 })
    }

    await connectDB()

    // Get the date range from query params or default to last 30 days
    const days = parseInt(req.nextUrl.searchParams.get("days") || "30")
    const startDate = new Date()
    startDate.setDate(startDate.getDate() - days)

    const userId = new mongoose.Types.ObjectId(authResult.userId)

    // Get total scans and their status distribution
    const [
      totalScans,
      statusDistribution,
      avgExecTime,
      categoryStats,
      toolStats,
      vulnerabilityStats,
      scanTrends,
      vulnerabilityTrends,
      recentActivity
    ] = await Promise.all([
      // Total scans
      ScanLog.countDocuments({ userId }),

      // Status distribution
      ScanLog.aggregate([
        { $match: { userId } },
        {
          $group: {
            _id: "$status",
            count: { $sum: 1 }
          }
        }
      ]),

      // Average execution time
      ScanLog.aggregate([
        { $match: { userId } },
        {
          $group: {
            _id: null,
            avgTime: { $avg: "$metrics.duration" }
          }
        }
      ]),

      // Scans by category
      ScanLog.aggregate([
        { $match: { userId } },
        {
          $group: {
            _id: "$toolCategory",
            count: { $sum: 1 }
          }
        }
      ]),

      // Scans by tool
      ScanLog.aggregate([
        { $match: { userId } },
        {
          $group: {
            _id: "$toolName",
            count: { $sum: 1 }
          }
        }
      ]),

      // Vulnerability statistics
      ScanLog.aggregate([
        { $match: { userId } },
        {
          $group: {
            _id: null,
            totalCritical: { $sum: "$statistics.criticalCount" },
            totalHigh: { $sum: "$statistics.highCount" },
            totalMedium: { $sum: "$statistics.mediumCount" },
            totalLow: { $sum: "$statistics.lowCount" },
            totalInfo: { $sum: "$statistics.infoCount" }
          }
        }
      ]),

      // Scan trends (daily count for the selected period)
      ScanLog.aggregate([
        {
          $match: {
            userId,
            createdAt: { $gte: startDate }
          }
        },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            count: { $sum: 1 }
          }
        },
        { $sort: { _id: 1 } }
      ]),

      // Vulnerability trends
      ScanLog.aggregate([
        {
          $match: {
            userId,
            createdAt: { $gte: startDate }
          }
        },
        {
          $group: {
            _id: { $dateToString: { format: "%Y-%m-%d", date: "$createdAt" } },
            critical: { $sum: "$statistics.criticalCount" },
            high: { $sum: "$statistics.highCount" },
            medium: { $sum: "$statistics.mediumCount" },
            low: { $sum: "$statistics.lowCount" }
          }
        },
        { $sort: { _id: 1 } }
      ]),

      // Recent activity
      ScanLog.find({ userId })
        .sort({ createdAt: -1 })
        .limit(10)
        .select({
          toolName: 1,
          toolCategory: 1,
          "input.target.host": 1,
          status: 1,
          "statistics.totalVulnerabilities": 1,
          "metrics.duration": 1,
          createdAt: 1
        })
    ])

    // Convert status distribution array to object
    const statusCounts = statusDistribution.reduce((acc, curr) => {
      acc[curr._id] = curr.count
      return acc
    }, {} as Record<string, number>)

    // Calculate security score based on vulnerability distribution and scan success rate
    const vulnStats = vulnerabilityStats[0] || {
      totalCritical: 0,
      totalHigh: 0,
      totalMedium: 0,
      totalLow: 0,
      totalInfo: 0
    }

    const totalVulnerabilities = 
      vulnStats.totalCritical +
      vulnStats.totalHigh +
      vulnStats.totalMedium +
      vulnStats.totalLow +
      vulnStats.totalInfo

    const weightedScore = totalVulnerabilities > 0
      ? 100 - (
        (vulnStats.totalCritical * 10 +
         vulnStats.totalHigh * 7 +
         vulnStats.totalMedium * 4 +
         vulnStats.totalLow * 2) / 
        totalVulnerabilities
      )
      : 100

    const successRate = statusCounts.success
      ? (statusCounts.success / totalScans) * 100
      : 100

    const securityScore = Math.round((weightedScore * 0.7 + successRate * 0.3))

    const stats: DashboardStats = {
      totalScans,
      successfulScans: statusCounts.success || 0,
      failedScans: (statusCounts.error || 0) + (statusCounts.timeout || 0),
      avgExecutionTime: avgExecTime[0]?.avgTime || 0,
      securityScore,
      criticalVulnerabilities: vulnStats.totalCritical,
      highVulnerabilities: vulnStats.totalHigh,
      mediumVulnerabilities: vulnStats.totalMedium,
      lowVulnerabilities: vulnStats.totalLow,
      infoFindings: vulnStats.totalInfo,
      scansByCategory: Object.fromEntries(
        categoryStats.map(stat => [stat._id, stat.count])
      ),
      scansByTool: Object.fromEntries(
        toolStats.map(stat => [stat._id, stat.count])
      ),
      scanTrends: scanTrends.map(trend => ({
        date: trend._id,
        count: trend.count
      })),
      vulnerabilityTrends: vulnerabilityTrends.map(trend => ({
        date: trend._id,
        critical: trend.critical,
        high: trend.high,
        medium: trend.medium,
        low: trend.low
      })),
      recentActivity: recentActivity.map(activity => ({
        toolName: activity.toolName,
        toolCategory: activity.toolCategory,
        target: activity.input.target.host,
        status: activity.status,
        findings: activity.statistics.totalVulnerabilities,
        executionTime: activity.metrics.duration,
        timestamp: activity.createdAt
      }))
    }

    return NextResponse.json(stats)
  } catch (error) {
    console.error("Error fetching dashboard stats:", error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : String(error) || "Unknown error" },
      { status: 500 }
    )
  }
}
