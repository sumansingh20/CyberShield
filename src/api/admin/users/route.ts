import { NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import User from "@/src/core/lib/models/User"
import Activity from "@/src/core/lib/models/Activity"
import { verifyAccessToken } from "@/src/core/lib/utils/jwt"
import { z } from "zod"

// Get all users (admin only)
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

    const { searchParams } = new URL(request.url)
    const page = parseInt(searchParams.get('page') || '1')
    const limit = parseInt(searchParams.get('limit') || '20')
    const search = searchParams.get('search') || ''
    const role = searchParams.get('role') || ''
    const status = searchParams.get('status') || ''

    // Build query
    const query: any = {}
    
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
        { firstName: { $regex: search, $options: 'i' } },
        { lastName: { $regex: search, $options: 'i' } }
      ]
    }

    if (role) {
      query.role = role
    }

    if (status === 'active') {
      query.isVerified = true
      query.lockUntil = { $exists: false }
    } else if (status === 'inactive') {
      query.$or = [
        { isVerified: false },
        { lockUntil: { $exists: true } }
      ]
    }

    const skip = (page - 1) * limit

    const [users, totalUsers] = await Promise.all([
      User.find(query)
        .select('-password -verificationToken -resetPasswordToken -twoFactorSecret')
        .sort({ createdAt: -1 })
        .skip(skip)
        .limit(limit),
      User.countDocuments(query)
    ])

    // Get activity count for each user
    const usersWithActivity = await Promise.all(
      users.map(async (user) => {
        const activityCount = await Activity.countDocuments({ userId: user._id })
        return {
          ...user.toObject(),
          activityCount
        }
      })
    )

    return NextResponse.json({
      success: true,
      data: {
        users: usersWithActivity,
        pagination: {
          current: page,
          totalPages: Math.ceil(totalUsers / limit),
          totalUsers,
          hasNext: page * limit < totalUsers,
          hasPrev: page > 1
        }
      }
    })

  } catch (error) {
    console.error("Get users error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

// Update user (admin only)
const updateUserSchema = z.object({
  userId: z.string(),
  updates: z.object({
    username: z.string().optional(),
    email: z.string().email().optional(),
    firstName: z.string().optional(),
    lastName: z.string().optional(),
    role: z.enum(['user', 'admin']).optional(),
    isVerified: z.boolean().optional(),
    emailNotifications: z.boolean().optional(),
    smsNotifications: z.boolean().optional(),
    loginAlerts: z.boolean().optional(),
    sessionTimeout: z.string().optional()
  })
})

export async function PUT(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json({ error: "Authorization token required" }, { status: 401 })
    }

    const decoded = await verifyAccessToken(token)
    if (decoded.role !== 'admin') {
      return NextResponse.json({ error: "Admin access required" }, { status: 403 })
    }

    const body = await request.json()
    const validation = updateUserSchema.safeParse(body)
    
    if (!validation.success) {
      return NextResponse.json({
        error: "Invalid input data",
        details: validation.error.errors
      }, { status: 400 })
    }

    const { userId, updates } = validation.data

    await connectDB()

    // Check if user exists
    const user = await User.findById(userId)
    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 })
    }

    // Prevent admin from demoting themselves
    if (userId === decoded.userId && updates.role === 'user') {
      return NextResponse.json({ 
        error: "You cannot change your own role" 
      }, { status: 400 })
    }

    // Update user
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { ...updates, updatedAt: new Date() },
      { new: true, select: '-password -verificationToken -resetPasswordToken -twoFactorSecret' }
    )

    // Log admin action
    await Activity.create({
      userId: decoded.userId,
      toolName: 'admin',
      action: `Updated user: ${user.email}`,
      status: 'success',
      duration: 0,
      ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || 'Unknown',
      results: { targetUser: user.email, updates }
    }).catch(console.error)

    return NextResponse.json({
      success: true,
      message: "User updated successfully",
      data: updatedUser
    })

  } catch (error) {
    console.error("Update user error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}

// Delete user (admin only)
export async function DELETE(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json({ error: "Authorization token required" }, { status: 401 })
    }

    const decoded = await verifyAccessToken(token)
    if (decoded.role !== 'admin') {
      return NextResponse.json({ error: "Admin access required" }, { status: 403 })
    }

    const { searchParams } = new URL(request.url)
    const userId = searchParams.get('userId')

    if (!userId) {
      return NextResponse.json({ error: "User ID is required" }, { status: 400 })
    }

    await connectDB()

    // Check if user exists
    const user = await User.findById(userId)
    if (!user) {
      return NextResponse.json({ error: "User not found" }, { status: 404 })
    }

    // Prevent admin from deleting themselves
    if (userId === decoded.userId) {
      return NextResponse.json({ 
        error: "You cannot delete your own account" 
      }, { status: 400 })
    }

    // Delete user and their activities
    await Promise.all([
      User.findByIdAndDelete(userId),
      Activity.deleteMany({ userId })
    ])

    // Log admin action
    await Activity.create({
      userId: decoded.userId,
      toolName: 'admin',
      action: `Deleted user: ${user.email}`,
      status: 'success',
      duration: 0,
      ipAddress: request.headers.get('x-forwarded-for') || '127.0.0.1',
      userAgent: request.headers.get('user-agent') || 'Unknown',
      results: { deletedUser: user.email }
    }).catch(console.error)

    return NextResponse.json({
      success: true,
      message: "User deleted successfully"
    })

  } catch (error) {
    console.error("Delete user error:", error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 })
  }
}
