import { NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import User from "@/src/core/lib/models/User"
import { verifyAccessToken } from "@/src/core/lib/utils/jwt"

export const dynamic = "force-static"
export const revalidate = 0

export async function GET(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json(
        { error: "Authorization token required" },
        { status: 401 }
      )
    }

    const decoded = await verifyAccessToken(token)

    await connectDB()
    const user = await User.findById(decoded.userId).select("-password")
    
    if (!user) {
      return NextResponse.json(
        { error: "User not found" },
        { status: 404 }
      )
    }

    return NextResponse.json({
      success: true,
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phone: user.phone,
        organization: user.organization,
        location: user.location,
        website: user.website,
        bio: user.bio,
        avatar: user.avatar,
        twoFactorEnabled: user.twoFactorEnabled,
        emailNotifications: user.emailNotifications,
        smsNotifications: user.smsNotifications,
        loginAlerts: user.loginAlerts,
        sessionTimeout: user.sessionTimeout,
        createdAt: user.createdAt,
        lastLoginAt: user.lastLoginAt
      }
    })

  } catch (error) {
    console.error("Profile fetch error:", error)
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    )
  }
}

export async function PUT(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json(
        { error: "Authorization token required" },
        { status: 401 }
      )
    }

    const decoded = await verifyAccessToken(token)

    const {
      firstName,
      lastName,
      phone,
      organization,
      location,
      website,
      bio
    } = await request.json()

    await connectDB()
    
    const updateData: any = {
      updatedAt: new Date()
    }

    if (firstName !== undefined) updateData.firstName = firstName
    if (lastName !== undefined) updateData.lastName = lastName
    if (phone !== undefined) updateData.phone = phone
    if (organization !== undefined) updateData.organization = organization
    if (location !== undefined) updateData.location = location
    if (website !== undefined) updateData.website = website
    if (bio !== undefined) updateData.bio = bio

    const user = await User.findByIdAndUpdate(
      decoded.userId,
      updateData,
      { new: true, select: "-password" }
    )

    if (!user) {
      return NextResponse.json(
        { error: "User not found" },
        { status: 404 }
      )
    }

    return NextResponse.json({
      success: true,
      message: "Profile updated successfully",
      user: {
        id: user._id,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        phone: user.phone,
        organization: user.organization,
        location: user.location,
        website: user.website,
        bio: user.bio,
        avatar: user.avatar
      }
    })

  } catch (error) {
    console.error("Profile update error:", error)
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    )
  }
}
