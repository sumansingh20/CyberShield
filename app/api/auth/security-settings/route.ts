import { NextRequest, NextResponse } from "next/server"
import connectDB from "@/lib/mongodb"
import User from "@/lib/models/User"
import { verifyAccessToken } from "@/lib/utils/jwt"

export async function PUT(request: NextRequest) {
  try {
    const token = request.headers.get("authorization")?.replace("Bearer ", "")
    
    if (!token) {
      return NextResponse.json(
        { error: "Authorization token required" },
        { status: 401 }
      )
    }

    const decoded = verifyAccessToken(token)
    if (!decoded) {
      return NextResponse.json(
        { error: "Invalid token" },
        { status: 401 }
      )
    }

    const {
      twoFactorEnabled,
      emailNotifications,
      smsNotifications,
      loginAlerts,
      sessionTimeout
    } = await request.json()

    await connectDB()
    
    const updateData: any = {
      updatedAt: new Date()
    }

    if (twoFactorEnabled !== undefined) updateData.twoFactorEnabled = twoFactorEnabled
    if (emailNotifications !== undefined) updateData.emailNotifications = emailNotifications
    if (smsNotifications !== undefined) updateData.smsNotifications = smsNotifications
    if (loginAlerts !== undefined) updateData.loginAlerts = loginAlerts
    if (sessionTimeout !== undefined) updateData.sessionTimeout = sessionTimeout

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
      message: "Security settings updated successfully",
      settings: {
        twoFactorEnabled: user.twoFactorEnabled,
        emailNotifications: user.emailNotifications,
        smsNotifications: user.smsNotifications,
        loginAlerts: user.loginAlerts,
        sessionTimeout: user.sessionTimeout
      }
    })

  } catch (error) {
    console.error("Security settings update error:", error)
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    )
  }
}
