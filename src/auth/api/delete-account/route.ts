import { NextRequest, NextResponse } from "next/server"
import connectDB from "@/src/core/lib/mongodb"
import User from "@/src/core/lib/models/User"
import { verifyAccessToken } from "@/src/core/lib/utils/jwt"

export async function DELETE(request: NextRequest) {
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

    await connectDB()
    
    const user = await User.findById((decoded as any).userId)
    if (!user) {
      return NextResponse.json(
        { error: "User not found" },
        { status: 404 }
      )
    }

    // Delete the user account
    await User.findByIdAndDelete((decoded as any).userId)

    // TODO: Clean up user-related data
    // - Delete scan logs
    // - Delete OTP records
    // - Delete any other user-related data

    return NextResponse.json({
      success: true,
      message: "Account deleted successfully"
    })

  } catch (error) {
    console.error("Account deletion error:", error)
    return NextResponse.json(
      { error: "Internal server error" },
      { status: 500 }
    )
  }
}
