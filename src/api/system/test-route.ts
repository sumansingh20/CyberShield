import { NextResponse } from "next/server"

export async function GET() {
  try {
    return NextResponse.json({
      success: true,
      message: "CyberShield API is working!",
      timestamp: new Date().toISOString(),
      environment: process.env.NODE_ENV || 'development'
    }, { status: 200 })
  } catch (error) {
    return NextResponse.json({
      success: false,
      message: "API test failed",
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

export async function POST() {
  try {
    return NextResponse.json({
      success: true,
      message: "POST endpoint working!",
      timestamp: new Date().toISOString()
    }, { status: 200 })
  } catch (error) {
    return NextResponse.json({
      success: false,
      message: "POST test failed",
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
