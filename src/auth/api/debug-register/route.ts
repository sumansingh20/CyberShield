import { NextRequest, NextResponse } from "next/server"

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    console.log("🔍 Registration Debug - Received data:", JSON.stringify(body, null, 2))
    
    // Test the actual registration endpoint
    const registerResponse = await fetch(`${request.nextUrl.origin}/api/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(body)
    })
    
    const registerData = await registerResponse.json()
    console.log("🔍 Registration Debug - API Response:", JSON.stringify(registerData, null, 2))
    console.log("🔍 Registration Debug - Status:", registerResponse.status)
    
    return NextResponse.json({
      debug: true,
      receivedData: body,
      apiResponse: registerData,
      status: registerResponse.status,
      success: registerResponse.ok
    })
    
  } catch (error) {
    console.error("🚨 Registration Debug Error:", error)
    return NextResponse.json({
      debug: true,
      error: error instanceof Error ? error.message : "Unknown error"
    }, { status: 500 })
  }
}
