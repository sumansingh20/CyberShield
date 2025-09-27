import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const { POST: xssScannerHandler } = await import('@/src/api/tools/xss-scanner/route')
    return await xssScannerHandler(request)
  } catch (error) {
    console.error('XSS Scanner API Error:', error)
    return NextResponse.json(
      { 
        error: 'Internal server error',
        message: 'Failed to process XSS vulnerability scan request'
      }, 
      { status: 500 }
    )
  }
}