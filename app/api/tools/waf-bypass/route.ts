import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const { POST: wafBypassHandler } = await import('@/src/api/tools/waf-bypass/route')
    return await wafBypassHandler(request)
  } catch (error) {
    console.error('WAF Bypass API Error:', error)
    return NextResponse.json(
      { 
        error: 'Internal server error',
        message: 'Failed to process WAF bypass testing request'
      }, 
      { status: 500 }
    )
  }
}