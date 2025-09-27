import { NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

// Ultra-fast health check without database connection
export async function GET() {
  try {
    const timestamp = new Date().toISOString()
    
    return NextResponse.json({
      success: true,
      status: 'healthy',
      timestamp,
      performance: 'optimized',
      uptime: process.uptime(),
      memory: process.memoryUsage(),
      environment: process.env.NODE_ENV || 'development'
    }, {
      headers: {
        'Cache-Control': 'no-store, must-revalidate',
        'Pragma': 'no-cache'
      }
    })
  } catch (error) {
    return NextResponse.json({
      success: false,
      status: 'error',
      message: 'Health check failed'
    }, { status: 500 })
  }
}