import { NextRequest, NextResponse } from 'next/server'

// Re-export the main SQL injection implementation
export async function POST(request: NextRequest) {
  try {
    const { POST: sqlInjectionHandler } = await import('@/src/api/tools/sql-injection/route')
    return await sqlInjectionHandler(request)
  } catch (error) {
    console.error('SQL Injection API Error:', error)
    return NextResponse.json(
      { 
        error: 'Internal server error',
        message: 'Failed to process SQL injection testing request'
      }, 
      { status: 500 }
    )
  }
}