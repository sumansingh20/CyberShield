import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const { POST: directoryBruteforceHandler } = await import('@/src/api/tools/directory-bruteforce/route')
    return await directoryBruteforceHandler(request)
  } catch (error) {
    console.error('Directory Brute Force API Error:', error)
    return NextResponse.json(
      { 
        error: 'Internal server error',
        message: 'Failed to process directory brute force request'
      }, 
      { status: 500 }
    )
  }
}