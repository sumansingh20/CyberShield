import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const { POST: passwordCrackingHandler } = await import('@/src/api/tools/password-cracking/route')
    return await passwordCrackingHandler(request)
  } catch (error) {
    console.error('Password Cracking API Error:', error)
    return NextResponse.json(
      { 
        error: 'Internal server error',
        message: 'Failed to process password cracking request'
      }, 
      { status: 500 }
    )
  }
}