import { NextRequest, NextResponse } from 'next/server'
import jwt from 'jsonwebtoken'
import { generateBackupCodes, saveBackupCodes, verifyBackupCode, getRemainingBackupCodesCount } from '@/src/core/lib/utils/backup-codes'
import { z } from 'zod'

// JWT verification function
function verifyToken(token: string) {
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as any
    return decoded
  } catch (error) {
    return null
  }
}

// POST - Generate backup codes
export async function POST(req: NextRequest) {
  try {
    // Get user from token
    const token = req.headers.get('authorization')?.replace('Bearer ', '')
    if (!token) {
      return NextResponse.json({
        success: false,
        message: 'Authorization token required'
      }, { status: 401 })
    }

    const payload = verifyToken(token)
    if (!payload) {
      return NextResponse.json({
        success: false,
        message: 'Invalid or expired token'
      }, { status: 401 })
    }

    const userId = payload.userId

    // Generate new backup codes
    console.log(`🔑 Generating backup codes for user: ${userId}`)
    const codes = generateBackupCodes()
    
    // Save hashed codes to database
    const saved = await saveBackupCodes(userId, codes)
    
    if (!saved) {
      return NextResponse.json({
        success: false,
        message: 'Failed to generate backup codes'
      }, { status: 500 })
    }

    console.log(`✅ Backup codes generated for user: ${userId}`)

    return NextResponse.json({
      success: true,
      message: 'Backup codes generated successfully',
      codes: codes, // Return plain codes to user (one time only)
      warning: 'Save these codes securely. They will not be shown again!'
    })

  } catch (error) {
    console.error('Backup codes generation error:', error)
    return NextResponse.json({
      success: false,
      message: 'Failed to generate backup codes'
    }, { status: 500 })
  }
}

// PUT - Verify backup code
export async function PUT(req: NextRequest) {
  try {
    const body = await req.json()
    const { code } = body
    
    if (!code) {
      return NextResponse.json({
        success: false,
        message: 'Backup code is required'
      }, { status: 400 })
    }

    // Get user from token
    const token = req.headers.get('authorization')?.replace('Bearer ', '')
    if (!token) {
      return NextResponse.json({
        success: false,
        message: 'Authorization token required'
      }, { status: 401 })
    }

    const payload = verifyToken(token)
    if (!payload) {
      return NextResponse.json({
        success: false,
        message: 'Invalid or expired token'
      }, { status: 401 })
    }

    const userId = payload.userId

    // Verify backup code
    console.log(`🔑 Verifying backup code for user: ${userId}`)
    const verified = await verifyBackupCode(userId, code)
    
    if (!verified) {
      return NextResponse.json({
        success: false,
        message: 'Invalid backup code'
      }, { status: 400 })
    }

    // Get remaining codes count
    const remainingCount = await getRemainingBackupCodesCount(userId)

    console.log(`✅ Backup code verified for user: ${userId}, remaining: ${remainingCount}`)

    return NextResponse.json({
      success: true,
      message: 'Backup code verified successfully',
      remainingCodes: remainingCount,
      warning: remainingCount <= 2 ? 'You are running low on backup codes. Consider generating new ones.' : undefined
    })

  } catch (error) {
    console.error('Backup code verification error:', error)
    return NextResponse.json({
      success: false,
      message: 'Failed to verify backup code'
    }, { status: 500 })
  }
}

// GET - Check remaining backup codes count
export async function GET(req: NextRequest) {
  try {
    // Get user from token
    const token = req.headers.get('authorization')?.replace('Bearer ', '')
    if (!token) {
      return NextResponse.json({
        success: false,
        message: 'Authorization token required'
      }, { status: 401 })
    }

    const payload = verifyToken(token)
    if (!payload) {
      return NextResponse.json({
        success: false,
        message: 'Invalid or expired token'
      }, { status: 401 })
    }

    const userId = payload.userId
    const remainingCount = await getRemainingBackupCodesCount(userId)

    return NextResponse.json({
      success: true,
      remainingCodes: remainingCount,
      hasBackupCodes: remainingCount > 0
    })

  } catch (error) {
    console.error('Backup codes check error:', error)
    return NextResponse.json({
      success: false,
      message: 'Failed to check backup codes'
    }, { status: 500 })
  }
}
