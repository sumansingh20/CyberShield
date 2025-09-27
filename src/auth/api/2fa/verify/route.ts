import { NextRequest, NextResponse } from 'next/server'
import speakeasy from 'speakeasy'
import User from '@/src/core/lib/models/User'
import Activity from '@/src/core/lib/models/Activity'
import connectDB from '@/src/core/lib/mongodb'
import { verifyJWT, signJWT, TempTokenPayload } from '@/src/core/lib/utils/jwt-helper'
import { generateTokens } from '@/src/core/lib/utils/jwt'

// POST - Verify 2FA code during login
export async function POST(req: NextRequest) {
  try {
    const { tempToken, code, isBackupCode = false } = await req.json()
    
    if (!tempToken || !code) {
      return NextResponse.json(
        { error: 'Temporary token and verification code are required' },
        { status: 400 }
      )
    }

    // Verify temp token
    let decoded
    try {
      decoded = await verifyJWT<TempTokenPayload>(tempToken)
      
      if (decoded.type !== 'temp-2fa') {
        throw new Error('Invalid token type')
      }
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid or expired temporary token' },
        { status: 401 }
      )
    }

    await connectDB()
    const user = await User.findById(decoded.userId)
      .select('+twoFactorSecret +twoFactorBackupCodes')
    
    if (!user || !user.twoFactorEnabled) {
      return NextResponse.json(
        { error: 'User not found or 2FA not enabled' },
        { status: 404 }
      )
    }

    let verified = false

    if (isBackupCode) {
      // Verify backup code
      if (user.twoFactorBackupCodes?.includes(code.toUpperCase())) {
        verified = true
        
        // Remove used backup code
        await User.findByIdAndUpdate(decoded.userId, {
          $pull: { twoFactorBackupCodes: code.toUpperCase() }
        })
      }
    } else {
      // Verify TOTP code
      verified = speakeasy.totp.verify({
        secret: user.twoFactorSecret!,
        encoding: 'base32',
        token: code,
        window: 2 // Allow 2 steps before/after for clock drift
      })
    }

    if (!verified) {
      // Log failed 2FA attempt
      const userIP = req.headers.get('x-forwarded-for') || 
                    req.headers.get('x-real-ip') || 
                    '127.0.0.1'
      const userAgent = req.headers.get('user-agent') || 'Unknown'

      await Activity.create({
        userId: user._id,
        toolName: 'login',
        action: '2FA verification failed',
        status: 'error',
        duration: 0,
        ipAddress: userIP,
        userAgent: userAgent
      }).catch(console.error)

      // Increment login attempts
      await user.incLoginAttempts()
      
      return NextResponse.json(
        { error: isBackupCode ? 'Invalid backup code' : 'Invalid verification code' },
        { status: 400 }
      )
    }

    // Generate final JWT tokens
    const tokens = await generateTokens({
      userId: user._id.toString(),
      email: user.email,
      role: user.role
    })

    // Update user login info
    await User.findByIdAndUpdate(decoded.userId, {
      lastLoginAt: new Date(),
      lastActiveAt: new Date(),
      $unset: { loginAttempts: 1, lockUntil: 1 }
    })

    // Log successful login
    const userIP = req.headers.get('x-forwarded-for') || 
                  req.headers.get('x-real-ip') || 
                  '127.0.0.1'
    const userAgent = req.headers.get('user-agent') || 'Unknown'

    await Activity.create({
      userId: user._id,
      toolName: 'login',
      action: '2FA login successful',
      status: 'success',
      duration: 0,
      ipAddress: userIP,
      userAgent: userAgent
    }).catch(console.error)

    // Create response
    const response = NextResponse.json({
      success: true,
      message: 'Login successful',
      user: {
        id: user._id.toString(),
        email: user.email,
        username: user.username,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
        avatar: user.avatar,
        isVerified: user.isVerified,
        twoFactorEnabled: user.twoFactorEnabled
      },
      tokens
    })

    // Set HTTP-only cookies
    const isProduction = process.env.NODE_ENV === 'production'
    
    response.cookies.set({
      name: 'accessToken',
      value: tokens.accessToken,
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: 15 * 60 // 15 minutes
    })

    response.cookies.set({
      name: 'refreshToken',
      value: tokens.refreshToken,
      httpOnly: true,
      secure: isProduction,
      sameSite: 'lax',
      path: '/',
      maxAge: 7 * 24 * 60 * 60 // 7 days
    })

    return response

  } catch (error) {
    console.error('2FA verification error:', error)
    return NextResponse.json(
      { error: 'Failed to verify 2FA code' },
      { status: 500 }
    )
  }
}

// GET - Check 2FA status for a user
export async function GET(req: NextRequest) {
  try {
    const { searchParams } = new URL(req.url)
    const tempToken = searchParams.get('tempToken')
    
    if (!tempToken) {
      return NextResponse.json(
        { error: 'Temporary token is required' },
        { status: 400 }
      )
    }

    // Verify temp token
    let decoded
    try {
      decoded = verifyJWT<TempTokenPayload>(tempToken)
      
      if (decoded.type !== 'temp-2fa') {
        throw new Error('Invalid token type')
      }
    } catch (error) {
      return NextResponse.json(
        { error: 'Invalid or expired temporary token' },
        { status: 401 }
      )
    }

    await connectDB()
    const user = await User.findById(decoded.userId)
      .select('+twoFactorBackupCodes')
    
    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    return NextResponse.json({
      twoFactorEnabled: user.twoFactorEnabled,
      hasBackupCodes: user.twoFactorBackupCodes && user.twoFactorBackupCodes.length > 0,
      backupCodesRemaining: user.twoFactorBackupCodes?.length || 0
    })

  } catch (error) {
    console.error('2FA status check error:', error)
    return NextResponse.json(
      { error: 'Failed to check 2FA status' },
      { status: 500 }
    )
  }
}
