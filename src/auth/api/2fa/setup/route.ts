import { NextRequest, NextResponse } from 'next/server'
import speakeasy from 'speakeasy'
import QRCode from 'qrcode'
import User from '@/src/core/lib/models/User'
import connectDB from '@/src/core/lib/mongodb'
import { verifyJWT, TokenPayload } from '@/src/core/lib/utils/jwt-helper'

// GET - Generate 2FA setup (secret and QR code)
export async function GET(req: NextRequest) {
  try {
    const authHeader = req.headers.get('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Authorization token required' },
        { status: 401 }
      )
    }

    const token = authHeader.substring(7)
    const decoded = verifyJWT<TokenPayload>(token)
    
    await connectDB()
    const user = await User.findById(decoded.userId).select('+twoFactorSecret')
    
    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    // If 2FA is already enabled, don't allow setup again
    if (user.twoFactorEnabled) {
      return NextResponse.json(
        { error: '2FA is already enabled' },
        { status: 400 }
      )
    }

    // Generate new secret
    const secret = speakeasy.generateSecret({
      name: `CyberShield (${user.email})`,
      issuer: 'CyberShield',
      length: 32
    })

    // Generate QR code
    const qrCodeUrl = await QRCode.toDataURL(secret.otpauth_url!)

    // Store temporary secret (not enabled yet)
    await User.findByIdAndUpdate(decoded.userId, {
      twoFactorSecret: secret.base32
    })

    return NextResponse.json({
      secret: secret.base32,
      qrCode: qrCodeUrl,
      manualEntryKey: secret.base32,
      issuer: 'CyberShield',
      accountName: user.email
    })

  } catch (error) {
    console.error('2FA setup error:', error)
    return NextResponse.json(
      { error: 'Failed to setup 2FA' },
      { status: 500 }
    )
  }
}

// POST - Enable 2FA after verifying code
export async function POST(req: NextRequest) {
  try {
    const authHeader = req.headers.get('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Authorization token required' },
        { status: 401 }
      )
    }

    const token = authHeader.substring(7)
    const decoded = await verifyJWT<{ userId: string }>(token)
    
    const { code } = await req.json()
    
    if (!code) {
      return NextResponse.json(
        { error: 'Verification code is required' },
        { status: 400 }
      )
    }

    await connectDB()
    const user = await User.findById(decoded.userId).select('+twoFactorSecret')
    
    if (!user || !user.twoFactorSecret) {
      return NextResponse.json(
        { error: 'Setup 2FA first' },
        { status: 400 }
      )
    }

    // Verify the code
    const verified = speakeasy.totp.verify({
      secret: user.twoFactorSecret,
      encoding: 'base32',
      token: code,
      window: 2 // Allow 2 steps before/after for clock drift
    })

    if (!verified) {
      return NextResponse.json(
        { error: 'Invalid verification code' },
        { status: 400 }
      )
    }

    // Generate backup codes
    const backupCodes = []
    for (let i = 0; i < 10; i++) {
      const code = Math.random().toString(36).substring(2, 8).toUpperCase()
      backupCodes.push(code)
    }

    // Enable 2FA
    await User.findByIdAndUpdate(decoded.userId, {
      twoFactorEnabled: true,
      twoFactorBackupCodes: backupCodes
    })

    return NextResponse.json({
      success: true,
      message: '2FA enabled successfully',
      backupCodes
    })

  } catch (error) {
    console.error('2FA enable error:', error)
    return NextResponse.json(
      { error: 'Failed to enable 2FA' },
      { status: 500 }
    )
  }
}

// DELETE - Disable 2FA
export async function DELETE(req: NextRequest) {
  try {
    const authHeader = req.headers.get('authorization')
    if (!authHeader?.startsWith('Bearer ')) {
      return NextResponse.json(
        { error: 'Authorization token required' },
        { status: 401 }
      )
    }

    const token = authHeader.substring(7)
    const decoded = await verifyJWT<{ userId: string }>(token)
    
    const { password } = await req.json()
    
    if (!password) {
      return NextResponse.json(
        { error: 'Password is required to disable 2FA' },
        { status: 400 }
      )
    }

    await connectDB()
    const user = await User.findById(decoded.userId).select('+password')
    
    if (!user) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      )
    }

    // Verify password
    const isValidPassword = await user.comparePassword(password)
    if (!isValidPassword) {
      return NextResponse.json(
        { error: 'Invalid password' },
        { status: 400 }
      )
    }

    // Disable 2FA
    await User.findByIdAndUpdate(decoded.userId, {
      twoFactorEnabled: false,
      $unset: {
        twoFactorSecret: 1,
        twoFactorBackupCodes: 1
      }
    })

    return NextResponse.json({
      success: true,
      message: '2FA disabled successfully'
    })

  } catch (error) {
    console.error('2FA disable error:', error)
    return NextResponse.json(
      { error: 'Failed to disable 2FA' },
      { status: 500 }
    )
  }
}
