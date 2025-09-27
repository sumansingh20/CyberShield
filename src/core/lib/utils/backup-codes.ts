import crypto from 'crypto'
import connectToDatabase from '@/src/core/lib/mongodb'
import User from '@/src/core/lib/models/User'

// Generate backup codes for user
export const generateBackupCodes = (): string[] => {
  const codes = []
  for (let i = 0; i < 10; i++) {
    // Generate 8-digit backup codes
    const code = crypto.randomInt(10000000, 99999999).toString()
    codes.push(code)
  }
  return codes
}

// Hash backup codes for secure storage
export const hashBackupCodes = (codes: string[]): string[] => {
  return codes.map(code => {
    return crypto.createHash('sha256').update(code).digest('hex')
  })
}

// Save backup codes to user account
export const saveBackupCodes = async (userId: string, codes: string[]): Promise<boolean> => {
  try {
    await connectToDatabase()
    const hashedCodes = hashBackupCodes(codes)
    
    await User.findByIdAndUpdate(userId, {
      backupCodes: hashedCodes,
      backupCodesGenerated: new Date()
    })
    
    console.log(`✅ Backup codes saved for user: ${userId}`)
    return true
  } catch (error) {
    console.error('❌ Failed to save backup codes:', error)
    return false
  }
}

// Verify backup code
export const verifyBackupCode = async (userId: string, code: string): Promise<boolean> => {
  try {
    await connectToDatabase()
    const user = await User.findById(userId)
    
    if (!user || !user.backupCodes || user.backupCodes.length === 0) {
      return false
    }
    
    const hashedCode = crypto.createHash('sha256').update(code).digest('hex')
    const codeIndex = user.backupCodes.indexOf(hashedCode)
    
    if (codeIndex === -1) {
      return false
    }
    
    // Remove used backup code (single use only)
    user.backupCodes.splice(codeIndex, 1)
    await user.save()
    
    console.log(`✅ Backup code verified and removed for user: ${userId}`)
    return true
  } catch (error) {
    console.error('❌ Failed to verify backup code:', error)
    return false
  }
}

// Get remaining backup codes count
export const getRemainingBackupCodesCount = async (userId: string): Promise<number> => {
  try {
    await connectToDatabase()
    const user = await User.findById(userId)
    
    if (!user || !user.backupCodes) {
      return 0
    }
    
    return user.backupCodes.length
  } catch (error) {
    console.error('❌ Failed to get backup codes count:', error)
    return 0
  }
}
