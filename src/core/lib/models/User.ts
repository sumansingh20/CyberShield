import mongoose from "mongoose"
import bcrypt from "bcryptjs"

export interface IUser extends mongoose.Document {
  username: string
  email: string
  phone?: string
  password: string
  role: "user" | "admin"
  isVerified: boolean
  verificationToken?: string
  twoFactorEnabled: boolean
  twoFactorSecret?: string
  twoFactorBackupCodes?: string[]
  backupCodes?: string[]
  backupCodesGenerated?: Date
  preferredTwoFactorMethod: 'totp' | 'sms' | 'email' | 'voice'
  firstName: string
  lastName: string
  avatar?: string
  organization?: string
  location?: string
  website?: string
  bio?: string
  agreeToTerms: boolean
  emailNotifications: boolean
  smsNotifications: boolean
  loginAlerts: boolean
  sessionTimeout: string
  lastLoginAt?: Date
  passwordChangedAt?: Date
  loginAttempts: number
  lockUntil?: Date
  resetPasswordToken?: string
  resetPasswordExpires?: Date
  toolsUsed: string[]
  totalScans: number
  lastActiveAt: Date
  createdAt: Date
  updatedAt: Date
  comparePassword(candidatePassword: string): Promise<boolean>
  incLoginAttempts(): Promise<void>
  resetLoginAttempts(): Promise<void>
  generateVerificationToken(): string
  generatePasswordResetToken(): string
  isLocked: boolean
}

const userSchema = new mongoose.Schema(
  {
    username: {
      type: String,
      required: [true, 'Username is required'],
      unique: true,
      trim: true,
      minlength: [3, 'Username must be at least 3 characters long'],
      maxlength: [30, 'Username cannot exceed 30 characters']
    },
    email: {
      type: String,
      required: [true, 'Email is required'],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
    },
    phone: {
      type: String,
      trim: true,
      match: [/^[\+]?[1-9][\d]{0,15}$/, 'Please enter a valid phone number']
    },
    password: {
      type: String,
      required: [true, 'Password is required'],
      minlength: process.env.NODE_ENV === 'development' ? [6, 'Password must be at least 6 characters long'] : [8, 'Password must be at least 8 characters long'],
      select: false // Don't include password in queries by default
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user"
    },
    isVerified: {
      type: Boolean,
      default: false
    },
    verificationToken: {
      type: String,
      select: false
    },
    twoFactorEnabled: {
      type: Boolean,
      default: false
    },
    twoFactorSecret: {
      type: String,
      select: false
    },
    twoFactorBackupCodes: [{
      type: String,
      select: false
    }],
    backupCodes: [{
      type: String,
      select: false
    }],
    backupCodesGenerated: {
      type: Date
    },
    preferredTwoFactorMethod: {
      type: String,
      enum: ['totp', 'sms', 'email', 'voice'],
      default: 'totp'
    },
    firstName: {
      type: String,
      required: [true, 'First name is required'],
      trim: true,
      maxlength: [50, 'First name cannot exceed 50 characters']
    },
    lastName: {
      type: String,
      required: [true, 'Last name is required'],
      trim: true,
      maxlength: [50, 'Last name cannot exceed 50 characters']
    },
    avatar: {
      type: String,
      default: null
    },
    organization: {
      type: String,
      trim: true,
      maxlength: [100, 'Organization name cannot exceed 100 characters']
    },
    location: {
      type: String,
      trim: true,
      maxlength: [100, 'Location cannot exceed 100 characters']
    },
    website: {
      type: String,
      trim: true,
      match: [/^https?:\/\/.+/, 'Please enter a valid URL']
    },
    bio: {
      type: String,
      trim: true,
      maxlength: [500, 'Bio cannot exceed 500 characters']
    },
    agreeToTerms: {
      type: Boolean,
      required: [true, 'You must agree to the terms and conditions']
    },
    emailNotifications: {
      type: Boolean,
      default: true
    },
    smsNotifications: {
      type: Boolean,
      default: false
    },
    loginAlerts: {
      type: Boolean,
      default: true
    },
    sessionTimeout: {
      type: String,
      enum: ["15", "30", "60", "120", "never"],
      default: "30"
    },
    lastLoginAt: {
      type: Date
    },
    passwordChangedAt: {
      type: Date,
      default: Date.now
    },
    loginAttempts: {
      type: Number,
      default: 0,
      max: 5
    },
    lockUntil: {
      type: Date
    },
    resetPasswordToken: {
      type: String,
      select: false
    },
    resetPasswordExpires: {
      type: Date,
      select: false
    },
    toolsUsed: [{
      type: String
    }],
    totalScans: {
      type: Number,
      default: 0
    },
    lastActiveAt: {
      type: Date,
      default: Date.now
    }
  },
  {
    timestamps: true,
  }
)

// Hash password before saving
userSchema.pre("save", async function (next) {
  if (!this.isModified('password')) return next()
  
  try {
    const salt = await bcrypt.genSalt(12)
    this.password = await bcrypt.hash(this.password, salt)
    this.passwordChangedAt = new Date()
    next()
  } catch (error) {
    next(error as Error)
  }
})

// Update lastActiveAt on login
userSchema.pre('save', function(next) {
  if (this.isModified('lastLoginAt')) {
    this.lastActiveAt = new Date()
  }
  next()
})

// Compare password method
userSchema.methods.comparePassword = async function (candidatePassword: string): Promise<boolean> {
  try {
    return await bcrypt.compare(candidatePassword, this.password)
  } catch (error) {
    throw new Error('Password comparison failed')
  }
}

// Increment login attempts
userSchema.methods.incLoginAttempts = async function() {
  // Check if account is already locked
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return await this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    })
  }
  
  const updates: any = { $inc: { loginAttempts: 1 } }
  
  // Lock account after 5 failed attempts for 2 hours
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }
  }
  
  return await this.updateOne(updates)
}

// Reset login attempts
userSchema.methods.resetLoginAttempts = async function() {
  return await this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  })
}

// Generate verification token
userSchema.methods.generateVerificationToken = function(): string {
  const crypto = require('crypto')
  const token = crypto.randomBytes(32).toString('hex')
  this.verificationToken = crypto.createHash('sha256').update(token).digest('hex')
  return token
}

// Generate password reset token
userSchema.methods.generatePasswordResetToken = function(): string {
  const crypto = require('crypto')
  const resetToken = crypto.randomBytes(32).toString('hex')
  
  this.resetPasswordToken = crypto.createHash('sha256').update(resetToken).digest('hex')
  this.resetPasswordExpires = new Date(Date.now() + 10 * 60 * 1000) // 10 minutes
  
  return resetToken
}

// Virtual for checking if account is locked
userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil.getTime() > Date.now())
})

export default mongoose.models.User || mongoose.model<IUser>("User", userSchema)
