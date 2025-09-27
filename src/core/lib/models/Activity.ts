import mongoose from "mongoose"

export interface IActivity extends mongoose.Document {
  userId: mongoose.Types.ObjectId
  toolName: string
  action: string
  target?: string
  status: "success" | "error" | "warning" | "info"
  duration: number
  ipAddress: string
  userAgent: string
  results?: any
  errorMessage?: string
  createdAt: Date
  updatedAt: Date
}

const activitySchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: 'User',
      required: [true, 'User ID is required'],
      index: true
    },
    toolName: {
      type: String,
      required: [true, 'Tool name is required'],
      enum: [
        // Authentication activities
        'register', 'login', 'logout', 'verify-otp', 'forgot-password', 'reset-password',
        // Security tools
        'nmap', 'subdomain-enum', 'vuln-scan', 'whois', 'dns-lookup',
        'http-headers', 'port-scan', 'directory-buster', 'osint',
        'wireless-scan', 'social-engineering', 'mobile-security',
        'forensics', 'cryptography', 'masscan', 'metasploit',
        'burp-suite', 'binary-analysis', 'network-analysis',
        'cloud-security'
      ]
    },
    action: {
      type: String,
      required: [true, 'Action is required'],
      maxlength: [100, 'Action cannot exceed 100 characters']
    },
    target: {
      type: String,
      trim: true,
      maxlength: [255, 'Target cannot exceed 255 characters']
    },
    status: {
      type: String,
      enum: ["success", "error", "warning", "info"],
      required: [true, 'Status is required'],
      index: true
    },
    duration: {
      type: Number,
      required: [true, 'Duration is required'],
      min: [0, 'Duration cannot be negative']
    },
    ipAddress: {
      type: String,
      required: [true, 'IP address is required'],
      validate: {
        validator: function(v: string) {
          // Allow IPv4, IPv6, localhost, and common local addresses
          const ipv4 = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
          const ipv6 = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/
          const localhost = /^(localhost|127\.0\.0\.1|::1)$/
          return ipv4.test(v) || ipv6.test(v) || localhost.test(v) || v === '::ffff:127.0.0.1'
        },
        message: 'Invalid IP address format'
      }
    },
    userAgent: {
      type: String,
      required: [true, 'User agent is required'],
      maxlength: [500, 'User agent cannot exceed 500 characters']
    },
    results: {
      type: mongoose.Schema.Types.Mixed,
      default: null
    },
    errorMessage: {
      type: String,
      maxlength: [1000, 'Error message cannot exceed 1000 characters']
    }
  },
  {
    timestamps: true,
  }
)

// Indexes for better query performance
activitySchema.index({ userId: 1, createdAt: -1 })
activitySchema.index({ toolName: 1, status: 1 })
activitySchema.index({ createdAt: -1 })

// Static methods
activitySchema.statics.getRecentActivity = function(userId: string, limit: number = 10) {
  return this.find({ userId })
    .populate('userId', 'username email firstName lastName')
    .sort({ createdAt: -1 })
    .limit(limit)
}

activitySchema.statics.getToolUsageStats = function(userId?: string, days: number = 30) {
  const matchStage: any = {
    createdAt: { $gte: new Date(Date.now() - days * 24 * 60 * 60 * 1000) }
  }
  
  if (userId) {
    matchStage.userId = new mongoose.Types.ObjectId(userId)
  }
  
  return this.aggregate([
    { $match: matchStage },
    { 
      $group: {
        _id: '$toolName',
        count: { $sum: 1 },
        successCount: {
          $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
        },
        errorCount: {
          $sum: { $cond: [{ $eq: ['$status', 'error'] }, 1, 0] }
        },
        avgDuration: { $avg: '$duration' }
      }
    },
    { $sort: { count: -1 } }
  ])
}

// Delete the existing model if it exists to prevent caching issues
if (mongoose.models.Activity) {
  delete mongoose.models.Activity
}

export default mongoose.model<IActivity>("Activity", activitySchema)
