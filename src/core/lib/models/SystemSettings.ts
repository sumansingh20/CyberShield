import mongoose from "mongoose"

export interface ISystemSettings extends mongoose.Document {
  maintenanceMode: boolean
  registrationEnabled: boolean
  maxUsersPerDay: number
  maxToolUsagePerUser: number
  allowedTools: string[]
  bannedDomains: string[]
  securityLevel: "low" | "medium" | "high"
  sessionTimeout: number
  passwordPolicy: {
    minLength: number
    requireUppercase: boolean
    requireLowercase: boolean
    requireNumbers: boolean
    requireSymbols: boolean
  }
  rateLimiting: {
    enabled: boolean
    requestsPerMinute: number
    requestsPerHour: number
  }
  emailSettings: {
    enabled: boolean
    smtpHost: string
    smtpPort: number
    smtpUser: string
    smtpFrom: string
  }
  backupSettings: {
    enabled: boolean
    frequency: "daily" | "weekly" | "monthly"
    retention: number
  }
  createdAt: Date
  updatedAt: Date
}

export interface ISystemSettingsModel extends mongoose.Model<ISystemSettings> {
  getInstance(): Promise<ISystemSettings>
}

const systemSettingsSchema = new mongoose.Schema(
  {
    maintenanceMode: {
      type: Boolean,
      default: false
    },
    registrationEnabled: {
      type: Boolean,
      default: true
    },
    maxUsersPerDay: {
      type: Number,
      default: 100,
      min: [1, 'Max users per day must be at least 1']
    },
    maxToolUsagePerUser: {
      type: Number,
      default: 1000,
      min: [1, 'Max tool usage must be at least 1']
    },
    allowedTools: [{
      type: String,
      enum: [
        'nmap', 'subdomain-enum', 'vuln-scan', 'whois', 'dns-lookup',
        'http-headers', 'port-scan', 'directory-buster', 'osint',
        'wireless-scan', 'social-engineering', 'mobile-security',
        'forensics', 'cryptography', 'masscan', 'metasploit',
        'burp-suite', 'binary-analysis', 'network-analysis',
        'cloud-security'
      ]
    }],
    bannedDomains: [{
      type: String
    }],
    securityLevel: {
      type: String,
      enum: ["low", "medium", "high"],
      default: "medium"
    },
    sessionTimeout: {
      type: Number,
      default: 30,
      min: [5, 'Session timeout must be at least 5 minutes']
    },
    passwordPolicy: {
      minLength: {
        type: Number,
        default: 8,
        min: [6, 'Password minimum length must be at least 6']
      },
      requireUppercase: {
        type: Boolean,
        default: true
      },
      requireLowercase: {
        type: Boolean,
        default: true
      },
      requireNumbers: {
        type: Boolean,
        default: true
      },
      requireSymbols: {
        type: Boolean,
        default: false
      }
    },
    rateLimiting: {
      enabled: {
        type: Boolean,
        default: true
      },
      requestsPerMinute: {
        type: Number,
        default: 60,
        min: [1, 'Requests per minute must be at least 1']
      },
      requestsPerHour: {
        type: Number,
        default: 1000,
        min: [1, 'Requests per hour must be at least 1']
      }
    },
    emailSettings: {
      enabled: {
        type: Boolean,
        default: false
      },
      smtpHost: {
        type: String,
        default: ''
      },
      smtpPort: {
        type: Number,
        default: 587
      },
      smtpUser: {
        type: String,
        default: ''
      },
      smtpFrom: {
        type: String,
        default: ''
      }
    },
    backupSettings: {
      enabled: {
        type: Boolean,
        default: false
      },
      frequency: {
        type: String,
        enum: ["daily", "weekly", "monthly"],
        default: "weekly"
      },
      retention: {
        type: Number,
        default: 30,
        min: [1, 'Backup retention must be at least 1 day']
      }
    }
  },
  {
    timestamps: true,
  }
)

// Singleton pattern - only one settings document should exist
systemSettingsSchema.statics.getInstance = async function() {
  let settings = await this.findOne()
  if (!settings) {
    settings = await this.create({})
  }
  return settings
}

export default (mongoose.models.SystemSettings as ISystemSettingsModel) || mongoose.model<ISystemSettings, ISystemSettingsModel>("SystemSettings", systemSettingsSchema)
