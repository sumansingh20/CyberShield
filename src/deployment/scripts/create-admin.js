const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

// Simple User schema for the setup script
const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], default: 'user' },
  isVerified: { type: Boolean, default: false },
  agreeToTerms: { type: Boolean, required: true },
  emailNotifications: { type: Boolean, default: true },
  smsNotifications: { type: Boolean, default: false },
  loginAlerts: { type: Boolean, default: true },
  sessionTimeout: { type: String, default: '30' },
  passwordChangedAt: { type: Date, default: Date.now },
  loginAttempts: { type: Number, default: 0 },
  toolsUsed: [{ type: String }],
  totalScans: { type: Number, default: 0 },
  lastActiveAt: { type: Date, default: Date.now }
}, {
  timestamps: true
})

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next()
  
  try {
    const salt = await bcrypt.genSalt(12)
    this.password = await bcrypt.hash(this.password, salt)
    this.passwordChangedAt = new Date()
    next()
  } catch (error) {
    next(error)
  }
})

async function createInitialAdmin() {
  try {
    // Connect to MongoDB
    const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cybershield-platform'
    
    console.log('🔗 Connecting to MongoDB...')
    await mongoose.connect(MONGODB_URI)
    console.log('✅ Connected to MongoDB')

    // Get or create User model
    const User = mongoose.models.User || mongoose.model('User', userSchema)

    // Check if admin user already exists
    const existingAdmin = await User.findOne({ role: 'admin' })
    
    if (existingAdmin) {
      console.log('✅ Admin user already exists:', existingAdmin.email)
      return
    }

    // Create default admin user
    const adminData = {
      username: 'admin',
      email: 'admin@cybershield-platform.com',
      password: 'CyberShield2025!',
      firstName: 'CyberShield',
      lastName: 'Administrator',
      role: 'admin',
      isVerified: true,
      agreeToTerms: true,
      emailNotifications: true,
      smsNotifications: false,
      loginAlerts: true,
      sessionTimeout: '60'
    }

    const adminUser = await User.create(adminData)
    
    console.log('🎉 CyberShield admin user created successfully!')
    console.log('📧 Email:', adminUser.email)
    console.log('🔑 Password: CyberShield2025!')
    console.log('⚠️  Please change the password after first login')

    // Create system settings if they don't exist
    const SystemSettings = mongoose.models.SystemSettings || mongoose.model('SystemSettings', new mongoose.Schema({
      maintenanceMode: { type: Boolean, default: false },
      registrationEnabled: { type: Boolean, default: true },
      maxUsersPerDay: { type: Number, default: 100 },
      maxToolUsagePerUser: { type: Number, default: 1000 },
      allowedTools: [{ type: String }],
      bannedDomains: [{ type: String }],
      securityLevel: { type: String, enum: ['low', 'medium', 'high'], default: 'medium' },
      sessionTimeout: { type: Number, default: 30 },
      passwordPolicy: {
        minLength: { type: Number, default: 8 },
        requireUppercase: { type: Boolean, default: true },
        requireLowercase: { type: Boolean, default: true },
        requireNumbers: { type: Boolean, default: true },
        requireSymbols: { type: Boolean, default: false }
      },
      rateLimiting: {
        enabled: { type: Boolean, default: true },
        requestsPerMinute: { type: Number, default: 60 },
        requestsPerHour: { type: Number, default: 1000 }
      }
    }, { timestamps: true }))

    const existingSettings = await SystemSettings.findOne()
    if (!existingSettings) {
      await SystemSettings.create({})
      console.log('⚙️ System settings initialized')
    }

  } catch (error) {
    console.error('❌ Error creating admin user:', error)
    process.exit(1)
  } finally {
    await mongoose.disconnect()
    console.log('🔌 Disconnected from MongoDB')
    process.exit(0)
  }
}

// Run the script
createInitialAdmin()