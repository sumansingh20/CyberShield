// Simple script to create a test admin user for authentication testing
const mongoose = require('mongoose')
const bcrypt = require('bcryptjs')

// Connect to MongoDB
const MONGODB_URI = 'mongodb://localhost:27017/cybersec-platform'

const userSchema = new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  role: { type: String, enum: ['admin', 'user'], default: 'user' },
  isVerified: { type: Boolean, default: true },
  agreeToTerms: { type: Boolean, default: true },
  emailNotifications: { type: Boolean, default: true },
  smsNotifications: { type: Boolean, default: false },
  loginAlerts: { type: Boolean, default: true },
  sessionTimeout: { type: String, default: '30' }
}, { timestamps: true })

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next()
  this.password = await bcrypt.hash(this.password, 12)
  next()
})

const User = mongoose.models.User || mongoose.model('User', userSchema)

async function createTestUser() {
  try {
    console.log('🔗 Connecting to MongoDB...')
    await mongoose.connect(MONGODB_URI)
    console.log('✅ Connected to MongoDB')

    // Check if admin user already exists
    const existingAdmin = await User.findOne({ email: 'admin@cybershield.com' })
    if (existingAdmin) {
      console.log('👤 Test admin user already exists!')
      console.log('📧 Email: admin@cybershield.com')
      console.log('🔑 Password: admin123')
      console.log('🌐 Login at: http://localhost:3001/login')
      return
    }

    // Create test admin user
    const testAdmin = await User.create({
      username: 'admin',
      email: 'admin@cybershield.com',
      password: 'admin123',
      firstName: 'Admin',
      lastName: 'User',
      role: 'admin',
      isVerified: true
    })

    console.log('🎉 Test admin user created successfully!')
    console.log('📧 Email: admin@cybershield.com')
    console.log('🔑 Password: admin123')
    console.log('👑 Role: admin')
    console.log('🌐 Login at: http://localhost:3001/login')
    
    // Also create a regular test user
    const existingUser = await User.findOne({ email: 'test@cybershield.com' })
    if (!existingUser) {
      await User.create({
        username: 'testuser',
        email: 'test@cybershield.com',
        password: 'test123',
        firstName: 'Test',
        lastName: 'User',
        role: 'user',
        isVerified: true
      })
      
      console.log('👤 Test regular user also created!')
      console.log('📧 Email: test@cybershield.com')
      console.log('🔑 Password: test123')
      console.log('👤 Role: user')
    }

  } catch (error) {
    console.error('❌ Error creating test user:', error.message)
    if (error.code === 11000) {
      console.log('💡 User might already exist. Try logging in with existing credentials.')
    }
  } finally {
    await mongoose.disconnect()
    console.log('🔌 Disconnected from MongoDB')
  }
}

createTestUser()