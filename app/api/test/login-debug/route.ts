import { NextRequest, NextResponse } from 'next/server'
import connectDB from '@/src/core/lib/mongodb'
import User from '@/src/core/lib/models/User'

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    console.log('🔍 Login debug request:', body)

    // Test database connection
    await connectDB()
    console.log('✅ Database connected successfully')

    // Test basic user lookup (without password)
    const user = await User.findOne({ email: body.email })
    console.log('🔍 User lookup result:', user ? 'User found' : 'User not found')

    if (!user) {
      // In development, try to create a test user
      if (process.env.NODE_ENV === 'development' && 
          (body.email === 'suman@cybershield.com' || body.email === 'suman@iitp.ac.in')) {
        console.log('🔧 Creating test user for development...')
        
        try {
          const testUser = new User({
            username: body.email === 'suman@iitp.ac.in' ? 'suman_iitp' : 'suman',
            email: body.email,
            password: 'suman01@', // This will be hashed by the pre-save hook
            firstName: 'Suman',
            lastName: 'Singh',
            role: 'admin',
            isVerified: true,
            agreeToTerms: true,
            emailNotifications: true,
            smsNotifications: false,
            loginAlerts: true,
            sessionTimeout: '30'
          })
          
          await testUser.save()
          console.log('✅ Test user created successfully')
          
          return NextResponse.json({
            success: true,
            message: 'Test user created successfully',
            debug: {
              databaseConnected: true,
              userCreated: true,
              email: body.email
            }
          })
          
        } catch (createError) {
          console.error('❌ Test user creation failed:', createError)
          return NextResponse.json({
            success: false,
            message: 'Test user creation failed',
            error: createError instanceof Error ? createError.message : 'Unknown error',
            debug: {
              databaseConnected: true,
              userCreated: false,
              createError: createError instanceof Error ? createError.message : 'Unknown error'
            }
          })
        }
      }
      
      return NextResponse.json({
        success: false,
        message: 'User not found',
        debug: {
          databaseConnected: true,
          userFound: false,
          email: body.email
        }
      })
    }

    // Test password comparison
    const userWithPassword = await User.findOne({ email: body.email }).select('+password')
    const isPasswordValid = await userWithPassword?.comparePassword(body.password || 'test')
    
    return NextResponse.json({
      success: true,
      message: 'Debug information',
      debug: {
        databaseConnected: true,
        userFound: true,
        userVerified: user.isVerified,
        userLocked: user.isLocked,
        passwordValid: isPasswordValid,
        email: body.email,
        role: user.role
      }
    })

  } catch (error) {
    console.error('🚫 Login debug error:', error)
    return NextResponse.json({
      success: false,
      message: 'Debug test failed',
      error: error instanceof Error ? error.message : 'Unknown error',
      debug: {
        databaseConnected: false,
        errorType: error instanceof Error ? error.constructor.name : 'Unknown',
        errorMessage: error instanceof Error ? error.message : 'Unknown error'
      }
    }, { status: 500 })
  }
}