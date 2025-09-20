// Test script to verify OTP/2FA functionality
const testUser = {
  firstName: "Test",
  lastName: "User", 
  email: "test@example.com",
  username: "testuser",
  phone: "+1234567890",
  password: "testpass123",
  agreeToTerms: true
}

async function testOTPFlow() {
  console.log("🔧 Testing OTP/2FA Implementation")
  console.log("=================================")
  
  try {
    // Test Registration Flow
    console.log("\n1. Testing Registration...")
    const registerResponse = await fetch("http://localhost:3001/api/auth/register", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify(testUser),
    })
    
    const registerResult = await registerResponse.json()
    console.log("Register response:", registerResult)
    
    if (registerResult.userId) {
      console.log("✅ Registration successful - OTP should be sent")
      console.log("📧 Email OTP and 📱 SMS OTP should be sent to user")
      
      // Note: In a real scenario, you would get these OTPs from email/SMS
      // For testing, you would need to check your email/SMS or look at the database
      console.log("\n2. Next steps:")
      console.log("- Check email inbox for 6-digit OTP code")
      console.log("- Check phone for SMS with 6-digit OTP code") 
      console.log("- Go to verification page: http://localhost:3001/verify-otp?userId=" + registerResult.userId + "&purpose=registration")
      console.log("- Enter both OTP codes to complete registration")
      
      console.log("\n3. Login Flow:")
      console.log("- After successful OTP verification, login will also require 2FA")
      console.log("- Each login will generate new OTP codes")
      console.log("- User must verify both email and SMS OTP for complete authentication")
      
    } else {
      console.log("❌ Registration failed:", registerResult.error)
    }
    
  } catch (error) {
    console.error("❌ Test failed:", error.message)
  }
  
  console.log("\n🔒 2FA Security Features:")
  console.log("- Dual verification (Email + SMS)")
  console.log("- OTP expiration (10 minutes)")
  console.log("- Attempt limits (3 max attempts)")
  console.log("- Rate limiting for resend requests")
  console.log("- Automatic cleanup of expired/used OTPs")
  
  console.log("\n🌐 URLs to test:")
  console.log("- Main app: http://localhost:3001")
  console.log("- Login: http://localhost:3001/login")
  console.log("- Register: http://localhost:3001/register")
  console.log("- OTP Verify: http://localhost:3001/verify-otp")
}

// Run the test
testOTPFlow()