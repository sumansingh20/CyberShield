/**
 * Test Container Security API with proper authentication
 */

async function testContainerSecurityAPI() {
  console.log('🔒 Testing Container Security API...')
  
  try {
    // First login to get authentication
    console.log('1. Attempting login...')
    const loginResponse = await fetch('http://localhost:3001/api/auth/login', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        email: 'user@unified.com',
        password: 'user123'
      })
    })

    if (loginResponse.status !== 200) {
      console.log('❌ Login failed:', loginResponse.status)
      return
    }

    const loginData = await loginResponse.json()
    console.log('✅ Login successful')

    // Get the auth cookies from the response
    const cookies = loginResponse.headers.get('set-cookie')
    
    // Test Container Security API
    console.log('2. Testing Container Security API...')
    const response = await fetch('http://localhost:3001/api/tools/expert/container-security', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Cookie': cookies || ''
      },
      body: JSON.stringify({
        target: 'nginx:latest',
        scanType: 'docker-image'
      })
    })

    const result = await response.json()
    
    if (response.status === 200 && result.success) {
      console.log('✅ Container Security API is working!')
      console.log('   Status:', response.status)
      console.log('   Success:', result.success)
      console.log('   Execution Time:', result.result.executionTime + 'ms')
      console.log('   Output Length:', result.result.output.length, 'characters')
    } else {
      console.log('❌ Container Security API error')
      console.log('   Status:', response.status)
      console.log('   Error:', result.error || 'Unknown error')
    }
  } catch (error) {
    console.error('❌ Failed to test Container Security API:', error.message)
  }
}

// Run the test
testContainerSecurityAPI()
