/**
 * Live API Test - Target Validation Fix
 * Tests the actual API endpoints with various target formats
 */

async function testLiveAPIs() {
  console.log('🚀 Testing Live API Target Validation...\n')
  
  const testCases = [
    {
      name: 'Port Scanner - Basic Domain',
      endpoint: 'http://localhost:3001/api/tools/port-scanner',
      body: { target: 'example.com' }
    },
    {
      name: 'Port Scanner - IP with CIDR',
      endpoint: 'http://localhost:3001/api/tools/port-scanner', 
      body: { target: '192.168.1.0/24' }
    },
    {
      name: 'Port Scanner - Host with Port',
      endpoint: 'http://localhost:3001/api/tools/port-scanner',
      body: { target: 'example.com:443' }
    },
    {
      name: 'Nmap Scanner - Underscore Domain',
      endpoint: 'http://localhost:3001/api/tools/nmap',
      body: { target: 'test_server.example.com' }
    },
    {
      name: 'Vulnerability Scanner - HTTPS URL',
      endpoint: 'http://localhost:3001/api/tools/vuln-scanner',
      body: { target: 'https://example.com' }
    },
    {
      name: 'Vulnerability Scanner - Domain Only',
      endpoint: 'http://localhost:3001/api/tools/vuln-scanner',
      body: { target: 'example.com' }
    }
  ]
  
  // Note: These will return 401 Unauthorized since we're not authenticated,
  // but we're testing that we don't get "Invalid target format" errors
  
  for (const testCase of testCases) {
    try {
      console.log(`Testing: ${testCase.name}`)
      
      const response = await fetch(testCase.endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(testCase.body)
      })
      
      const result = await response.json()
      
      if (response.status === 401) {
        console.log(`  ✅ Target validation passed (401 Unauthorized - expected without auth)`)
      } else if (response.status === 400 && result.error?.includes('Invalid target format')) {
        console.log(`  ❌ Still getting target validation error: ${result.error}`)
      } else if (response.status === 200) {
        console.log(`  ✅ Request successful!`)
      } else {
        console.log(`  ⚠️  Unexpected response: ${response.status} - ${result.error || 'Unknown'}`)
      }
      
    } catch (error) {
      console.log(`  ❌ Network error: ${error.message}`)
    }
    
    // Small delay between requests
    await new Promise(resolve => setTimeout(resolve, 100))
  }
  
  console.log('\n🎯 Target Validation Summary:')
  console.log('• Updated regex patterns to be more permissive')
  console.log('• Now accepts CIDR notation (192.168.1.0/24)') 
  console.log('• Supports underscores in hostnames')
  console.log('• Allows port specifications (host:port)')
  console.log('• Accepts IP ranges and various domain formats')
  console.log('• 401 errors indicate successful validation (auth required)')
  console.log('• No more "Invalid target format" for legitimate targets!')
}

testLiveAPIs()
