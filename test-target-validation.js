/**
 * Test Target Validation Fix
 * This script tests various target formats to ensure they're accepted
 */

const testTargets = [
  // Basic formats
  'example.com',
  '192.168.1.1',
  'test-server.local',
  'my_host.domain.com',
  
  // CIDR ranges
  '192.168.1.0/24',
  '10.0.0.0/8',
  '172.16.0.0/12',
  
  // IP ranges
  '192.168.1.1-10',
  '10.0.0.1/24',
  
  // Ports
  '192.168.1.1:8080',
  'example.com:443',
  
  // URLs (for vuln scanners)
  'https://example.com',
  'http://test.local:8080',
  'https://sub.domain.com/path'
]

async function testTargetValidation() {
  console.log('🧪 Testing Target Validation Fix...\n')
  
  // Test the regex patterns we implemented
  const nmapPortRegex = /^[a-zA-Z0-9.\-_/:]+$/
  const vulnScannerRegex = /^(https?:\/\/)?[a-zA-Z0-9.\-_/:]+$/
  const urlOnlyRegex = /^https?:\/\/[a-zA-Z0-9.\-_/:]+/
  
  console.log('Testing Basic Network Tools (Nmap/Port Scanner):')
  console.log('=' .repeat(50))
  
  testTargets.forEach(target => {
    const isValid = nmapPortRegex.test(target)
    const status = isValid ? '✅' : '❌'
    console.log(`${status} ${target}`)
  })
  
  console.log('\nTesting Vulnerability Scanner (flexible):')
  console.log('=' .repeat(50))
  
  testTargets.forEach(target => {
    const isValid = vulnScannerRegex.test(target)
    const status = isValid ? '✅' : '❌'
    console.log(`${status} ${target}`)
  })
  
  console.log('\nTesting URL-only Vulnerability Scanner:')
  console.log('=' .repeat(50))
  
  testTargets.forEach(target => {
    const isValid = urlOnlyRegex.test(target)
    const status = isValid ? '✅' : '❌'
    console.log(`${status} ${target}`)
  })
  
  console.log('\n🎉 Target validation patterns updated!')
  console.log('Now supports:')
  console.log('• IP addresses and ranges (192.168.1.1, 192.168.1.0/24)')
  console.log('• Domain names with underscores and hyphens')
  console.log('• Port specifications (host:port)')
  console.log('• CIDR notation for network ranges')
  console.log('• URLs for web application testing')
}

testTargetValidation()
