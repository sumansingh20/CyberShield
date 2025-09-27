#!/usr/bin/env node

/**
 * CyberShield Deployment Verification Script
 * Checks if the platform is properly deployed and configured
 */

const https = require('https');
const http = require('http');

async function checkEndpoint(url, expectedStatus = 200) {
  return new Promise((resolve) => {
    const protocol = url.startsWith('https') ? https : http;
    
    protocol.get(url, (res) => {
      console.log(`✓ ${url} → Status: ${res.statusCode}`);
      resolve(res.statusCode === expectedStatus);
    }).on('error', (err) => {
      console.log(`✗ ${url} → Error: ${err.message}`);
      resolve(false);
    });
  });
}

async function verifyDeployment() {
  const baseUrl = process.env.NEXT_PUBLIC_APP_URL || 'http://localhost:3000';
  
  console.log('🔍 CyberShield Deployment Verification\n');
  console.log(`🌐 Base URL: ${baseUrl}\n`);
  
  // Test endpoints
  const endpoints = [
    { path: '/', name: 'Homepage' },
    { path: '/register', name: 'Registration Page' },
    { path: '/login', name: 'Login Page' },
    { path: '/api/health', name: 'Health Check API' },
    { path: '/api/auth/login', name: 'Auth API', method: 'POST', status: 405 }
  ];
  
  let passed = 0;
  let total = endpoints.length;
  
  for (const endpoint of endpoints) {
    const url = `${baseUrl}${endpoint.path}`;
    const expectedStatus = endpoint.status || 200;
    
    console.log(`Testing ${endpoint.name}...`);
    const success = await checkEndpoint(url, expectedStatus);
    
    if (success) {
      passed++;
      console.log(`✅ ${endpoint.name} - PASSED\n`);
    } else {
      console.log(`❌ ${endpoint.name} - FAILED\n`);
    }
  }
  
  console.log(`\n📊 Results: ${passed}/${total} tests passed`);
  
  if (passed === total) {
    console.log('🎉 All tests passed! Your CyberShield platform is working correctly.');
    
    console.log('\n🚀 Next Steps:');
    console.log(`1. Visit: ${baseUrl}`);
    console.log('2. Register a new account');
    console.log('3. Login and try the security tools');
    console.log(`4. Admin login: admin@cybershield-platform.com / CyberShield2025!`);
    console.log(`5. Admin panel: ${baseUrl}/admin`);
    
  } else {
    console.log('⚠️  Some tests failed. Check your deployment configuration.');
  }
  
  // Environment check
  console.log('\n🔧 Environment Variables Check:');
  const requiredEnvs = [
    'MONGODB_URI',
    'JWT_SECRET', 
    'NEXT_PUBLIC_APP_URL'
  ];
  
  requiredEnvs.forEach(env => {
    const exists = process.env[env] ? '✅' : '❌';
    console.log(`${exists} ${env}`);
  });
}

// Run verification
verifyDeployment().catch(console.error);