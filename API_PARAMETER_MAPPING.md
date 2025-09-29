# CyberShield API Parameter Mapping

This document maps the correct parameter names for each tool API to ensure frontend-backend compatibility.

## 🔧 Network & Security Tools

### Port Scanner (`/api/tools/port-scanner`)
**Correct Parameters:**
```json
{
  "target": "google.com",          // Not "host"
  "ports": "80,443,22",           // Not "portRange"
  "scanType": "tcp",              // Optional
  "timeout": 3000                 // Optional
}
```

### Network Scanner (`/api/tools/network-scanner`)
**Correct Parameters:**
```json
{
  "target": "192.168.1.0/24",     // IP, hostname, or CIDR
  "scanType": "discovery",         // "discovery", "comprehensive"
  "portRange": "80,443"           // Optional
}
```

### NMAP (`/api/tools/nmap`)
**Correct Parameters:**
```json
{
  "target": "google.com",         // IP, hostname, or CIDR
  "scanType": "tcp",              // "tcp", "syn", "comprehensive"
  "options": {                    // Optional
    "portRange": "1-1000"
  }
}
```

### Vulnerability Scanner (`/api/tools/vuln-scanner`)
**Correct Parameters:**
```json
{
  "target": "google.com",         // Target hostname/IP
  "scanType": "comprehensive",     // Scan depth
  "options": {}                   // Optional settings
}
```

### Ping Sweep (`/api/tools/ping-sweep`)
**Correct Parameters:**
```json
{
  "network": "192.168.1.0/24",   // Network CIDR
  "timeout": 2000,               // Optional ping timeout
  "concurrent": 50               // Optional thread count
}
```

### Subdomain Enumeration (`/api/tools/subdomain-enum`)
**Correct Parameters:**
```json
{
  "domain": "example.com",        // Target domain
  "method": "comprehensive",      // "basic", "comprehensive", "passive"
  "wordlist": "common"           // Optional wordlist type
}
```

### Wireless Scanner (`/api/tools/wireless-scanner`)
**Correct Parameters:**
```json
{
  "networkInterface": "wlan0",    // Network interface name
  "scanType": "discovery"         // "discovery", "passive", "active"
}
```

## 🌐 Web Security Tools

### XSS Scanner (`/api/tools/xss-scanner`)
**Correct Parameters:**
```json
{
  "url": "http://example.com",    // Not "targetUrl"
  "testType": "reflected",        // "reflected", "stored", "dom", "blind", "comprehensive"
  "inputFields": "name,email",    // Optional field targeting
  "customPayload": "<script>..."  // Optional custom payload
}
```

### SQL Injection Scanner (`/api/tools/sql-injection`)
**Correct Parameters:**
```json
{
  "url": "http://example.com",    // Target URL
  "method": "GET",                // HTTP method
  "parameters": "id,name",        // Parameters to test
  "testType": "comprehensive"     // Test depth
}
```

### Directory Brute Force (`/api/tools/directory-bruteforce`)
**Correct Parameters:**
```json
{
  "targetUrl": "http://example.com", // Target URL
  "wordlistType": "common",          // "common", "comprehensive", "admin"
  "extensions": "php,html,txt",      // Optional file extensions
  "threads": 10                      // Optional thread count
}
```

### HTTP Headers Analyzer (`/api/tools/http-headers`)
**Correct Parameters:**
```json
{
  "url": "https://example.com",   // Target URL
  "followRedirects": true         // Optional redirect following
}
```

### WAF Bypass (`/api/tools/waf-bypass`)
**Correct Parameters:**
```json
{
  "url": "http://example.com",    // Target URL
  "payload": "' OR 1=1 --",      // Payload to test
  "technique": "encoding"         // Bypass technique
}
```

## 🔍 Information Gathering

### DNS Lookup (`/api/tools/dns-lookup`)
**Correct Parameters:**
```json
{
  "domain": "example.com",        // Domain to lookup
  "recordType": "A"              // "A", "AAAA", "MX", "NS", "TXT", "CNAME"
}
```

### WHOIS Lookup (`/api/tools/whois`)
**Correct Parameters:**
```json
{
  "domain": "example.com"        // Domain for WHOIS query
}
```

## 🤖 AI Security Tools

### AI Phishing Detector (`/api/tools/ai-phishing-detector`)
**Correct Parameters:**
```json
{
  "url": "http://suspicious-site.com",  // URL to analyze
  "analysisType": "comprehensive"       // Analysis depth
}
```

### AI Threat Intelligence (`/api/tools/ai-threat-intelligence`)
**Correct Parameters:**
```json
{
  "indicator": "malicious-domain.com",  // IoC to analyze
  "indicatorType": "domain",            // "domain", "ip", "hash", "url"
  "analysisDepth": "detailed"          // Analysis level
}
```

### AI Intrusion Detector (`/api/tools/ai-intrusion-detector`)
**Correct Parameters:**
```json
{
  "logData": "log entries...",     // Log data to analyze
  "analysisType": "behavioral",    // Analysis type
  "timeRange": "24h"              // Time window
}
```

### AI Security Assistant (`/api/tools/ai-security-assistant`)
**Correct Parameters:**
```json
{
  "query": "How to secure Apache?",  // Security question
  "context": "web-server",           // Context category
  "detailLevel": "comprehensive"     // Response detail level
}
```

## 🛡️ Advanced Tools

### Password Cracking (`/api/tools/password-cracking`)
**Correct Parameters:**
```json
{
  "hash": "$2a$10$...",           // Hash to crack
  "hashType": "bcrypt",           // Hash algorithm
  "wordlist": "rockyou",          // Wordlist selection
  "rules": "best64"               // Optional rules
}
```

### Payload Generator (`/api/tools/payload-generator`)
**Correct Parameters:**
```json
{
  "payloadType": "reverse-shell", // Payload type
  "target": "windows",            // Target OS/platform
  "lhost": "192.168.1.100",      // Listener host
  "lport": "4444"                // Listener port
}
```

### Social Engineering (`/api/tools/social-engineering`)
**Correct Parameters:**
```json
{
  "target": "company.com",        // Target organization
  "campaignType": "phishing",     // Campaign type
  "template": "generic"           // Template selection
}
```

### Exploit Database (`/api/tools/exploit-database`)
**Correct Parameters:**
```json
{
  "searchQuery": "Apache 2.4",   // Search terms
  "searchType": "software",       // Search category
  "platform": "linux",           // Target platform
  "exploitType": "remote",        // Exploit type
  "verifiedOnly": true            // Filter verified exploits
}
```

## 📝 Common Issues & Solutions

### ❌ Common Mistakes:
1. Using `host` instead of `target` for network tools
2. Using `portRange` instead of `ports` for port scanner  
3. Using `targetUrl` instead of `url` for web tools
4. Missing required parameters (returns 400 Bad Request)

### ✅ Best Practices:
1. Always include required parameters as documented above
2. Use correct parameter names exactly as specified
3. Provide reasonable timeout values for network operations
4. Handle both success and error responses in frontend code

### 🔧 Testing Commands:
```bash
# Test Port Scanner
curl -X POST http://localhost:3000/api/tools/port-scanner \
  -H "Content-Type: application/json" \
  -d '{"target":"google.com","ports":"80,443"}'

# Test XSS Scanner  
curl -X POST http://localhost:3000/api/tools/xss-scanner \
  -H "Content-Type: application/json" \
  -d '{"url":"http://testphp.vulnweb.com/","testType":"reflected"}'
```

## 📊 Serverless Compatibility Status

### ✅ Fully Compatible (All Environments):
- DNS Lookup, WHOIS, HTTP Headers
- XSS Scanner, SQL Injection, Directory Brute Force
- All AI Security Tools, Exploit Database
- Password Cracking, Payload Generator

### 🔄 Serverless Fallback Available:
- Port Scanner (HTTP-based detection)
- Network Scanner (HTTP availability checks)
- Vulnerability Scanner (web-based scanning)
- NMAP (HTTP-based inference)
- Ping Sweep (HTTP connectivity tests)
- Subdomain Enumeration (DNS-over-HTTPS)

### ⚠️ Local/VPS Only:
- Wireless Scanner (requires system interface access)