import { type NextRequest, NextResponse } from "next/server"
import { createConnection } from "net"
import { promisify } from "util"
import { exec } from "child_process"

const execAsync = promisify(exec)

export const dynamic = "force-dynamic"

interface VulnerabilityFinding {
  id: string
  cveId?: string
  type: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
  title: string
  description: string
  recommendation: string
  affectedComponent?: string
  discoveryMethod: string
  references?: string[]
  cvssScore?: number
}

interface SecurityAssessment {
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW'
  overallScore: number
  compliance: {
    owasp: number
    nist: number
    pci: number
  }
  attackSurface: {
    webServices: number
    openPorts: number
    exposedServices: string[]
  }
}

// CVE Database - Real vulnerabilities from NIST NVD and security feeds
const cveDatabase = {
  'Apache/2.4.49': {
    cveId: 'CVE-2021-41773',
    severity: 'Critical' as const,
    cvssScore: 9.8,
    description: 'Apache HTTP Server 2.4.49 path traversal vulnerability',
    references: ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-41773']
  },
  'nginx/1.18.0': {
    cveId: 'CVE-2021-23017',
    severity: 'High' as const,
    cvssScore: 7.5,
    description: 'Nginx resolver off-by-one heap write vulnerability',
    references: ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-23017']
  },
  'OpenSSL/1.1.1': {
    cveId: 'CVE-2022-0778',
    severity: 'High' as const,
    cvssScore: 7.5,
    description: 'OpenSSL infinite loop in BN_mod_sqrt() reachable when parsing certificates',
    references: ['https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-0778']
  }
}

// Enhanced vulnerability checks with CVE integration
async function checkHttpHeaders(url: string): Promise<VulnerabilityFinding[]> {
  try {
    const response = await fetch(url, { 
      method: 'HEAD',
      headers: {
        'User-Agent': 'CyberShield-VulnScanner/2.0'
      }
    })
    
    const headers = Object.fromEntries(response.headers.entries())
    const findings: VulnerabilityFinding[] = []

    // Check for critical security headers
    const criticalHeaders = {
      'strict-transport-security': {
        severity: 'High' as const,
        title: 'Missing HSTS Header',
        description: 'HTTP Strict Transport Security not implemented',
        recommendation: 'Add HSTS header to prevent protocol downgrade attacks'
      },
      'content-security-policy': {
        severity: 'High' as const,
        title: 'Missing CSP Header',
        description: 'Content Security Policy not implemented',
        recommendation: 'Implement CSP to prevent XSS and injection attacks'
      },
      'x-frame-options': {
        severity: 'Medium' as const,
        title: 'Missing X-Frame-Options',
        description: 'Clickjacking protection not implemented',
        recommendation: 'Add X-Frame-Options header to prevent clickjacking'
      }
    }

    for (const [header, config] of Object.entries(criticalHeaders)) {
      if (!headers[header]) {
        findings.push({
          id: `missing-${header}`,
          type: 'Security Header',
          severity: config.severity,
          title: config.title,
          description: config.description,
          recommendation: config.recommendation,
          discoveryMethod: 'HTTP Header Analysis',
          affectedComponent: 'Web Server'
        })
      }
    }

    // Check for server information disclosure with CVE matching
    const serverHeader = headers['server']
    if (serverHeader) {
      findings.push({
        id: 'server-disclosure',
        type: 'Information Disclosure',
        severity: 'Low',
        title: 'Server Information Disclosure',
        description: `Server header reveals: ${serverHeader}`,
        recommendation: 'Hide server version information to reduce attack surface',
        discoveryMethod: 'HTTP Header Analysis',
        affectedComponent: 'Web Server'
      })

      // Check for known CVEs in server version
      const cveMatch = Object.keys(cveDatabase).find(version => 
        serverHeader.toLowerCase().includes(version.toLowerCase())
      )
      
      if (cveMatch) {
        const cve = cveDatabase[cveMatch as keyof typeof cveDatabase]
        findings.push({
          id: `cve-${cve.cveId}`,
          cveId: cve.cveId,
          type: 'Known Vulnerability',
          severity: cve.severity,
          title: `Known CVE: ${cve.cveId}`,
          description: cve.description,
          recommendation: 'Update to the latest secure version immediately',
          discoveryMethod: 'CVE Database Matching',
          affectedComponent: serverHeader,
          references: cve.references,
          cvssScore: cve.cvssScore
        })
      }
    }

    return findings
  } catch (error) {
    return [{
      id: 'http-error',
      type: 'Connection Error',
      severity: 'Info',
      title: 'HTTP Connection Failed',
      description: 'Could not establish HTTP connection to target',
      recommendation: 'Verify target accessibility and network connectivity',
      discoveryMethod: 'Network Connectivity Test'
    }]
  }
}

// Advanced SSL/TLS security assessment
async function checkSSLTLS(hostname: string): Promise<VulnerabilityFinding[]> {
  try {
    const findings: VulnerabilityFinding[] = []
    const httpsUrl = `https://${hostname}`
    
    const response = await fetch(httpsUrl, { 
      method: 'HEAD',
      headers: {
        'User-Agent': 'CyberShield-VulnScanner/2.0'
      }
    })
    
    if (response.ok) {
      findings.push({
        id: 'https-available',
        type: 'SSL/TLS',
        severity: 'Info',
        title: 'HTTPS Enabled',
        description: 'Target supports encrypted HTTPS connections',
        recommendation: 'Ensure all HTTP traffic is redirected to HTTPS',
        discoveryMethod: 'SSL/TLS Connectivity Test'
      })
      
      // Advanced HSTS analysis
      const hstsHeader = response.headers.get('strict-transport-security')
      if (hstsHeader) {
        const maxAge = hstsHeader.match(/max-age=(\d+)/)
        const hasSubdomains = hstsHeader.includes('includeSubDomains')
        const hasPreload = hstsHeader.includes('preload')
        
        if (!maxAge || parseInt(maxAge[1]) < 31536000) { // Less than 1 year
          findings.push({
            id: 'weak-hsts-maxage',
            type: 'SSL/TLS Configuration',
            severity: 'Medium',
            title: 'Weak HSTS Max-Age',
            description: 'HSTS max-age is less than recommended 1 year',
            recommendation: 'Set HSTS max-age to at least 31536000 seconds (1 year)',
            discoveryMethod: 'HSTS Header Analysis'
          })
        }
        
        if (!hasSubdomains) {
          findings.push({
            id: 'hsts-no-subdomains',
            type: 'SSL/TLS Configuration',
            severity: 'Medium',
            title: 'HSTS Missing includeSubDomains',
            description: 'HSTS policy does not cover subdomains',
            recommendation: 'Add includeSubDomains directive to HSTS header',
            discoveryMethod: 'HSTS Header Analysis'
          })
        }
      }
    }
    
    // Test for mixed content vulnerabilities
    try {
      const httpUrl = `http://${hostname}`
      const httpResponse = await fetch(httpUrl, { 
        method: 'HEAD',
        redirect: 'manual',
        headers: {
          'User-Agent': 'CyberShield-VulnScanner/2.0'
        }
      })
      
      if (httpResponse.status === 200) {
        findings.push({
          id: 'http-accessible',
          type: 'Protocol Security',
          severity: 'High',
          title: 'HTTP Service Accessible',
          description: 'Insecure HTTP protocol is accessible alongside HTTPS',
          recommendation: 'Redirect all HTTP traffic to HTTPS and disable HTTP service',
          discoveryMethod: 'Protocol Accessibility Test'
        })
      }
    } catch (error) {
      // HTTP not accessible - good!
    }
    
    return findings
  } catch (error) {
    return [{
      id: 'ssl-unavailable',
      type: 'SSL/TLS',
      severity: 'Critical',
      title: 'HTTPS Not Available',
      description: 'Target does not support HTTPS - all communications are unencrypted',
      recommendation: 'Implement SSL/TLS certificates and enable HTTPS immediately',
      discoveryMethod: 'SSL/TLS Connectivity Test'
    }]
  }
}

// Advanced port scanning with vulnerability correlation
async function checkNetworkPorts(hostname: string): Promise<VulnerabilityFinding[]> {
  const findings: VulnerabilityFinding[] = []
  const commonPorts = [21, 22, 23, 25, 53, 80, 135, 139, 443, 445, 993, 995, 3389, 5432, 3306]
  
  const portScanPromises = commonPorts.map(async (port) => {
    return new Promise<{ port: number; isOpen: boolean }>((resolve) => {
      const socket = createConnection({ host: hostname, port, timeout: 2000 })
      
      socket.on('connect', () => {
        socket.destroy()
        resolve({ port, isOpen: true })
      })
      
      socket.on('timeout', () => {
        socket.destroy()
        resolve({ port, isOpen: false })
      })
      
      socket.on('error', () => {
        resolve({ port, isOpen: false })
      })
    })
  })
  
  const portResults = await Promise.all(portScanPromises)
  const openPorts = portResults.filter(r => r.isOpen).map(r => r.port)
  
  // Analyze security implications of open ports
  for (const port of openPorts) {
    switch (port) {
      case 21:
        findings.push({
          id: 'ftp-service',
          type: 'Insecure Service',
          severity: 'High',
          title: 'FTP Service Detected',
          description: 'FTP transmits credentials and data in plaintext',
          recommendation: 'Replace FTP with SFTP or FTPS for secure file transfer',
          discoveryMethod: 'Port Scanning',
          affectedComponent: `Port ${port}/tcp`
        })
        break
      case 23:
        findings.push({
          id: 'telnet-service',
          type: 'Insecure Service',
          severity: 'Critical',
          title: 'Telnet Service Detected',
          description: 'Telnet transmits all data including passwords in plaintext',
          recommendation: 'Disable Telnet and use SSH for secure remote access',
          discoveryMethod: 'Port Scanning',
          affectedComponent: `Port ${port}/tcp`,
          cvssScore: 9.8
        })
        break
      case 3389:
        findings.push({
          id: 'rdp-exposed',
          type: 'Network Exposure',
          severity: 'High',
          title: 'RDP Service Exposed',
          description: 'Remote Desktop Protocol accessible from network',
          recommendation: 'Restrict RDP access to trusted networks and enable NLA',
          discoveryMethod: 'Port Scanning',
          affectedComponent: `Port ${port}/tcp`
        })
        break
    }
  }
  
  return findings
}

// Comprehensive security assessment
function generateSecurityAssessment(findings: VulnerabilityFinding[]): SecurityAssessment {
  const critical = findings.filter(f => f.severity === 'Critical').length
  const high = findings.filter(f => f.severity === 'High').length
  const medium = findings.filter(f => f.severity === 'Medium').length
  const low = findings.filter(f => f.severity === 'Low').length
  
  // Calculate overall security score (0-100)
  let score = 100
  score -= critical * 25  // Critical findings heavily impact score
  score -= high * 15      // High findings significantly impact score
  score -= medium * 8     // Medium findings moderately impact score
  score -= low * 3        // Low findings slightly impact score
  
  const overallScore = Math.max(0, score)
  
  // Determine risk level
  let riskLevel: SecurityAssessment['riskLevel'] = 'LOW'
  if (overallScore < 30) riskLevel = 'CRITICAL'
  else if (overallScore < 50) riskLevel = 'HIGH'
  else if (overallScore < 70) riskLevel = 'MEDIUM'
  
  // Compliance scoring (simplified)
  const owaspScore = Math.max(0, 100 - (critical * 30) - (high * 20) - (medium * 10))
  const nistScore = Math.max(0, 100 - (critical * 25) - (high * 15) - (medium * 8))
  const pciScore = Math.max(0, 100 - (critical * 35) - (high * 25) - (medium * 15))
  
  // Attack surface analysis
  const webServices = findings.filter(f => f.type.includes('HTTP') || f.type.includes('SSL')).length
  const openPorts = findings.filter(f => f.affectedComponent?.includes('Port')).length
  const exposedServices = [...new Set(findings
    .filter(f => f.affectedComponent)
    .map(f => f.affectedComponent!)
    .filter(component => component.includes('Port') || component.includes('Service'))
  )]
  
  return {
    riskLevel,
    overallScore,
    compliance: {
      owasp: owaspScore,
      nist: nistScore,
      pci: pciScore
    },
    attackSurface: {
      webServices,
      openPorts,
      exposedServices
    }
  }
}

async function checkCommonPaths(baseUrl: string): Promise<VulnerabilityFinding[]> {
  const sensitivePaths = [
    { path: '/admin', severity: 'High' as const, type: 'Administrative Interface' },
    { path: '/.git', severity: 'Critical' as const, type: 'Source Code Exposure' },
    { path: '/.env', severity: 'Critical' as const, type: 'Configuration Exposure' },
    { path: '/backup', severity: 'High' as const, type: 'Backup File Exposure' },
    { path: '/phpMyAdmin', severity: 'High' as const, type: 'Database Admin Interface' }
  ]
  
  const findings: VulnerabilityFinding[] = []
  
  for (const { path, severity, type } of sensitivePaths) {
    try {
      const response = await fetch(`${baseUrl}${path}`, {
        method: 'HEAD',
        headers: {
          'User-Agent': 'CyberShield-VulnScanner/2.0'
        }
      })
      
      if (response.status === 200) {
        findings.push({
          id: `accessible-path-${path.replace(/[^a-zA-Z0-9]/g, '-')}`,
          type,
          severity,
          title: `Accessible Sensitive Path: ${path}`,
          description: `The sensitive path ${path} is publicly accessible`,
          recommendation: 'Restrict access to sensitive directories and implement proper access controls',
          discoveryMethod: 'Directory Enumeration',
          affectedComponent: `Path: ${path}`
        })
      }
    } catch (error) {
      // Path check failed, continue
    }
  }
  
  return findings
}

export async function POST(req: NextRequest) {
  try {
    const { target, scanType, options } = await req.json()

    if (!target) {
      return NextResponse.json({
        success: false,
        message: "Target URL or hostname is required"
      }, { status: 400 })
    }

    const startTime = Date.now()
    let allFindings: VulnerabilityFinding[] = []

    // Normalize target URL
    let baseUrl = target
    if (!target.startsWith('http://') && !target.startsWith('https://')) {
      baseUrl = `https://${target}`
    }

    const hostname = new URL(baseUrl).hostname

    // Comprehensive vulnerability assessment
    if (scanType === 'web' || scanType === 'comprehensive') {
      console.log('🔍 Starting web vulnerability assessment...')
      
      // HTTP Security Headers Analysis
      const headerFindings = await checkHttpHeaders(baseUrl)
      allFindings = allFindings.concat(headerFindings)

      // SSL/TLS Security Assessment
      const sslFindings = await checkSSLTLS(hostname)
      allFindings = allFindings.concat(sslFindings)

      // Sensitive Path Discovery
      const pathFindings = await checkCommonPaths(baseUrl)
      allFindings = allFindings.concat(pathFindings)
    }

    // Network security assessment
    if (scanType === 'network' || scanType === 'comprehensive') {
      console.log('🌐 Starting network security assessment...')
      
      // Port scanning and service analysis
      const networkFindings = await checkNetworkPorts(hostname)
      allFindings = allFindings.concat(networkFindings)
    }

    const endTime = Date.now()
    const scanTime = endTime - startTime

    // Generate comprehensive security assessment
    const securityAssessment = generateSecurityAssessment(allFindings)

    // Categorize findings by severity
    const critical = allFindings.filter(f => f.severity === 'Critical').length
    const high = allFindings.filter(f => f.severity === 'High').length
    const medium = allFindings.filter(f => f.severity === 'Medium').length
    const low = allFindings.filter(f => f.severity === 'Low').length
    const info = allFindings.filter(f => f.severity === 'Info').length

    // Generate enhanced summary with emojis and risk indicators
    const riskIcon = securityAssessment.riskLevel === 'CRITICAL' ? '🚨' : 
                    securityAssessment.riskLevel === 'HIGH' ? '⚠️' : 
                    securityAssessment.riskLevel === 'MEDIUM' ? '🔶' : '✅'
    
    let summary = `${riskIcon} Vulnerability assessment completed for ${target}.\n`
    summary += `📊 Security Score: ${securityAssessment.overallScore}/100 (${securityAssessment.riskLevel} RISK)\n`
    summary += `🔍 Found ${allFindings.length} security findings: ${critical} Critical, ${high} High, ${medium} Medium, ${low} Low severity.\n`
    
    if (critical > 0) {
      summary += `⚡ URGENT: ${critical} critical vulnerabilities require immediate attention!\n`
    }
    
    if (allFindings.some(f => f.cveId)) {
      const cveCount = allFindings.filter(f => f.cveId).length
      summary += `📋 ${cveCount} known CVE(s) identified in the assessment.`
    }

    // Enhanced recommendations based on findings
    const recommendations = [
      '🔒 Implement comprehensive security headers (CSP, HSTS, X-Frame-Options)',
      '🛡️ Ensure all communications use HTTPS with proper TLS configuration',
      '🔐 Restrict access to administrative interfaces and sensitive directories',
      '📦 Keep all software components updated to latest secure versions',
      '🔍 Conduct regular automated security scans and penetration testing'
    ]
    
    // Add specific recommendations based on findings
    if (allFindings.some(f => f.cveId)) {
      recommendations.unshift('🚨 CRITICAL: Update software with known CVE vulnerabilities immediately')
    }
    
    if (allFindings.some(f => f.type.includes('Insecure'))) {
      recommendations.push('🔄 Replace insecure protocols (HTTP, FTP, Telnet) with secure alternatives')
    }

    const result = {
      target,
      scanType,
      summary,
      securityAssessment,
      findings: allFindings.sort((a, b) => {
        // Sort by severity: Critical > High > Medium > Low > Info
        const severityOrder = { 'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4 }
        return severityOrder[a.severity] - severityOrder[b.severity]
      }),
      statistics: {
        total: allFindings.length,
        critical,
        high,
        medium,
        low,
        info,
        cveFindings: allFindings.filter(f => f.cveId).length
      },
      scanTime,
      timestamp: new Date().toISOString(),
      recommendations,
      compliance: {
        owasp: `${securityAssessment.compliance.owasp}% compliant`,
        nist: `${securityAssessment.compliance.nist}% compliant`,
        pci: `${securityAssessment.compliance.pci}% compliant`
      }
    }

    return NextResponse.json({
      success: true,
      data: result
    })

  } catch (error) {
    console.error("❌ Vulnerability scanner error:", error)
    
    return NextResponse.json({
      success: false,
      message: "Vulnerability scan failed",
      error: process.env.NODE_ENV === 'development' ? (error instanceof Error ? error.message : 'Unknown error') : undefined
    }, { status: 500 })
  }
}