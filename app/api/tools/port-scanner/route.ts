import { NextRequest, NextResponse } from 'next/server'
import { createConnection } from 'net'

// Common service names for ports
const portServices: { [key: number]: string } = {
  21: 'FTP',
  22: 'SSH',
  23: 'Telnet',
  25: 'SMTP',
  53: 'DNS',
  80: 'HTTP',
  110: 'POP3',
  139: 'NetBIOS',
  143: 'IMAP',
  443: 'HTTPS',
  993: 'IMAPS',
  995: 'POP3S',
  1433: 'MSSQL',
  1521: 'Oracle',
  3306: 'MySQL',
  3389: 'RDP',
  5432: 'PostgreSQL',
  5900: 'VNC',
  6379: 'Redis',
  8080: 'HTTP-Alt',
  8443: 'HTTPS-Alt',
  9200: 'Elasticsearch',
  27017: 'MongoDB'
}

// Function to parse port range
function parsePortRange(portRange: string): number[] {
  const ports: number[] = []
  
  if (portRange.includes(',')) {
    // Comma-separated ports (e.g., "80,443,8080")
    const portList = portRange.split(',').map(p => p.trim())
    for (const port of portList) {
      if (port.includes('-')) {
        const [start, end] = port.split('-').map(Number)
        for (let i = start; i <= end; i++) {
          if (i >= 1 && i <= 65535) ports.push(i)
        }
      } else {
        const p = parseInt(port)
        if (p >= 1 && p <= 65535) ports.push(p)
      }
    }
  } else if (portRange.includes('-')) {
    // Range (e.g., "1-1000")
    const [start, end] = portRange.split('-').map(Number)
    if (start >= 1 && end <= 65535 && start <= end) {
      for (let i = start; i <= end; i++) {
        ports.push(i)
      }
    }
  } else {
    // Single port
    const port = parseInt(portRange)
    if (port >= 1 && port <= 65535) ports.push(port)
  }
  
  return [...new Set(ports)].sort((a, b) => a - b) // Remove duplicates and sort
}

// Enhanced security analysis and vulnerability detection
function analyzeSecurityVulnerabilities(openPorts: any[]): {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL',
  vulnerabilities: Array<{port: number, service: string, severity: string, description: string, recommendation: string}>,
  overallScore: number,
  securityRecommendations: string[]
} {
  const vulnerabilities: Array<{port: number, service: string, severity: string, description: string, recommendation: string}> = []
  const recommendations: string[] = []
  let riskScore = 0

  openPorts.forEach(portInfo => {
    const { port, service, banner } = portInfo
    
    // Critical vulnerabilities
    if (port === 23) { // Telnet
      vulnerabilities.push({
        port,
        service: 'Telnet',
        severity: 'CRITICAL',
        description: 'Unencrypted remote access protocol exposes credentials',
        recommendation: 'Disable Telnet and use SSH (port 22) instead'
      })
      riskScore += 40
    }
    
    if (port === 21) { // FTP
      vulnerabilities.push({
        port,
        service: 'FTP',
        severity: 'HIGH',
        description: 'FTP transmits credentials in plain text',
        recommendation: 'Use SFTP (SSH File Transfer) or FTPS instead'
      })
      riskScore += 30
    }
    
    if (port === 139 || port === 445) { // SMB/NetBIOS
      vulnerabilities.push({
        port,
        service: 'SMB/NetBIOS',
        severity: 'HIGH', 
        description: 'SMB services vulnerable to EternalBlue and other exploits',
        recommendation: 'Ensure latest patches, disable SMBv1, use network segmentation'
      })
      riskScore += 35
    }
    
    if (port === 3389) { // RDP
      vulnerabilities.push({
        port,
        service: 'RDP',
        severity: 'HIGH',
        description: 'RDP exposed to internet increases brute force attack risk',
        recommendation: 'Use VPN access, enable NLA, implement account lockout policies'
      })
      riskScore += 30
    }
    
    if (port === 1433 || port === 3306 || port === 5432) { // Database ports
      vulnerabilities.push({
        port,
        service: service || 'Database',
        severity: 'HIGH',
        description: 'Database service exposed to network',
        recommendation: 'Restrict access to application servers only, use firewalls'
      })
      riskScore += 25
    }
    
    // Medium vulnerabilities
    if (port === 80 && !openPorts.some(p => p.port === 443)) {
      vulnerabilities.push({
        port,
        service: 'HTTP',
        severity: 'MEDIUM',
        description: 'HTTP without HTTPS exposes data in transit',
        recommendation: 'Implement HTTPS with valid SSL certificates'
      })
      riskScore += 15
    }
    
    if (port === 5900) { // VNC
      vulnerabilities.push({
        port,
        service: 'VNC',
        severity: 'MEDIUM',
        description: 'VNC remote desktop service may have weak authentication',
        recommendation: 'Use strong passwords, enable encryption, tunnel through SSH'
      })
      riskScore += 20
    }
    
    // Banner analysis for version vulnerabilities
    if (banner) {
      const bannerLower = banner.toLowerCase()
      if (bannerLower.includes('openssh') && bannerLower.includes('_')) {
        const version = bannerLower.match(/openssh[_\s]([\d\.]+)/)
        if (version) {
          vulnerabilities.push({
            port,
            service: 'SSH',
            severity: 'LOW',
            description: `OpenSSH version ${version[1]} detected - may have known vulnerabilities`,
            recommendation: 'Update to latest OpenSSH version'
          })
          riskScore += 5
        }
      }
      
      if (bannerLower.includes('apache') || bannerLower.includes('nginx')) {
        const serverMatch = bannerLower.match(/(apache|nginx)\/([\d\.]+)/)
        if (serverMatch) {
          vulnerabilities.push({
            port,
            service: 'Web Server',
            severity: 'LOW',
            description: `${serverMatch[1]} version ${serverMatch[2]} detected - verify latest security patches`,
            recommendation: 'Keep web server updated, hide version information'
          })
          riskScore += 3
        }
      }
    }
  })
  
  // Generate overall recommendations
  if (vulnerabilities.some(v => v.severity === 'CRITICAL')) {
    recommendations.push('🚨 IMMEDIATE ACTION: Close critical services or implement strong access controls')
  }
  
  if (vulnerabilities.some(v => v.port === 23 || v.port === 21)) {
    recommendations.push('🔒 Replace insecure protocols with encrypted alternatives (SSH, SFTP)')
  }
  
  if (vulnerabilities.some(v => v.port === 1433 || v.port === 3306 || v.port === 5432)) {
    recommendations.push('🛡️ Database services should not be directly accessible from internet')
  }
  
  recommendations.push('🔍 Implement regular vulnerability scanning and patch management')
  recommendations.push('🌐 Use network segmentation and firewalls to limit exposure')
  recommendations.push('📊 Monitor unusual connection attempts and failed authentications')
  
  // Determine risk level
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  if (riskScore >= 80) riskLevel = 'CRITICAL'
  else if (riskScore >= 50) riskLevel = 'HIGH'
  else if (riskScore >= 20) riskLevel = 'MEDIUM'
  else riskLevel = 'LOW'
  
  return {
    riskLevel,
    vulnerabilities,
    overallScore: Math.min(riskScore, 100),
    securityRecommendations: recommendations
  }
}

// Enhanced service fingerprinting
function enhancedServiceDetection(portInfo: any): any {
  const { port, service, banner } = portInfo
  let detectedService = service || 'Unknown'
  let version = 'Unknown'
  let details = ''
  
  if (banner) {
    const bannerLower = banner.toLowerCase()
    
    // SSH detection
    if (bannerLower.includes('ssh')) {
      const sshMatch = bannerLower.match(/ssh-([\d\.]+)\s+openssh[_\s]([\d\.]+)/)
      if (sshMatch) {
        detectedService = 'OpenSSH'
        version = sshMatch[2]
        details = `Protocol ${sshMatch[1]}, OpenSSH ${sshMatch[2]}`
      }
    }
    
    // HTTP server detection
    if (bannerLower.includes('server:')) {
      const serverMatch = bannerLower.match(/server:\s*([^\r\n]+)/)
      if (serverMatch) {
        detectedService = 'HTTP Server'
        version = serverMatch[1]
        details = serverMatch[1]
      }
    }
    
    // FTP detection
    if (bannerLower.includes('ftp') && (bannerLower.includes('ready') || bannerLower.includes('welcome'))) {
      const ftpMatch = bannerLower.match(/(vsftpd|proftpd|filezilla|microsoft ftp)\s*([\d\.]+)?/)
      if (ftpMatch) {
        detectedService = ftpMatch[1].toUpperCase()
        version = ftpMatch[2] || 'Unknown'
        details = `${ftpMatch[1]} FTP Server ${ftpMatch[2] || ''}`
      }
    }
    
    // Database detection
    if (bannerLower.includes('mysql')) {
      const mysqlMatch = bannerLower.match(/([\d\.]+)-/)
      if (mysqlMatch) {
        detectedService = 'MySQL'
        version = mysqlMatch[1]
        details = `MySQL Database Server ${mysqlMatch[1]}`
      }
    }
  }
  
  // Port-based detection when no banner is available
  if (detectedService === 'Unknown' || detectedService === portServices[port]) {
    switch (port) {
      case 22:
        detectedService = 'SSH Server'
        details = 'Secure Shell remote access'
        break
      case 80:
        detectedService = 'Web Server'
        details = 'HTTP web service'
        break
      case 443:
        detectedService = 'Secure Web Server'
        details = 'HTTPS web service with SSL/TLS'
        break
      case 25:
        detectedService = 'SMTP Server'
        details = 'Email sending service'
        break
      case 993:
        detectedService = 'IMAPS Server'
        details = 'Secure IMAP email service'
        break
    }
  }
  
  return {
    ...portInfo,
    detectedService,
    version,
    details: details || `${detectedService} on port ${port}`
  }
}
function scanPort(host: string, port: number, timeout: number = 3000): Promise<{
  port: number,
  open: boolean,
  service?: string,
  banner?: string,
  responseTime?: number,
  error?: string
}> {
  return new Promise((resolve) => {
    const startTime = Date.now()
    const socket = createConnection({ host, port, timeout })
    
    let responseTime: number
    let banner = ''
    
    socket.setTimeout(timeout)
    
    socket.on('connect', () => {
      responseTime = Date.now() - startTime
      
      // Try to grab banner
      const bannerTimeout = setTimeout(() => {
        socket.destroy()
        resolve({
          port,
          open: true,
          service: portServices[port] || 'Unknown',
          banner: banner || undefined,
          responseTime
        })
      }, 1000)
      
      socket.on('data', (data) => {
        banner += data.toString().trim().substring(0, 200) // Limit banner size
        clearTimeout(bannerTimeout)
        socket.destroy()
        resolve({
          port,
          open: true,
          service: portServices[port] || 'Unknown',
          banner: banner || undefined,
          responseTime
        })
      })
    })
    
    socket.on('timeout', () => {
      socket.destroy()
      resolve({
        port,
        open: false,
        error: 'Connection timeout'
      })
    })
    
    socket.on('error', (error) => {
      socket.destroy()
      resolve({
        port,
        open: false,
        error: error.message
      })
    })
  })
}

export async function POST(request: NextRequest) {
  try {
    const { target, ports, scanType, timeout } = await request.json()
    
    if (!target) {
      return NextResponse.json({
        success: false,
        message: 'Target host is required'
      }, { status: 400 })
    }
    
    if (!ports) {
      return NextResponse.json({
        success: false,
        message: 'Port range is required'
      }, { status: 400 })
    }

    const host = target.trim()
    const scanTimeout = timeout || 3000
    const startTime = Date.now()

    // Parse ports
    let targetPorts: number[]
    try {
      targetPorts = parsePortRange(ports.toString())
    } catch (error) {
      return NextResponse.json({
        success: false,
        message: 'Invalid port range format'
      }, { status: 400 })
    }

    if (targetPorts.length === 0) {
      return NextResponse.json({
        success: false,
        message: 'No valid ports in range'
      }, { status: 400 })
    }

    if (targetPorts.length > 1000) {
      return NextResponse.json({
        success: false,
        message: 'Port range too large (maximum 1000 ports)'
      }, { status: 400 })
    }

    // Limit concurrent scans to avoid overwhelming the system
    const concurrencyLimit = 50
    const results: any[] = []
    
    for (let i = 0; i < targetPorts.length; i += concurrencyLimit) {
      const batch = targetPorts.slice(i, i + concurrencyLimit)
      const batchResults = await Promise.all(
        batch.map(port => scanPort(host, port, scanTimeout))
      )
      results.push(...batchResults)
    }

    const executionTime = Date.now() - startTime
    const openPorts = results.filter(r => r.open)
    const closedPorts = results.filter(r => !r.open)

    // Enhanced service detection
    const enhancedOpenPorts = openPorts.map(enhancedServiceDetection)
    
    // Perform comprehensive security analysis
    const securityAnalysis = analyzeSecurityVulnerabilities(enhancedOpenPorts)

    // Group by service type (updated with enhanced detection)
    const serviceGroups: { [key: string]: any[] } = {}
    enhancedOpenPorts.forEach(port => {
      const service = port.detectedService || port.service || 'Unknown'
      if (!serviceGroups[service]) {
        serviceGroups[service] = []
      }
      serviceGroups[service].push(port)
    })

    // Legacy security flags (keeping for compatibility)
    const securityFlags = []
    if (enhancedOpenPorts.some(p => p.port === 21)) securityFlags.push('FTP service detected')
    if (enhancedOpenPorts.some(p => p.port === 23)) securityFlags.push('Telnet service detected (unencrypted)')
    if (enhancedOpenPorts.some(p => p.port === 139 || p.port === 445)) securityFlags.push('SMB/NetBIOS services detected')
    if (enhancedOpenPorts.some(p => p.port === 3389)) securityFlags.push('RDP service detected')
    if (enhancedOpenPorts.some(p => p.port === 22)) securityFlags.push('SSH service available')
    if (enhancedOpenPorts.some(p => p.port === 80) && !enhancedOpenPorts.some(p => p.port === 443)) {
      securityFlags.push('HTTP without HTTPS detected')
    }

    const result = {
      target: host,
      portRange: ports,
      scanType: scanType || 'TCP Connect',
      totalPorts: targetPorts.length,
      openPorts: enhancedOpenPorts.length,
      closedPorts: closedPorts.length,
      ports: {
        open: enhancedOpenPorts,
        closed: closedPorts.length > 50 ? [] : closedPorts // Don't return too many closed ports
      },
      serviceGroups,
      securityFlags, // Legacy compatibility
      securityAnalysis, // Enhanced security analysis
      summary: `Port scan completed: ${enhancedOpenPorts.length}/${targetPorts.length} ports are open (${securityAnalysis.riskLevel} risk)`,
      statistics: {
        totalScanned: targetPorts.length,
        openCount: enhancedOpenPorts.length,
        closedCount: closedPorts.length,
        averageResponseTime: enhancedOpenPorts.length > 0 
          ? Math.round(enhancedOpenPorts.reduce((sum, port) => sum + (port.responseTime || 0), 0) / enhancedOpenPorts.length)
          : 0,
        fastestResponse: enhancedOpenPorts.length > 0 
          ? Math.min(...enhancedOpenPorts.map(p => p.responseTime || Infinity))
          : 0,
        slowestResponse: enhancedOpenPorts.length > 0 
          ? Math.max(...enhancedOpenPorts.map(p => p.responseTime || 0))
          : 0,
        vulnerabilityCount: securityAnalysis.vulnerabilities.length,
        criticalVulnerabilities: securityAnalysis.vulnerabilities.filter(v => v.severity === 'CRITICAL').length,
        highVulnerabilities: securityAnalysis.vulnerabilities.filter(v => v.severity === 'HIGH').length
      },
      executionTime,
      timestamp: new Date().toISOString()
    }

    return NextResponse.json({
      success: true,
      data: result
    })

  } catch (error) {
    console.error('Port scan error:', error)
    return NextResponse.json({
      success: false,
      message: 'Internal server error during port scan',
      error: process.env.NODE_ENV === 'development' ? (error instanceof Error ? error.message : 'Unknown error') : undefined
    }, { status: 500 })
  }
}