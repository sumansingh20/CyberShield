import { type NextRequest, NextResponse } from "next/server"
import { exec } from "child_process"
import { promisify } from "util"
import { readFile } from "fs/promises"
import { createConnection } from "net"

const execAsync = promisify(exec)

export const dynamic = "force-dynamic"

interface SecurityAnalysis {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  securityScore: number
  vulnerabilities: Array<{
    type: string
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    description: string
    port?: number
    service?: string
  }>
  recommendations: string[]
}

interface DeviceFingerprint {
  osGuess: string
  deviceType: 'Server' | 'Workstation' | 'Router' | 'Switch' | 'Unknown'
  vendor?: string
  confidence: number
}

interface NetworkHost {
  ip: string
  hostname?: string
  status: 'up' | 'down'
  responseTime?: number
  openPorts: number[]
  services?: Array<{ port: number; service: string; version?: string; banner?: string }>
  deviceFingerprint?: DeviceFingerprint
  securityAnalysis?: SecurityAnalysis
}

// Enhanced device fingerprinting based on open ports and services
function analyzeDeviceFingerprint(openPorts: number[], hostname?: string): DeviceFingerprint {
  let osGuess = 'Unknown'
  let deviceType: 'Server' | 'Workstation' | 'Router' | 'Switch' | 'Unknown' = 'Unknown'
  let vendor: string | undefined
  let confidence = 30

  // Windows indicators
  if (openPorts.includes(135) || openPorts.includes(139) || openPorts.includes(445) || openPorts.includes(3389)) {
    osGuess = 'Windows'
    confidence = 85
    if (openPorts.includes(3389)) {
      deviceType = 'Server'
      confidence = 90
    } else if (openPorts.includes(135)) {
      deviceType = 'Workstation'
      confidence = 80
    }
  }
  
  // Linux/Unix indicators
  else if (openPorts.includes(22) && (openPorts.includes(80) || openPorts.includes(443))) {
    osGuess = 'Linux/Unix'
    deviceType = 'Server'
    confidence = 85
  }
  
  // Router/Network device indicators
  else if (openPorts.includes(23) && openPorts.includes(161)) {
    osGuess = 'Router/Switch OS'
    deviceType = 'Router'
    confidence = 75
    if (hostname?.toLowerCase().includes('cisco')) vendor = 'Cisco'
  }
  
  // Database servers
  else if (openPorts.includes(3306) || openPorts.includes(5432) || openPorts.includes(1433)) {
    osGuess = 'Database Server'
    deviceType = 'Server'
    confidence = 80
  }
  
  // Web servers
  else if (openPorts.includes(80) || openPorts.includes(443)) {
    osGuess = 'Web Server'
    deviceType = 'Server'
    confidence = 70
  }

  return { osGuess, deviceType, vendor, confidence }
}

// Enhanced security analysis
function analyzeHostSecurity(host: NetworkHost): SecurityAnalysis {
  const vulnerabilities: SecurityAnalysis['vulnerabilities'] = []
  let securityScore = 100
  const recommendations: string[] = []

  // Check for insecure services
  if (host.openPorts.includes(23)) {
    vulnerabilities.push({
      type: 'Insecure Protocol',
      severity: 'HIGH',
      description: 'Telnet service detected - transmits data in plaintext',
      port: 23,
      service: 'Telnet'
    })
    securityScore -= 25
    recommendations.push('🔒 Replace Telnet with SSH for secure remote access')
  }

  if (host.openPorts.includes(21)) {
    vulnerabilities.push({
      type: 'Insecure Protocol',
      severity: 'MEDIUM',
      description: 'FTP service detected - consider SFTP or FTPS',
      port: 21,
      service: 'FTP'
    })
    securityScore -= 15
    recommendations.push('🔒 Consider using SFTP instead of FTP for secure file transfer')
  }

  if (host.openPorts.includes(135) && host.openPorts.includes(139)) {
    vulnerabilities.push({
      type: 'Windows Vulnerability',
      severity: 'MEDIUM',
      description: 'Windows RPC and NetBIOS ports exposed',
      service: 'Windows RPC/NetBIOS'
    })
    securityScore -= 20
    recommendations.push('🛡️ Consider restricting RPC and NetBIOS access to trusted networks')
  }

  if (host.openPorts.includes(161)) {
    vulnerabilities.push({
      type: 'Information Disclosure',
      severity: 'MEDIUM',
      description: 'SNMP service detected - ensure proper community string security',
      port: 161,
      service: 'SNMP'
    })
    securityScore -= 15
    recommendations.push('🔐 Secure SNMP with strong community strings and restrict access')
  }

  // Check for database exposure
  const dbPorts = [3306, 5432, 1433, 1521]
  const exposedDbPorts = host.openPorts.filter(port => dbPorts.includes(port))
  if (exposedDbPorts.length > 0) {
    vulnerabilities.push({
      type: 'Database Exposure',
      severity: 'HIGH',
      description: 'Database services exposed to network',
      service: 'Database'
    })
    securityScore -= 30
    recommendations.push('🔒 Restrict database access to application servers only')
  }

  // Positive security indicators
  if (host.openPorts.includes(443) && !host.openPorts.includes(80)) {
    securityScore += 10
    recommendations.push('✅ HTTPS-only configuration detected - good security practice')
  }

  if (host.openPorts.includes(22) && !host.openPorts.includes(23)) {
    securityScore += 5
    recommendations.push('✅ SSH service available - secure remote access enabled')
  }

  // Too many open ports
  if (host.openPorts.length > 10) {
    vulnerabilities.push({
      type: 'Attack Surface',
      severity: 'MEDIUM',
      description: 'High number of open ports increases attack surface'
    })
    securityScore -= 15
    recommendations.push('🔍 Review and close unnecessary open ports to reduce attack surface')
  }

  // Determine risk level
  let riskLevel: SecurityAnalysis['riskLevel'] = 'LOW'
  if (securityScore < 30) riskLevel = 'CRITICAL'
  else if (securityScore < 50) riskLevel = 'HIGH'
  else if (securityScore < 70) riskLevel = 'MEDIUM'

  return {
    riskLevel,
    securityScore: Math.max(0, securityScore),
    vulnerabilities,
    recommendations
  }
}

// Helper function to ping a host
async function pingHost(host: string): Promise<{ isUp: boolean, responseTime?: number }> {
  try {
    const isWindows = process.platform === "win32"
    const pingCommand = isWindows 
      ? `ping -n 1 -w 1000 ${host}`
      : `ping -c 1 -W 1 ${host}`
    
    const { stdout } = await execAsync(pingCommand)
    
    if (isWindows) {
      const match = stdout.match(/time[<=](\d+)ms/i)
      if (match) {
        return { isUp: true, responseTime: parseInt(match[1]) }
      }
    } else {
      const match = stdout.match(/time=(\d+\.?\d*) ms/)
      if (match) {
        return { isUp: true, responseTime: parseFloat(match[1]) }
      }
    }
    
    return { isUp: false }
  } catch (error) {
    return { isUp: false }
  }
}

// Helper function to scan a single port
async function scanPort(host: string, port: number, timeout = 1000): Promise<boolean> {
  return new Promise((resolve) => {
    const socket = createConnection({ host, port, timeout })
    
    socket.on('connect', () => {
      socket.destroy()
      resolve(true)
    })
    
    socket.on('timeout', () => {
      socket.destroy()
      resolve(false)
    })
    
    socket.on('error', () => {
      resolve(false)
    })
  })
}

// Helper function to parse CIDR notation
function parseCIDR(cidr: string): string[] {
  if (!cidr.includes('/')) {
    return [cidr] // Single IP
  }

  const [network, prefixStr] = cidr.split('/')
  const prefix = parseInt(prefixStr)
  
  if (prefix >= 24) {
    // For /24 and smaller, scan subnet range based on CIDR
    const baseIp = network.split('.').slice(0, 3).join('.')
    const hosts = []
    const maxHosts = Math.pow(2, 32 - prefix) - 2 // Exclude network and broadcast
    const actualMax = Math.min(254, maxHosts) // Practical limit for /24
    
    for (let i = 1; i <= actualMax; i++) {
      hosts.push(`${baseIp}.${i}`)
    }
    return hosts
  } else {
    // For larger networks, return strategic sample points
    const baseOctets = network.split('.')
    const strategicHosts = []
    
    // Add network gateways and common infrastructure IPs
    for (let i = 1; i <= 10; i++) {
      strategicHosts.push(`${baseOctets[0]}.${baseOctets[1]}.${baseOctets[2]}.${i}`)
    }
    
    return strategicHosts
  }
}

export async function POST(req: NextRequest) {
  try {
    const { target, scanType, portRange } = await req.json()

    if (!target) {
      return NextResponse.json({
        success: false,
        message: "Target is required"
      }, { status: 400 })
    }

    const startTime = Date.now()
    const hosts: any[] = []
    let totalPorts = 0

    // Parse target - could be single IP, hostname, or CIDR
    let targetHosts: string[] = []
    
    if (target.includes('/')) {
      // CIDR notation
      targetHosts = parseCIDR(target)
    } else if (target.includes('-')) {
      // IP range like 192.168.1.1-10
      const [baseIp, range] = target.split('-')
      const baseIpParts = baseIp.split('.')
      const startHost = parseInt(baseIpParts[3])
      const endHost = parseInt(range)
      
      for (let i = startHost; i <= Math.min(endHost, startHost + 10); i++) {
        targetHosts.push(`${baseIpParts.slice(0, 3).join('.')}.${i}`)
      }
    } else {
      // Single host
      targetHosts = [target]
    }

    // Scan each host
    for (const host of targetHosts) {
      const pingResult = await pingHost(host)
      
      if (!pingResult.isUp && scanType === 'discovery') {
        continue // Skip unreachable hosts for discovery scan
      }

      const hostData: NetworkHost = {
        ip: host,
        status: pingResult.isUp ? 'up' : 'down',
        openPorts: [],
        responseTime: pingResult.responseTime
      }

      // Try to resolve hostname
      try {
        const { stdout } = await execAsync(`nslookup ${host}`)
        const hostnameMatch = stdout.match(/Name:\s+(.+)/)
        if (hostnameMatch) {
          hostData.hostname = hostnameMatch[1].trim()
        }
      } catch (error) {
        // Hostname resolution failed, continue without it
      }

      // Port scanning for specific scan types
      if ((scanType === 'port-scan' || scanType === 'comprehensive') && pingResult.isUp) {
        const portsToScan = []
        
        if (portRange === '21,22,23,25,53,80,110,443,993,995') {
          portsToScan.push(...[21, 22, 23, 25, 53, 80, 110, 443, 993, 995])
        } else if (portRange === '1-1000') {
          // Scan common ports for efficiency
          portsToScan.push(...[21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 3389, 5432, 3306])
        } else if (portRange === '1-5000') {
          // Extended common ports
          portsToScan.push(...[21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 1521, 3389, 5432, 3306, 5000])
        } else {
          // Default to common ports
          portsToScan.push(...[21, 22, 23, 25, 53, 80, 110, 443])
        }

        // Scan ports in parallel but limit concurrency
        const portPromises = portsToScan.map(async (port) => {
          const isOpen = await scanPort(host, port, 2000)
          return { port, isOpen }
        })

        const portResults = await Promise.all(portPromises)
        hostData.openPorts = portResults.filter(r => r.isOpen).map(r => r.port)
        totalPorts += hostData.openPorts.length

        // Add enhanced service detection for open ports
        if (hostData.openPorts.length > 0) {
          hostData.services = hostData.openPorts.map((port: number) => {
            const serviceMap: { [key: number]: { name: string; version?: string } } = {
              21: { name: 'FTP', version: 'File Transfer Protocol' },
              22: { name: 'SSH', version: 'Secure Shell' },
              23: { name: 'Telnet', version: 'Insecure Remote Terminal' },
              25: { name: 'SMTP', version: 'Simple Mail Transfer Protocol' },
              53: { name: 'DNS', version: 'Domain Name System' },
              80: { name: 'HTTP', version: 'Web Server (Insecure)' },
              110: { name: 'POP3', version: 'Post Office Protocol v3' },
              135: { name: 'RPC', version: 'Microsoft RPC' },
              139: { name: 'NetBIOS', version: 'NetBIOS Session Service' },
              143: { name: 'IMAP', version: 'Internet Message Access Protocol' },
              443: { name: 'HTTPS', version: 'Secure Web Server' },
              445: { name: 'SMB', version: 'Server Message Block' },
              993: { name: 'IMAPS', version: 'IMAP over SSL' },
              995: { name: 'POP3S', version: 'POP3 over SSL' },
              1433: { name: 'MSSQL', version: 'Microsoft SQL Server' },
              1521: { name: 'Oracle', version: 'Oracle Database' },
              3306: { name: 'MySQL', version: 'MySQL Database' },
              3389: { name: 'RDP', version: 'Remote Desktop Protocol' },
              5432: { name: 'PostgreSQL', version: 'PostgreSQL Database' }
            }
            const service = serviceMap[port] || { name: 'Unknown' }
            return { 
              port, 
              service: service.name,
              version: service.version,
              banner: service.version ? `${service.name} - ${service.version}` : service.name
            }
          })
          
          // Add device fingerprinting
          hostData.deviceFingerprint = analyzeDeviceFingerprint(hostData.openPorts, hostData.hostname)
          
          // Add security analysis
          hostData.securityAnalysis = analyzeHostSecurity(hostData)
        }
      }

      hosts.push(hostData)
    }

    const endTime = Date.now()
    const scanTime = endTime - startTime

    // Generate enhanced summary with security insights
    const activeHosts = hosts.filter(h => h.status === 'up').length
    const totalHosts = hosts.length
    
    // Security analysis summary
    const criticalHosts = hosts.filter(h => h.securityAnalysis?.riskLevel === 'CRITICAL').length
    const highRiskHosts = hosts.filter(h => h.securityAnalysis?.riskLevel === 'HIGH').length
    const vulnerabilityCount = hosts.reduce((sum, h) => sum + (h.securityAnalysis?.vulnerabilities.length || 0), 0)
    
    let summary = `🔍 Network scan completed for ${target}.\n`
    summary += `📊 Found ${activeHosts} active hosts out of ${totalHosts} scanned.\n`
    
    if (scanType !== 'discovery') {
      summary += `🚪 Discovered ${totalPorts} open ports across all hosts.\n`
      
      if (criticalHosts > 0) {
        summary += `🚨 CRITICAL: ${criticalHosts} host(s) with critical security issues!\n`
      }
      if (highRiskHosts > 0) {
        summary += `⚠️ HIGH RISK: ${highRiskHosts} host(s) with high-risk vulnerabilities.\n`
      }
      if (vulnerabilityCount > 0) {
        summary += `🔓 Total vulnerabilities detected: ${vulnerabilityCount}\n`
      }
    }
    
    const avgResponseTime = hosts
      .filter(h => h.responseTime)
      .reduce((sum, h) => sum + (h.responseTime || 0), 0) / Math.max(1, hosts.filter(h => h.responseTime).length)
    
    if (avgResponseTime > 0) {
      summary += `⏱️ Average response time: ${avgResponseTime.toFixed(2)}ms`
    }

    const result = {
      target,
      scanType,
      summary,
      hosts: hosts.filter(h => h.status === 'up' || scanType === 'comprehensive'), // Show only up hosts unless comprehensive
      totalHosts: activeHosts,
      totalPorts,
      scanTime,
      timestamp: new Date().toISOString(),
      portRange: scanType !== 'discovery' ? portRange : undefined,
      securitySummary: scanType !== 'discovery' ? {
        criticalHosts,
        highRiskHosts,
        vulnerabilityCount,
        averageSecurityScore: Math.round(hosts
          .filter(h => h.securityAnalysis)
          .reduce((sum, h) => sum + (h.securityAnalysis?.securityScore || 0), 0) / 
          Math.max(1, hosts.filter(h => h.securityAnalysis).length))
      } : undefined
    }

    return NextResponse.json({
      success: true,
      data: result
    })

  } catch (error) {
    console.error("Network scanner error:", error)
    
    return NextResponse.json({
      success: false,
      message: "Network scan failed",
      error: process.env.NODE_ENV === 'development' ? (error instanceof Error ? error.message : 'Unknown error') : undefined
    }, { status: 500 })
  }
}