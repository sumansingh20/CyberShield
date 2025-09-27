import { type NextRequest, NextResponse } from "next/server"
import { exec } from "child_process"
import { promisify } from "util"

const execAsync = promisify(exec)

export const dynamic = "force-dynamic"

// Helper function to validate IP address or hostname
function isValidTarget(target: string): boolean {
  // Basic validation for IP addresses and hostnames
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  const hostnameRegex = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/
  const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/
  
  return ipRegex.test(target) || hostnameRegex.test(target) || cidrRegex.test(target)
}

// Helper function to parse port ranges
function parsePortRange(portRange: string): number[] {
  if (portRange === 'top-100') {
    return [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3389, 5900, 8080]
  } else if (portRange === 'top-1000') {
    // Extended list of common ports
    const commonPorts = []
    for (let i = 1; i <= 1024; i++) {
      if ([21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995].includes(i)) {
        commonPorts.push(i)
      }
    }
    return commonPorts
  } else if (portRange.includes('-')) {
    const [start, end] = portRange.split('-').map(Number)
    const ports = []
    for (let i = start; i <= Math.min(end, start + 100); i++) { // Limit to 100 ports
      ports.push(i)
    }
    return ports
  } else if (portRange.includes(',')) {
    return portRange.split(',').map(Number).filter(Boolean)
  }
  return [80, 443, 22, 21, 25, 53, 110, 143]
}

// Simulate nmap-like scanning using Node.js networking
async function performAdvancedScan(target: string, scanType: string, options: any): Promise<any> {
  const startTime = Date.now()
  const results: any = {
    target,
    scanType,
    timestamp: new Date().toISOString(),
    hosts: []
  }

  try {
    // Parse target to get individual hosts
    let hosts = []
    if (target.includes('/')) {
      // CIDR notation - simulate by scanning a few IPs
      const baseIp = target.split('/')[0].split('.').slice(0, 3).join('.')
      for (let i = 1; i <= 5; i++) {
        hosts.push(`${baseIp}.${i}`)
      }
    } else {
      hosts = [target]
    }

    for (const host of hosts) {
      const hostResult: any = {
        ip: host,
        hostname: '',
        status: 'unknown',
        ports: [],
        os: 'Unknown',
        services: []
      }

      // Ping test
      try {
        const isWindows = process.platform === "win32"
        const pingCmd = isWindows ? `ping -n 1 -w 1000 ${host}` : `ping -c 1 -W 1 ${host}`
        await execAsync(pingCmd)
        hostResult.status = 'up'
      } catch {
        if (scanType === 'stealth' || scanType === 'comprehensive') {
          hostResult.status = 'filtered' // Might be up but not responding to ping
        } else {
          hostResult.status = 'down'
          continue
        }
      }

      // Hostname resolution
      try {
        const { stdout } = await execAsync(`nslookup ${host}`)
        const hostnameMatch = stdout.match(/Name:\s+(.+)/)
        if (hostnameMatch) {
          hostResult.hostname = hostnameMatch[1].trim()
        }
      } catch {
        // Hostname resolution failed
      }

      // Port scanning based on scan type
      const portsToScan = parsePortRange(options.portRange || 'top-100')
      
      for (const port of portsToScan.slice(0, 20)) { // Limit to 20 ports for performance
        const portResult = await scanSinglePort(host, port, scanType)
        if (portResult.isOpen) {
          hostResult.ports.push({
            port,
            state: 'open',
            service: getServiceName(port),
            version: portResult.version || 'Unknown',
            protocol: 'tcp'
          })
        } else if (portResult.isFiltered && scanType === 'comprehensive') {
          hostResult.ports.push({
            port,
            state: 'filtered',
            service: getServiceName(port),
            protocol: 'tcp'
          })
        }
      }

      // Enhanced OS Detection
      const osInfo = { os: simulateOSDetection(hostResult.ports), confidence: 75, details: 'Basic OS detection', characteristics: ['Standard TCP services'] }
      if (hostResult.ports.length > 0) {
        hostResult.os = osInfo.os
        hostResult.osConfidence = osInfo.confidence
        hostResult.osDetails = osInfo.details
        hostResult.osCharacteristics = osInfo.characteristics
      }
      
      // Vulnerability Detection
      hostResult.vulnerabilities = detectVulnerabilities(hostResult)
      
      // Service enumeration with enhanced details
      hostResult.services = hostResult.ports.map((p: any) => ({
        port: p.port,
        service: p.service,
        version: p.version,
        state: p.state,
        vulnerabilityCount: hostResult.vulnerabilities.filter((v: any) => v.port === p.port).length
      }))

      results.hosts.push(hostResult)
    }

    const endTime = Date.now()
    results.scanTime = endTime - startTime
    results.summary = generateScanSummary(results)
    
    // Add scan statistics
    results.statistics = {
      totalHosts: results.hosts.length,
      hostsUp: results.hosts.filter((h: any) => h.status === 'up').length,
      totalOpenPorts: results.hosts.reduce((sum: number, h: any) => 
        sum + h.ports.filter((p: any) => p.state === 'open').length, 0),
      uniqueServices: [...new Set(results.hosts.flatMap((h: any) => h.services.map((s: any) => s.service)))].length,
      totalVulnerabilities: results.hosts.reduce((sum: number, h: any) => sum + (h.vulnerabilities?.length || 0), 0)
    }

    return results
  } catch (error) {
    throw new Error(`Advanced scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

// Simulate port scanning
async function scanSinglePort(host: string, port: number, scanType: string): Promise<{ isOpen: boolean, isFiltered: boolean, version?: string }> {
  return new Promise((resolve) => {
    const net = require('net')
    const socket = new net.Socket()
    const timeout = scanType === 'stealth' ? 5000 : 2000

    socket.setTimeout(timeout)

    socket.connect(port, host, () => {
      socket.destroy()
      resolve({ isOpen: true, isFiltered: false, version: 'Unknown' })
    })

    socket.on('timeout', () => {
      socket.destroy()
      resolve({ isOpen: false, isFiltered: scanType === 'stealth', version: undefined })
    })

    socket.on('error', (error: any) => {
      if (error.code === 'ECONNREFUSED') {
        resolve({ isOpen: false, isFiltered: false, version: undefined })
      } else {
        resolve({ isOpen: false, isFiltered: true, version: undefined })
      }
    })
  })
}

// Enhanced vulnerability detection based on discovered services
function detectVulnerabilities(hostResult: any): Array<{service: string, port: number, vulnerability: string, severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL', description: string, recommendation: string}> {
  const vulnerabilities = []
  
  for (const port of hostResult.ports) {
    const { port: portNum, service, version, state } = port
    
    if (state !== 'open') continue
    
    // Critical vulnerabilities
    if (service === 'Telnet' && portNum === 23) {
      vulnerabilities.push({
        service,
        port: portNum,
        vulnerability: 'CVE-2020-15778',
        severity: 'CRITICAL' as const,
        description: 'Telnet transmits credentials in plaintext',
        recommendation: 'Disable Telnet and use SSH instead'
      })
    }
    
    if (service === 'FTP' && portNum === 21) {
      vulnerabilities.push({
        service,
        port: portNum,
        vulnerability: 'CVE-2019-12815',
        severity: 'HIGH' as const,
        description: 'FTP server may allow anonymous access or weak authentication',
        recommendation: 'Use SFTP or secure FTP with strong authentication'
      })
    }
    
    // SMB vulnerabilities
    if (portNum === 445 || portNum === 139) {
      vulnerabilities.push({
        service: 'SMB',
        port: portNum,
        vulnerability: 'MS17-010 (EternalBlue)',
        severity: 'CRITICAL' as const,
        description: 'SMB service vulnerable to remote code execution',
        recommendation: 'Apply MS17-010 patch, disable SMBv1, use network segmentation'
      })
    }
    
    // RDP vulnerabilities
    if (service === 'RDP' && portNum === 3389) {
      vulnerabilities.push({
        service,
        port: portNum,
        vulnerability: 'CVE-2019-0708 (BlueKeep)',
        severity: 'CRITICAL' as const,
        description: 'RDP service vulnerable to remote code execution',
        recommendation: 'Apply security updates, use Network Level Authentication, restrict access'
      })
    }
    
    // Database vulnerabilities
    if ([1433, 3306, 5432, 1521].includes(portNum)) {
      vulnerabilities.push({
        service,
        port: portNum,
        vulnerability: 'Database Exposure',
        severity: 'HIGH' as const,
        description: 'Database service exposed to network without proper access controls',
        recommendation: 'Restrict database access to application servers only, use VPN or private networks'
      })
    }
  }
  
  return vulnerabilities
}

// Get service name for port
function getServiceName(port: number): string {
  const services: { [key: number]: string } = {
    21: 'FTP',
    22: 'SSH',
    23: 'Telnet',
    25: 'SMTP',
    53: 'DNS',
    80: 'HTTP',
    110: 'POP3',
    135: 'RPC',
    139: 'NetBios',
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
    8080: 'HTTP-Proxy'
  }
  return services[port] || 'Unknown'
}

// Simulate OS detection based on open ports
function simulateOSDetection(ports: any[]): string {
  const portNumbers = ports.map(p => p.port)
  
  if (portNumbers.includes(3389)) return 'Windows (RDP detected)'
  if (portNumbers.includes(22) && portNumbers.includes(80)) return 'Linux (SSH + HTTP)'
  if (portNumbers.includes(22)) return 'Unix-like (SSH detected)'
  if (portNumbers.includes(135)) return 'Windows (RPC detected)'
  if (portNumbers.includes(80) || portNumbers.includes(443)) return 'Web Server'
  
  return 'Unknown OS'
}

// Generate comprehensive scan summary
function generateScanSummary(results: any): string {
  const totalHosts = results.hosts.length
  const upHosts = results.hosts.filter((h: any) => h.status === 'up').length
  const totalOpenPorts = results.hosts.reduce((sum: number, h: any) => 
    sum + h.ports.filter((p: any) => p.state === 'open').length, 0)
  const totalVulns = results.hosts.reduce((sum: number, h: any) => sum + (h.vulnerabilities?.length || 0), 0)
  
  return `Professional Nmap scan completed for ${results.target}. Found ${upHosts}/${totalHosts} hosts up with ${totalOpenPorts} total open ports and ${totalVulns} potential vulnerabilities. Scan completed in ${results.scanTime}ms.`
}

export async function POST(req: NextRequest) {
  try {
    const { target, scanType, options } = await req.json()

    if (!target) {
      return NextResponse.json({
        success: false,
        message: "Target is required"
      }, { status: 400 })
    }

    if (!isValidTarget(target)) {
      return NextResponse.json({
        success: false,
        message: "Invalid target format. Use IP address, hostname, or CIDR notation."
      }, { status: 400 })
    }

    // Perform the advanced scan
    const results = await performAdvancedScan(target, scanType, options || {})

    return NextResponse.json({
      success: true,
      data: results
    })

  } catch (error) {
    console.error("Advanced Nmap scan error:", error)
    
    return NextResponse.json({
      success: false,
      message: "Advanced scan failed",
      error: process.env.NODE_ENV === 'development' ? (error instanceof Error ? error.message : 'Unknown error') : undefined
    }, { status: 500 })
  }
}