import { NextRequest, NextResponse } from 'next/server'
import { spawn } from 'child_process'
import { promisify } from 'util'

// Helper function to validate IP range
function parseIPRange(range: string): string[] {
  const ips: string[] = []
  
  if (range.includes('/')) {
    // CIDR notation (e.g., 192.168.1.0/24)
    const [baseIP, subnetMask] = range.split('/')
    const subnet = parseInt(subnetMask)
    
    if (subnet < 8 || subnet > 30) {
      throw new Error('Subnet mask must be between /8 and /30')
    }
    
    const baseIPParts = baseIP.split('.').map(Number)
    const numHosts = Math.pow(2, 32 - subnet) - 2 // Exclude network and broadcast
    
    if (numHosts > 254) {
      throw new Error('IP range too large (max 254 hosts)')
    }
    
    // Generate IPs in the range
    for (let i = 1; i <= numHosts && i <= 254; i++) {
      const lastOctet = (baseIPParts[3] + i) % 256
      if (lastOctet !== 0 && lastOctet !== 255) { // Skip network and broadcast
        ips.push(`${baseIPParts[0]}.${baseIPParts[1]}.${baseIPParts[2]}.${lastOctet}`)
      }
    }
  } else if (range.includes('-')) {
    // Range notation (e.g., 192.168.1.1-192.168.1.10)
    const [startIP, endIP] = range.split('-')
    const startParts = startIP.split('.').map(Number)
    const endParts = endIP.split('.').map(Number)
    
    // Only support single octet range for now
    if (startParts.slice(0, 3).join('.') !== endParts.slice(0, 3).join('.')) {
      throw new Error('Range must be within the same subnet')
    }
    
    const start = startParts[3]
    const end = endParts[3]
    
    if (end - start > 254) {
      throw new Error('IP range too large (max 254 hosts)')
    }
    
    for (let i = start; i <= end; i++) {
      ips.push(`${startParts[0]}.${startParts[1]}.${startParts[2]}.${i}`)
    }
  } else {
    // Single IP
    if (!range.match(/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/)) {
      throw new Error('Invalid IP address format')
    }
    ips.push(range)
  }
  
  return ips
}

// Function to ping a single IP
function pingIP(ip: string, timeout: number = 3000): Promise<{ ip: string, alive: boolean, responseTime?: number, error?: string }> {
  return new Promise((resolve) => {
    const startTime = Date.now()
    const isWindows = process.platform === 'win32'
    const pingCmd = isWindows ? 'ping' : 'ping'
    const pingArgs = isWindows 
      ? ['-n', '1', '-w', timeout.toString(), ip]
      : ['-c', '1', '-W', Math.ceil(timeout / 1000).toString(), ip]
    
    const ping = spawn(pingCmd, pingArgs)
    let output = ''
    let errorOutput = ''
    
    ping.stdout.on('data', (data) => {
      output += data.toString()
    })
    
    ping.stderr.on('data', (data) => {
      errorOutput += data.toString()
    })
    
    ping.on('close', (code) => {
      const responseTime = Date.now() - startTime
      
      if (code === 0) {
        // Extract ping time from output
        let pingTime: number | undefined
        if (isWindows) {
          const match = output.match(/time[<=](\d+)ms/)
          pingTime = match ? parseInt(match[1]) : responseTime
        } else {
          const match = output.match(/time=(\d+\.?\d*) ms/)
          pingTime = match ? parseFloat(match[1]) : responseTime
        }
        
        resolve({
          ip,
          alive: true,
          responseTime: pingTime
        })
      } else {
        resolve({
          ip,
          alive: false,
          error: errorOutput || 'Host unreachable'
        })
      }
    })
    
    ping.on('error', (error) => {
      resolve({
        ip,
        alive: false,
        error: error.message
      })
    })
  })
}

export async function POST(request: NextRequest) {
  try {
    const { target, timeout } = await request.json()
    
    if (!target) {
      return NextResponse.json({
        success: false,
        message: 'Target IP range is required'
      }, { status: 400 })
    }

    const pingTimeout = timeout || 3000
    const startTime = Date.now()

    // Parse IP range
    let targetIPs: string[]
    try {
      targetIPs = parseIPRange(target.trim())
    } catch (error) {
      return NextResponse.json({
        success: false,
        message: error instanceof Error ? error.message : 'Invalid IP range format'
      }, { status: 400 })
    }

    if (targetIPs.length === 0) {
      return NextResponse.json({
        success: false,
        message: 'No valid IPs in range'
      }, { status: 400 })
    }

    // Limit concurrent pings to avoid overwhelming the system
    const concurrencyLimit = 20
    const results: any[] = []
    
    for (let i = 0; i < targetIPs.length; i += concurrencyLimit) {
      const batch = targetIPs.slice(i, i + concurrencyLimit)
      const batchResults = await Promise.all(
        batch.map(ip => pingIP(ip, pingTimeout))
      )
      results.push(...batchResults)
    }

    const executionTime = Date.now() - startTime
    const aliveHosts = results.filter(r => r.alive)
    const deadHosts = results.filter(r => !r.alive)

    // Get additional info for alive hosts
    const hostsWithDetails = await Promise.all(
      aliveHosts.map(async (host) => {
        try {
          // Try to get hostname via reverse DNS
          const controller = new AbortController()
          const timeoutId = setTimeout(() => controller.abort(), 2000)
          
          // We can't do reverse DNS directly in Node.js without additional packages
          // For now, we'll just return the IP info
          return {
            ...host,
            hostname: null,
            ports: [] // Could add port scanning here later
          }
        } catch (error) {
          return {
            ...host,
            hostname: null,
            ports: []
          }
        }
      })
    )

    const result = {
      target,
      totalHosts: targetIPs.length,
      aliveHosts: aliveHosts.length,
      deadHosts: deadHosts.length,
      hosts: {
        alive: hostsWithDetails,
        dead: deadHosts
      },
      summary: `Ping sweep completed: ${aliveHosts.length}/${targetIPs.length} hosts are alive`,
      statistics: {
        totalScanned: targetIPs.length,
        aliveCount: aliveHosts.length,
        deadCount: deadHosts.length,
        successRate: Math.round((aliveHosts.length / targetIPs.length) * 100),
        averageResponseTime: aliveHosts.length > 0 
          ? Math.round(aliveHosts.reduce((sum, host) => sum + (host.responseTime || 0), 0) / aliveHosts.length)
          : 0
      },
      executionTime,
      timestamp: new Date().toISOString()
    }

    return NextResponse.json({
      success: true,
      data: result
    })

  } catch (error) {
    console.error('Ping sweep error:', error)
    return NextResponse.json({
      success: false,
      message: 'Internal server error during ping sweep',
      error: process.env.NODE_ENV === 'development' ? (error instanceof Error ? error.message : 'Unknown error') : undefined
    }, { status: 500 })
  }
}