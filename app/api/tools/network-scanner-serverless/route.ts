import { NextRequest, NextResponse } from 'next/server'

export const dynamic = 'force-dynamic'

export async function POST(request: NextRequest) {
  try {
    const { target, scanType = 'discovery' } = await request.json()

    if (!target) {
      return NextResponse.json({
        success: false,
        message: 'Target is required'
      }, { status: 400 })
    }

    const startTime = Date.now()
    const cleanTarget = target.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].trim()

    // Serverless-friendly network discovery
    const results = {
      target: cleanTarget,
      scanType,
      hosts: [] as any[],
      summary: '',
      totalHosts: 0,
      executionTime: 0,
      timestamp: new Date().toISOString(),
      method: 'serverless-web-based',
      limitations: [
        'Serverless environment cannot perform traditional ping sweeps',
        'Using web-based discovery methods only',
        'Limited to HTTP/HTTPS service detection'
      ]
    }

    // For single host, check HTTP/HTTPS availability
    if (!target.includes('/') && !target.includes('-')) {
      const hostInfo = await checkSingleHost(cleanTarget)
      results.hosts.push(hostInfo)
      results.totalHosts = hostInfo.status === 'up' ? 1 : 0
    } else {
      // For ranges, provide informational response
      results.hosts.push({
        ip: cleanTarget,
        status: 'info',
        message: 'Network range scanning not supported in serverless environment',
        alternative: 'Use individual host scanning or dedicated network tools'
      })
    }

    results.executionTime = Date.now() - startTime
    results.summary = `Serverless network scan completed for ${cleanTarget}. Found ${results.totalHosts} responsive host(s).`

    return NextResponse.json({
      success: true,
      data: results
    })

  } catch (error) {
    console.error('Serverless network scanner error:', error)
    return NextResponse.json({
      success: false,
      message: 'Network scan failed',
      error: process.env.NODE_ENV === 'development' ? (error instanceof Error ? error.message : 'Unknown error') : undefined,
      serverlessNote: 'Traditional network scanning requires system-level access not available in serverless environments'
    }, { status: 500 })
  }
}

async function checkSingleHost(hostname: string) {
  const hostInfo: any = {
    ip: hostname,
    hostname: hostname,
    status: 'down',
    openPorts: [],
    services: [],
    responseTime: 0
  }

  const startTime = Date.now()

  try {
    // Check HTTPS first
    const httpsController = new AbortController()
    const httpsTimeout = setTimeout(() => httpsController.abort(), 5000)
    
    try {
      const httpsResponse = await fetch(`https://${hostname}`, {
        method: 'HEAD',
        signal: httpsController.signal
      })
      clearTimeout(httpsTimeout)
      
      hostInfo.status = 'up'
      hostInfo.openPorts.push(443)
      hostInfo.services.push({
        port: 443,
        service: 'HTTPS',
        status: httpsResponse.status,
        headers: Object.fromEntries(httpsResponse.headers.entries())
      })
    } catch (httpsError) {
      clearTimeout(httpsTimeout)
      
      // Try HTTP if HTTPS fails
      const httpController = new AbortController()
      const httpTimeout = setTimeout(() => httpController.abort(), 5000)
      
      try {
        const httpResponse = await fetch(`http://${hostname}`, {
          method: 'HEAD',
          signal: httpController.signal
        })
        clearTimeout(httpTimeout)
        
        hostInfo.status = 'up'
        hostInfo.openPorts.push(80)
        hostInfo.services.push({
          port: 80,
          service: 'HTTP',
          status: httpResponse.status,
          headers: Object.fromEntries(httpResponse.headers.entries())
        })
      } catch (httpError) {
        clearTimeout(httpTimeout)
        hostInfo.status = 'down'
        hostInfo.error = 'No HTTP/HTTPS response'
      }
    }

    hostInfo.responseTime = Date.now() - startTime

    // Try to get additional info via DNS
    try {
      const dnsResponse = await fetch(`https://dns.google/resolve?name=${hostname}&type=A`)
      if (dnsResponse.ok) {
        const dnsData = await dnsResponse.json()
        if (dnsData.Answer && dnsData.Answer.length > 0) {
          hostInfo.ip = dnsData.Answer[0].data
          hostInfo.dnsResolved = true
        }
      }
    } catch (dnsError) {
      // DNS lookup failed, continue without IP resolution
    }

  } catch (error) {
    hostInfo.status = 'error'
    hostInfo.error = error instanceof Error ? error.message : 'Unknown error'
  }

  return hostInfo
}

export async function GET() {
  return NextResponse.json({
    message: 'Serverless Network Scanner API',
    version: '1.0.0',
    status: 'operational',
    limitations: [
      'Cannot perform traditional ping sweeps in serverless environment',
      'Limited to HTTP/HTTPS service discovery',
      'No subnet scanning capabilities',
      'Uses web-based detection methods only'
    ],
    capabilities: [
      'Single host HTTP/HTTPS availability check',
      'Basic service detection',
      'DNS resolution',
      'Fast serverless execution'
    ],
    alternatives: [
      'Use dedicated network scanning tools for comprehensive results',
      'Run local network discovery tools',
      'Use cloud-based network monitoring services'
    ],
    usage: {
      method: 'POST',
      body: {
        target: 'example.com',
        scanType: 'discovery'
      }
    }
  })
}