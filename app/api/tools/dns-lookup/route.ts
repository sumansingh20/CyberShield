import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const { domain, recordType } = await request.json()
    
    if (!domain) {
      return NextResponse.json({
        success: false,
        message: 'Domain is required'
      }, { status: 400 })
    }

    // Clean the domain name
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].trim()
    const lookupType = recordType || 'ALL'
    
    const startTime = Date.now()
    
    // DNS record types to lookup
    const recordTypes = lookupType === 'ALL' 
      ? ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA']
      : [lookupType]

    // ONLY perform real DNS lookups - NO mock data allowed
    const lookupPromises = recordTypes.map(async (type) => {
      try {
        // Use DNS over HTTPS (DoH) with multiple providers for reliability
        let dohResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${cleanDomain}&type=${type}`, {
          headers: {
            'Accept': 'application/dns-json',
            'User-Agent': 'CyberShield-DNS-Tool/1.0'
          },
          signal: AbortSignal.timeout(10000)
        })

        if (!dohResponse.ok) {
          // Fallback to Google DNS
          dohResponse = await fetch(`https://dns.google/resolve?name=${cleanDomain}&type=${type}`, {
            headers: {
              'Accept': 'application/dns-json',
              'User-Agent': 'CyberShield-DNS-Tool/1.0'
            },
            signal: AbortSignal.timeout(10000)
          })
        }

        if (!dohResponse.ok) {
          // Try Quad9 DNS as third fallback
          dohResponse = await fetch(`https://dns.quad9.net:5053/dns-query?name=${cleanDomain}&type=${type}`, {
            headers: {
              'Accept': 'application/dns-json',
              'User-Agent': 'CyberShield-DNS-Tool/1.0'
            },
            signal: AbortSignal.timeout(10000)
          })
        }

        if (!dohResponse.ok) {
          return { type, records: [], error: `DNS query failed for ${type} record` }
        }

        const dnsData = await dohResponse.json()
        
        if (dnsData.Answer) {
          return {
            type,
            records: dnsData.Answer.map((answer: any) => ({
              name: answer.name,
              type: answer.type,
              ttl: answer.TTL,
              data: answer.data,
              priority: answer.type === 15 ? parseInt(answer.data.split(' ')[0]) : undefined
            }))
          }
        } else {
          return { type, records: [] }
        }
      } catch (error) {
        return { 
          type, 
          records: [], 
          error: error instanceof Error ? error.message : 'DNS lookup timeout'
        }
      }
    })

    const dnsResults = await Promise.all(lookupPromises)
    
    // Organize results
    const results: any = {
      domain: cleanDomain,
      recordType: lookupType,
      records: {} as any,
      isRealData: true,
      executionTime: Date.now() - startTime,
      timestamp: new Date().toISOString(),
      errors: [] as string[],
      securityAnalysis: {},
      geolocation: [],
      summary: ''
    }
    
    let totalRecords = 0
    for (const result of dnsResults) {
      results.records[result.type] = result.records || []
      totalRecords += result.records?.length || 0
      if (result.error) {
        results.errors.push(`${result.type}: ${result.error}`)
      }
    }

    // Enhanced security analysis
    const securityChecks = {
      hasSPF: false,
      hasDMARC: false,
      hasDKIM: false,
      hasCAA: false,
      dnssecEnabled: false,
      securityScore: 0
    }

    // Analyze TXT records for email security
    if (results.records.TXT && results.records.TXT.length > 0) {
      for (const record of results.records.TXT) {
        const data = record.data.toLowerCase()
        if (data.includes('v=spf1')) {
          securityChecks.hasSPF = true
          securityChecks.securityScore += 20
        }
        if (data.includes('v=dmarc1')) {
          securityChecks.hasDMARC = true
          securityChecks.securityScore += 25
        }
        if (data.includes('v=dkim1')) {
          securityChecks.hasDKIM = true
          securityChecks.securityScore += 15
        }
      }
    }

    // Check for CAA records (already included in main lookup)
    if (results.records.CAA && results.records.CAA.length > 0) {
      securityChecks.hasCAA = true
      securityChecks.securityScore += 20
    }

    // Check DNSSEC status
    try {
      const dnssecResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${cleanDomain}&type=DNSKEY&do=1`, {
        headers: { 'Accept': 'application/dns-json' },
        signal: AbortSignal.timeout(5000)
      })
      
      if (dnssecResponse.ok) {
        const dnssecData = await dnssecResponse.json()
        if (dnssecData.Answer && dnssecData.Answer.length > 0) {
          securityChecks.dnssecEnabled = true
          securityChecks.securityScore += 20
        }
      }
    } catch (error) {
      // DNSSEC check failed - not critical
    }

    // Get geolocation data for IP addresses
    const geoData = []
    if (results.records.A && results.records.A.length > 0) {
      for (const record of results.records.A.slice(0, 3)) { // Limit to 3 IPs
        try {
          const geoResponse = await fetch(`http://ip-api.com/json/${record.data}?fields=status,message,country,regionName,city,isp,org,as,query`, {
            signal: AbortSignal.timeout(3000)
          })
          
          if (geoResponse.ok) {
            const geo = await geoResponse.json()
            if (geo.status === 'success') {
              geoData.push({
                ip: record.data,
                country: geo.country,
                region: geo.regionName,
                city: geo.city,
                isp: geo.isp,
                org: geo.org,
                as: geo.as
              })
            }
          }
        } catch (error) {
          // Geolocation failed for this IP - continue
        }
      }
    }

    results.securityAnalysis = securityChecks
    results.geolocation = geoData

    // Generate comprehensive summary
    const recordCounts = Object.entries(results.records)
      .filter(([_, records]) => Array.isArray(records) && records.length > 0)
      .map(([type, records]) => `${(records as any[]).length} ${type}`)
      .join(', ')
    
    const securityRating = securityChecks.securityScore >= 60 ? 'Good' : 
                          securityChecks.securityScore >= 30 ? 'Fair' : 'Poor'
    
    results.summary = totalRecords > 0 
      ? `Found ${totalRecords} DNS records (${recordCounts}). Security rating: ${securityRating} (${securityChecks.securityScore}/100)`
      : 'No DNS records found for the specified domain'

    return NextResponse.json({
      success: true,
      data: results
    })

  } catch (error) {
    console.error('DNS lookup error:', error)
    return NextResponse.json({
      success: false,
      message: 'DNS lookup failed',
      error: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}

export async function GET() {
  return NextResponse.json({
    message: 'Professional DNS Lookup API - Real DNS queries only',
    example: {
      method: 'POST',
      body: {
        domain: 'example.com',
        recordType: 'ALL' // or specific type like 'A', 'MX', etc.
      }
    },
    supportedRecordTypes: ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SOA', 'CAA', 'ALL'],
    features: [
      'Real DNS over HTTPS queries',
      'Multiple DNS provider fallbacks',
      'Security analysis (SPF, DMARC, DKIM, CAA, DNSSEC)',
      'IP geolocation',
      'Performance metrics',
      'Professional security scoring'
    ],
    note: 'This tool performs ONLY real DNS lookups with comprehensive security analysis. No mock or demonstration data.'
  })
}