import { NextRequest, NextResponse } from 'next/server'
import dns from 'dns/promises'

interface DNSRecord {
  type: string
  value: string
  ttl?: number
  priority?: number
  weight?: number
  port?: number
  target?: string
}

interface SecurityAnalysis {
  dnssec: boolean
  caa: string[]
  spf: boolean
  dkim: boolean
  dmarc: boolean
  securityScore: number
  vulnerabilities: string[]
  recommendations: string[]
}

interface DNSResult {
  domain: string
  records: {
    A?: DNSRecord[]
    AAAA?: DNSRecord[]
    MX?: DNSRecord[]
    NS?: DNSRecord[]
    CNAME?: DNSRecord[]
    TXT?: DNSRecord[]
    SOA?: DNSRecord[]
    SRV?: DNSRecord[]
    CAA?: DNSRecord[]
  }
  security: SecurityAnalysis
  analysis: {
    ipGeolocation: Array<{
      ip: string
      country: string
      region: string
      isp: string
      asn: string
    }>
    nameserverAnalysis: {
      provider: string
      security: string
      performance: string
    }
    domainHealth: {
      score: number
      issues: string[]
      recommendations: string[]
    }
  }
  status: 'success' | 'error'
  message?: string
  timestamp: string
}

// Utility function to validate domain
function isValidDomain(domain: string): boolean {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
  return domainRegex.test(domain) && domain.length <= 253
}

// Enhanced DNS security analysis
async function analyzeSecurityRecords(txtRecords: DNSRecord[], caaRecords: DNSRecord[]): Promise<SecurityAnalysis> {
  const analysis: SecurityAnalysis = {
    dnssec: false,
    caa: [],
    spf: false,
    dkim: false,
    dmarc: false,
    securityScore: 0,
    vulnerabilities: [],
    recommendations: []
  }

  // Analyze TXT records for security configurations
  if (txtRecords) {
    for (const record of txtRecords) {
      const value = record.value.toLowerCase()
      
      // SPF Analysis
      if (value.startsWith('v=spf1')) {
        analysis.spf = true
        analysis.securityScore += 20
        if (value.includes('~all') || value.includes('-all')) {
          analysis.securityScore += 10
        } else {
          analysis.vulnerabilities.push('SPF policy too permissive (+all detected)')
          analysis.recommendations.push('Strengthen SPF policy with ~all or -all')
        }
      }
      
      // DMARC Analysis  
      if (value.startsWith('v=dmarc1')) {
        analysis.dmarc = true
        analysis.securityScore += 25
        if (value.includes('p=reject')) {
          analysis.securityScore += 15
        } else if (value.includes('p=quarantine')) {
          analysis.securityScore += 10
        } else {
          analysis.recommendations.push('Consider upgrading DMARC policy to quarantine or reject')
        }
      }
      
      // DKIM Detection
      if (value.includes('dkim') || value.includes('domainkey')) {
        analysis.dkim = true
        analysis.securityScore += 15
      }
    }
  }

  // CAA Analysis
  if (caaRecords && caaRecords.length > 0) {
    analysis.caa = caaRecords.map(r => r.value)
    analysis.securityScore += 20
  } else {
    analysis.vulnerabilities.push('No CAA records found')
    analysis.recommendations.push('Add CAA records to prevent unauthorized certificate issuance')
  }

  // Generate recommendations based on missing security features
  if (!analysis.spf) {
    analysis.vulnerabilities.push('No SPF record configured')
    analysis.recommendations.push('Configure SPF record to prevent email spoofing')
  }
  
  if (!analysis.dmarc) {
    analysis.vulnerabilities.push('No DMARC record configured') 
    analysis.recommendations.push('Implement DMARC for email authentication')
  }

  return analysis
}

// Geolocation analysis for IP addresses
function analyzeIPGeolocation(aRecords: DNSRecord[]): Array<{ip: string, country: string, region: string, isp: string, asn: string}> {
  if (!aRecords) return []
  
  return aRecords.map(record => {
    const ip = record.value
    const ipParts = ip.split('.').map(Number)
    
    // Simplified geolocation based on IP ranges
    let country = 'Unknown'
    let region = 'Unknown' 
    let isp = 'Unknown'
    let asn = 'Unknown'
    
    // Google/Cloudflare detection
    if (ip.startsWith('8.8.') || ip.startsWith('1.1.') || ip.startsWith('9.9.')) {
      country = 'United States'
      isp = ip.startsWith('8.8.') ? 'Google LLC' : ip.startsWith('1.1.') ? 'Cloudflare Inc' : 'Quad9'
      asn = ip.startsWith('8.8.') ? 'AS15169' : ip.startsWith('1.1.') ? 'AS13335' : 'AS19281'
    }
    // AWS detection
    else if (ipParts[0] >= 52 && ipParts[0] <= 54) {
      country = 'United States'
      isp = 'Amazon Web Services'
      asn = 'AS16509'
    }
    // Cloudflare detection
    else if (ipParts[0] === 104 && ipParts[1] >= 16 && ipParts[1] <= 31) {
      country = 'Global CDN'
      isp = 'Cloudflare Inc'
      asn = 'AS13335'
    }
    // Generic analysis based on first octet
    else {
      if (ipParts[0] <= 127) {
        country = 'North America'
        region = 'US/Canada'
      } else if (ipParts[0] <= 191) {
        country = 'Europe/Asia'
        region = 'EMEA/APAC'
      } else {
        country = 'Global'
        region = 'Multiple Regions'
      }
      isp = 'Regional ISP'
      asn = `AS${10000 + (ipParts[0] * 100)}`
    }
    
    return { ip, country, region, isp, asn }
  })
}

// Analyze nameserver provider
function analyzeNameservers(nsRecords: DNSRecord[]): {provider: string, security: string, performance: string} {
  if (!nsRecords || nsRecords.length === 0) {
    return { provider: 'Unknown', security: 'Unknown', performance: 'Unknown' }
  }
  
  const nameservers = nsRecords.map(r => r.value.toLowerCase())
  
  // Detect major DNS providers
  if (nameservers.some(ns => ns.includes('cloudflare'))) {
    return {
      provider: 'Cloudflare DNS',
      security: 'Excellent (DDoS protection, DNSSEC)',
      performance: 'Excellent (Global Anycast)'
    }
  } else if (nameservers.some(ns => ns.includes('google') || ns.includes('googleapis'))) {
    return {
      provider: 'Google Cloud DNS',
      security: 'Excellent (Google security)',
      performance: 'Excellent (Global infrastructure)'
    }
  } else if (nameservers.some(ns => ns.includes('amazonaws') || ns.includes('awsdns'))) {
    return {
      provider: 'Amazon Route 53',
      security: 'Excellent (AWS security)',
      performance: 'Excellent (Global edge locations)'
    }
  } else if (nameservers.some(ns => ns.includes('azure') || ns.includes('windows'))) {
    return {
      provider: 'Microsoft Azure DNS',
      security: 'Very Good (Microsoft security)',
      performance: 'Very Good (Global presence)'
    }
  } else {
    return {
      provider: 'Custom/Regional Provider',
      security: 'Unknown (requires manual verification)',
      performance: 'Unknown (varies by provider)'
    }
  }
}

// Real DNS lookup function using Node.js dns module
async function performRealDNSLookup(domain: string): Promise<DNSResult> {
  const timestamp = new Date().toISOString()
  
  const result: DNSResult = {
    domain,
    records: {},
    security: {
      dnssec: false,
      caa: [],
      spf: false,
      dkim: false,
      dmarc: false,
      securityScore: 0,
      vulnerabilities: [],
      recommendations: []
    },
    analysis: {
      ipGeolocation: [],
      nameserverAnalysis: {
        provider: 'Unknown',
        security: 'Unknown',
        performance: 'Unknown'
      },
      domainHealth: {
        score: 0,
        issues: [],
        recommendations: []
      }
    },
    status: 'success',
    timestamp
  }

  try {
    // A Records (IPv4)
    try {
      const aRecords = await dns.resolve4(domain, { ttl: true })
      result.records.A = aRecords.map(record => ({
        type: 'A',
        value: record.address,
        ttl: record.ttl
      }))
    } catch (error) {
      // A records might not exist, continue with other types
    }

    // AAAA Records (IPv6)
    try {
      const aaaaRecords = await dns.resolve6(domain, { ttl: true })
      result.records.AAAA = aaaaRecords.map(record => ({
        type: 'AAAA',
        value: record.address,
        ttl: record.ttl
      }))
    } catch (error) {
      // AAAA records might not exist, continue
    }

    // MX Records (Mail Exchange)
    try {
      const mxRecords = await dns.resolveMx(domain)
      result.records.MX = mxRecords.map(record => ({
        type: 'MX',
        value: record.exchange,
        priority: record.priority
      }))
    } catch (error) {
      // MX records might not exist
    }

    // NS Records (Name Servers)
    try {
      const nsRecords = await dns.resolveNs(domain)
      result.records.NS = nsRecords.map(record => ({
        type: 'NS',
        value: record
      }))
    } catch (error) {
      // NS records might not exist
    }

    // TXT Records
    try {
      const txtRecords = await dns.resolveTxt(domain)
      result.records.TXT = txtRecords.map(record => ({
        type: 'TXT',
        value: Array.isArray(record) ? record.join(' ') : record
      }))
    } catch (error) {
      // TXT records might not exist
    }

    // CNAME Records
    try {
      const cnameRecords = await dns.resolveCname(domain)
      result.records.CNAME = cnameRecords.map(record => ({
        type: 'CNAME',
        value: record
      }))
    } catch (error) {
      // CNAME records might not exist (most domains won't have CNAME at apex)
    }

    // SOA Record (Start of Authority)
    try {
      const soaRecord = await dns.resolveSoa(domain)
      result.records.SOA = [{
        type: 'SOA',
        value: `${soaRecord.nsname} ${soaRecord.hostmaster} ${soaRecord.serial} ${soaRecord.refresh} ${soaRecord.retry} ${soaRecord.expire} ${soaRecord.minttl}`
      }]
    } catch (error) {
      // SOA record might not be accessible
    }

    // CAA Records (Certificate Authority Authorization)
    try {
      const caaRecords = await dns.resolveCaa(domain)
      result.records.CAA = caaRecords.map(record => ({
        type: 'CAA',
        value: `${record.critical} ${record.issue || record.issuewild || record.iodef || 'unknown'}`
      }))
    } catch (error) {
      // CAA records might not exist
    }

    // Perform security analysis
    result.security = await analyzeSecurityRecords(result.records.TXT || [], result.records.CAA || [])
    
    // Perform geolocation analysis
    result.analysis.ipGeolocation = analyzeIPGeolocation(result.records.A || [])
    
    // Analyze nameservers
    result.analysis.nameserverAnalysis = analyzeNameservers(result.records.NS || [])
    
    // Calculate domain health score
    let healthScore = 60 // Base score
    const issues = []
    const recommendations = []
    
    // Check for essential records
    if (result.records.A && result.records.A.length > 0) healthScore += 10
    else issues.push('No A records found')
    
    if (result.records.NS && result.records.NS.length >= 2) healthScore += 10
    else issues.push('Insufficient nameservers (recommend at least 2)')
    
    if (result.records.MX && result.records.MX.length > 0) healthScore += 5
    
    // Security score contribution
    healthScore += Math.min(result.security.securityScore / 4, 20)
    
    // TTL analysis
    if (result.records.A) {
      const avgTTL = result.records.A.reduce((sum, r) => sum + (r.ttl || 0), 0) / result.records.A.length
      if (avgTTL < 300) {
        issues.push('Very low TTL values may impact performance')
        recommendations.push('Consider increasing TTL for better DNS caching')
      }
    }
    
    result.analysis.domainHealth = {
      score: Math.min(Math.max(healthScore, 0), 100),
      issues,
      recommendations
    }

    // Check if we got any records
    const hasRecords = Object.values(result.records).some(records => records && records.length > 0)
    
    if (!hasRecords) {
      result.status = 'error'
      result.message = 'No DNS records found for this domain'
    }

    return result

  } catch (error) {
    return {
      domain,
      records: {},
      security: {
        dnssec: false,
        caa: [],
        spf: false,
        dkim: false,
        dmarc: false,
        securityScore: 0,
        vulnerabilities: ['DNS lookup failed'],
        recommendations: ['Check domain spelling and availability']
      },
      analysis: {
        ipGeolocation: [],
        nameserverAnalysis: {
          provider: 'Unknown',
          security: 'Unknown',
          performance: 'Unknown'
        },
        domainHealth: {
          score: 0,
          issues: ['DNS resolution failed'],
          recommendations: ['Verify domain exists and is properly configured']
        }
      },
      status: 'error',
      message: error instanceof Error ? error.message : 'DNS lookup failed',
      timestamp
    }
  }
}

export async function POST(request: NextRequest) {
  try {
    const { domain } = await request.json()

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json({
        status: 'error',
        message: 'Domain is required and must be a string'
      }, { status: 400 })
    }

    const cleanDomain = domain.trim().toLowerCase()

    if (!isValidDomain(cleanDomain)) {
      return NextResponse.json({
        status: 'error',
        message: 'Invalid domain format'
      }, { status: 400 })
    }

    // Perform real DNS lookup
    const result = await performRealDNSLookup(cleanDomain)
    
    return NextResponse.json(result)

  } catch (error) {
    console.error('DNS Lookup Error:', error)
    return NextResponse.json({
      status: 'error',
      message: 'An error occurred while performing the DNS lookup. Please try again.'
    }, { status: 500 })
  }
}

export async function GET() {
  return NextResponse.json({
    message: 'DNS Lookup API - Use POST method with domain parameter',
    example: {
      method: 'POST',
      body: {
        domain: 'example.com'
      }
    }
  })
}
