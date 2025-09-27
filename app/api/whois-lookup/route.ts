import { NextRequest, NextResponse } from 'next/server'

interface WhoisResult {
  domain: string
  registrar?: string
  registrationDate?: string
  expirationDate?: string
  lastUpdated?: string
  nameServers?: string[]
  status?: string[]
  registrant?: {
    name?: string
    organization?: string
    country?: string
    email?: string
    phone?: string
  }
  securityAnalysis: {
    domainAge: number
    riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    securityScore: number
    flags: string[]
    recommendations: string[]
  }
  businessInfo: {
    companyType: string
    industry: string
    trustScore: number
    publiclyTraded: boolean
    headquarters: string
  }
  technicalDetails: {
    dnsProvider: string
    cloudProvider?: string
    cdnUsage: boolean
    emailSecurity: {
      spfConfigured: boolean
      dmarcConfigured: boolean
      mxRecords: number
    }
  }
  domainHistory: {
    previousOwners: string[]
    transferHistory: Array<{date: string, action: string}>
    incidents: Array<{date: string, type: string, description: string}>
  }
  raw?: string
  status_code: 'success' | 'error'
  message?: string
  timestamp: string
}

// Utility function to validate domain
function isValidDomain(domain: string): boolean {
  const domainRegex = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$/
  return domainRegex.test(domain) && domain.length <= 253
}

// Simple WHOIS parser
function parseWhoisData(raw: string, domain: string): Partial<WhoisResult> {
  const lines = raw.split('\n').map(line => line.trim()).filter(line => line)
  const result: Partial<WhoisResult> = {}

  // Extract common fields
  for (const line of lines) {
    const lower = line.toLowerCase()
    
    // Registrar
    if ((lower.includes('registrar:') || lower.includes('registrar ')) && !result.registrar) {
      result.registrar = line.split(':').slice(1).join(':').trim()
    }
    
    // Creation date
    if ((lower.includes('creation date') || lower.includes('created') || lower.includes('registered')) && !result.registrationDate) {
      const dateMatch = line.match(/\d{4}-\d{2}-\d{2}/)
      if (dateMatch) result.registrationDate = dateMatch[0]
    }
    
    // Expiration date
    if ((lower.includes('expir') || lower.includes('expires')) && !result.expirationDate) {
      const dateMatch = line.match(/\d{4}-\d{2}-\d{2}/)
      if (dateMatch) result.expirationDate = dateMatch[0]
    }
    
    // Last updated
    if ((lower.includes('updated') || lower.includes('modified')) && !result.lastUpdated) {
      const dateMatch = line.match(/\d{4}-\d{2}-\d{2}/)
      if (dateMatch) result.lastUpdated = dateMatch[0]
    }
    
    // Name servers
    if (lower.includes('name server') || lower.includes('nserver')) {
      if (!result.nameServers) result.nameServers = []
      const ns = line.split(':').slice(1).join(':').trim().split(' ')[0]
      if (ns && !result.nameServers.includes(ns)) {
        result.nameServers.push(ns)
      }
    }
    
    // Status
    if (lower.includes('status') && lower.includes(':')) {
      if (!result.status) result.status = []
      const status = line.split(':').slice(1).join(':').trim()
      if (status && !result.status.includes(status)) {
        result.status.push(status)
      }
    }
  }

  return result
}

// Enhanced WHOIS analysis with security and business intelligence
function analyzeWhoisData(domain: string, registrationDate: string, registrant: any): {
  securityAnalysis: any,
  businessInfo: any,
  technicalDetails: any,
  domainHistory: any
} {
  const currentDate = new Date()
  const regDate = new Date(registrationDate)
  const domainAge = Math.floor((currentDate.getTime() - regDate.getTime()) / (1000 * 60 * 60 * 24))
  
  // Security Analysis
  const securityFlags = []
  let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL' = 'LOW'
  let securityScore = 85
  
  // Domain age analysis
  if (domainAge < 30) {
    securityFlags.push('Very new domain (less than 30 days old)')
    riskLevel = 'HIGH'
    securityScore -= 40
  } else if (domainAge < 365) {
    securityFlags.push('Recently registered domain (less than 1 year old)')
    riskLevel = 'MEDIUM'
    securityScore -= 20
  } else if (domainAge > 10 * 365) {
    securityFlags.push('Well-established domain (over 10 years old)')
    securityScore += 10
  }
  
  // Registrant analysis
  if (registrant?.name === 'Privacy Protected' || registrant?.organization?.includes('Privacy')) {
    securityFlags.push('Domain privacy protection enabled')
    securityScore -= 5
  }
  
  // Known secure domains
  const trustedDomains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com', 'github.com']
  const isTrusted = trustedDomains.includes(domain)
  if (isTrusted) {
    securityFlags.push('Recognized as trusted corporate domain')
    securityScore += 15
  }
  
  // Business Information Analysis
  const businessInfo = {
    companyType: 'Unknown',
    industry: 'Technology',
    trustScore: 85,
    publiclyTraded: false,
    headquarters: registrant?.country || 'Unknown'
  }
  
  if (domain === 'google.com' || domain === 'microsoft.com' || domain === 'apple.com' || domain === 'amazon.com') {
    businessInfo.companyType = 'Public Corporation'
    businessInfo.publiclyTraded = true
    businessInfo.trustScore = 98
    businessInfo.headquarters = 'United States'
  } else if (domain === 'github.com') {
    businessInfo.companyType = 'Technology Platform'
    businessInfo.industry = 'Software Development'
    businessInfo.trustScore = 92
    businessInfo.headquarters = 'United States'
  }
  
  // Technical Details Analysis
  const technicalDetails = {
    dnsProvider: 'Unknown',
    cloudProvider: undefined as string | undefined,
    cdnUsage: false,
    emailSecurity: {
      spfConfigured: false,
      dmarcConfigured: false,
      mxRecords: 0
    }
  }
  
  // DNS provider detection
  if (domain.includes('google.com')) {
    technicalDetails.dnsProvider = 'Google Cloud DNS'
    technicalDetails.cloudProvider = 'Google Cloud Platform'
    technicalDetails.cdnUsage = true
  } else if (domain.includes('microsoft.com')) {
    technicalDetails.dnsProvider = 'Azure DNS'
    technicalDetails.cloudProvider = 'Microsoft Azure'
    technicalDetails.cdnUsage = true
  } else if (domain.includes('github.com')) {
    technicalDetails.dnsProvider = 'NS1'
    technicalDetails.cloudProvider = 'Multiple (AWS, Azure, GCP)'
    technicalDetails.cdnUsage = true
  }
  
  // Domain History (simulated)
  const domainHistory = {
    previousOwners: [] as string[],
    transferHistory: [] as Array<{date: string, action: string}>,
    incidents: [] as Array<{date: string, type: string, description: string}>
  }
  
  if (domainAge > 2 * 365) {
    domainHistory.transferHistory.push({
      date: '2022-01-15',
      action: 'Domain registration renewed'
    })
    
    if (isTrusted) {
      domainHistory.incidents.push({
        date: '2021-03-10',
        type: 'Security Enhancement',
        description: 'Enhanced DNS security measures implemented'
      })
    }
  }
  
  const recommendations = []
  if (domainAge < 90) {
    recommendations.push('⚠️ Recently registered domain - verify legitimacy before trusting')
  }
  if (!isTrusted && registrant?.name === 'Privacy Protected') {
    recommendations.push('🔍 Privacy-protected registration - additional verification recommended')
  }
  recommendations.push('🛡️ Monitor domain for any suspicious activity or changes')
  recommendations.push('📧 Verify email security configurations (SPF, DMARC)')
  recommendations.push('🔒 Enable domain monitoring and SSL certificate tracking')
  
  return {
    securityAnalysis: {
      domainAge,
      riskLevel,
      securityScore: Math.max(0, Math.min(100, securityScore)),
      flags: securityFlags,
      recommendations
    },
    businessInfo,
    technicalDetails,
    domainHistory
  }
}

// Mock WHOIS data for demonstration (since real WHOIS requires external services)
function getMockWhoisData(domain: string): WhoisResult {
  const mockData: Record<string, Partial<WhoisResult>> = {
    'google.com': {
      registrar: 'MarkMonitor Inc.',
      registrationDate: '1997-09-15',
      expirationDate: '2028-09-14',
      lastUpdated: '2019-09-09',
      nameServers: ['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com'],
      status: ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited', 'serverDeleteProhibited', 'serverTransferProhibited', 'serverUpdateProhibited'],
      registrant: {
        name: 'Google LLC',
        organization: 'Google LLC',
        country: 'US',
        email: 'dns-admin@google.com',
        phone: '+1.6506234000'
      }
    },
    'github.com': {
      registrar: 'MarkMonitor Inc.',
      registrationDate: '2007-10-09',
      expirationDate: '2024-10-09',
      lastUpdated: '2023-09-07',
      nameServers: ['dns1.p08.nsone.net', 'dns2.p08.nsone.net', 'dns3.p08.nsone.net', 'dns4.p08.nsone.net'],
      status: ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited'],
      registrant: {
        name: 'GitHub, Inc.',
        organization: 'GitHub, Inc.',
        country: 'US',
        email: 'hostmaster@github.com',
        phone: '+1.4155522700'
      }
    },
    'microsoft.com': {
      registrar: 'MarkMonitor Inc.',
      registrationDate: '1991-05-02',
      expirationDate: '2025-05-03',
      lastUpdated: '2023-04-26',
      nameServers: ['ns1-205.azure-dns.com', 'ns2-205.azure-dns.net', 'ns3-205.azure-dns.org', 'ns4-205.azure-dns.info'],
      status: ['clientDeleteProhibited', 'clientTransferProhibited', 'clientUpdateProhibited'],
      registrant: {
        name: 'Microsoft Corporation',
        organization: 'Microsoft Corporation',
        country: 'US',
        email: 'msnhst@microsoft.com',
        phone: '+1.4258828080'
      }
    }
  }

  const mock = mockData[domain]
  if (mock) {
    const registrationDate = mock.registrationDate || '2020-01-01'
    const analysis = analyzeWhoisData(domain, registrationDate, mock.registrant)
    
    return {
      domain,
      status_code: 'success',
      timestamp: new Date().toISOString(),
      ...mock,
      ...analysis
    } as WhoisResult
  }

  // Generic response for other domains
  const genericRegistrationDate = '2020-01-01'
  const genericRegistrant = {
    name: 'Privacy Protected',
    organization: 'Private Whois Service',
    country: 'US'
  }
  const genericAnalysis = analyzeWhoisData(domain, genericRegistrationDate, genericRegistrant)

  return {
    domain,
    status_code: 'success',
    timestamp: new Date().toISOString(),
    registrar: 'Unknown Registrar',
    registrationDate: genericRegistrationDate,
    expirationDate: '2025-01-01',
    lastUpdated: '2023-01-01',
    nameServers: ['ns1.example.com', 'ns2.example.com'],
    status: ['clientTransferProhibited'],
    registrant: genericRegistrant,
    ...genericAnalysis,
    message: 'This is demo data. Real WHOIS lookups require external API services.'
  }
}

export async function POST(request: NextRequest) {
  try {
    const { domain } = await request.json()

    if (!domain || typeof domain !== 'string') {
      return NextResponse.json({
        status_code: 'error',
        message: 'Domain is required and must be a string'
      }, { status: 400 })
    }

    const cleanDomain = domain.trim().toLowerCase()

    if (!isValidDomain(cleanDomain)) {
      return NextResponse.json({
        status_code: 'error',
        message: 'Invalid domain format'
      }, { status: 400 })
    }

    // For demonstration, we'll use mock data
    // In production, you would integrate with a WHOIS API service
    const result = getMockWhoisData(cleanDomain)

    return NextResponse.json(result)

  } catch (error) {
    console.error('WHOIS Lookup Error:', error)
    return NextResponse.json({
      status_code: 'error',
      message: 'An error occurred while performing the WHOIS lookup. Please try again.'
    }, { status: 500 })
  }
}

export async function GET() {
  return NextResponse.json({
    message: 'WHOIS Lookup API - Use POST method with domain parameter',
    example: {
      method: 'POST',
      body: {
        domain: 'example.com'
      }
    },
    note: 'This API currently uses demo data. For production use, integrate with a real WHOIS service.'
  })
}
