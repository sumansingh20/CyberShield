import { NextRequest, NextResponse } from 'next/server'

export const dynamic = "force-dynamic"

// Serverless-compatible subdomain enumeration
async function handleServerlessSubdomainEnum(domain: string, scanType: string) {
  const startTime = Date.now()
  const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].trim()
  
  // Common subdomains list for serverless enumeration
  const commonSubdomains = [
    'www', 'api', 'admin', 'dev', 'staging', 'test', 'mail', 'ftp', 'blog', 'shop',
    'app', 'portal', 'dashboard', 'login', 'secure', 'vpn', 'remote', 'support',
    'help', 'docs', 'cdn', 'static', 'assets', 'media', 'images', 'files',
    'mobile', 'm', 'beta', 'alpha', 'demo', 'sandbox', 'old', 'new', 'v1', 'v2'
  ]

  const foundSubdomains: SubdomainDetail[] = []
  const scanPromises = commonSubdomains.map(async (sub) => {
    const fullSubdomain = `${sub}.${cleanDomain}`
    
    try {
      // Try DNS resolution using DoH (DNS over HTTPS)
      const dnsResponse = await fetch(`https://dns.google/resolve?name=${fullSubdomain}&type=A`, {
        signal: AbortSignal.timeout(5000)
      })
      
      if (dnsResponse.ok) {
        const dnsData = await dnsResponse.json()
        if (dnsData.Answer && dnsData.Answer.length > 0) {
          const ips = dnsData.Answer.map((answer: any) => answer.data)
          
          // Check if subdomain is accessible via HTTP/HTTPS
          let httpStatus: number | null = null
          let isHttps = false
          let title: string | undefined
          
          try {
            // Try HTTPS first
            const httpsResponse = await fetch(`https://${fullSubdomain}`, {
              method: 'HEAD',
              signal: AbortSignal.timeout(5000)
            })
            httpStatus = httpsResponse.status
            isHttps = true
            
            // Get page title if accessible
            if (httpsResponse.ok) {
              try {
                const pageResponse = await fetch(`https://${fullSubdomain}`, {
                  signal: AbortSignal.timeout(3000)
                })
                const html = await pageResponse.text()
                const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i)
                if (titleMatch) {
                  title = titleMatch[1].trim().substring(0, 100) // Limit title length
                }
              } catch {
                // Page content fetch failed, continue
              }
            }
          } catch {
            // Try HTTP if HTTPS fails
            try {
              const httpResponse = await fetch(`http://${fullSubdomain}`, {
                method: 'HEAD',
                signal: AbortSignal.timeout(5000)
              })
              httpStatus = httpResponse.status
              isHttps = false
            } catch {
              // HTTP also failed, but subdomain exists in DNS
              httpStatus = null
            }
          }

          const subdomainDetail: SubdomainDetail = {
            subdomain: fullSubdomain,
            ips,
            cnames: [], // CNAME lookup would require additional DNS queries
            httpStatus,
            isHttps,
            title,
            discoveryMethod: 'dns-web-check',
            lastSeen: new Date().toISOString()
          }

          // Add security analysis
          subdomainDetail.securityAnalysis = analyzeSubdomainSecurity(fullSubdomain, subdomainDetail)
          
          return subdomainDetail
        }
      }
    } catch (error) {
      // DNS resolution or HTTP check failed
      return null
    }
    
    return null
  })

  // Wait for all subdomain checks to complete
  const results = await Promise.all(scanPromises)
  const validSubdomains = results.filter((result): result is SubdomainDetail => result !== null)

  const totalTime = Date.now() - startTime

  return NextResponse.json({
    success: true,
    data: {
      domain: cleanDomain,
      scanType: 'serverless-dns-web',
      totalSubdomains: validSubdomains.length,
      subdomains: validSubdomains,
      executionTime: totalTime,
      timestamp: new Date().toISOString(),
      serverlessMode: true,
      limitations: [
        'Serverless environment limits to DNS-based discovery',
        'Cannot perform advanced techniques like certificate transparency logs',
        'Limited to common subdomain wordlist (no bruteforce)',
        'CNAME resolution limited in serverless environment'
      ],
      summary: `Found ${validSubdomains.length} active subdomains using serverless DNS enumeration`,
      metadata: {
        method: 'dns-over-https + http-check',
        wordlistSize: commonSubdomains.length,
        activeSubdomains: validSubdomains.filter(s => s.httpStatus && s.httpStatus < 400).length,
        httpsEnabled: validSubdomains.filter(s => s.isHttps).length
      }
    }
  })
}

interface SubdomainSecurity {
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  securityScore: number
  vulnerabilities: Array<{
    type: string
    severity: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    description: string
  }>
  recommendations: string[]
}

interface SubdomainDetail {
  subdomain: string
  ips: string[]
  cnames: string[]
  httpStatus: number | null
  isHttps: boolean
  title?: string
  discoveryMethod: string
  securityAnalysis?: SubdomainSecurity
  technology?: string[]
  lastSeen?: string
  geolocation?: {
    country: string
    city?: string
    org?: string
  }
}

// Enhanced security analysis for subdomains
function analyzeSubdomainSecurity(subdomain: string, details: Partial<SubdomainDetail>): SubdomainSecurity {
  const vulnerabilities: SubdomainSecurity['vulnerabilities'] = []
  let securityScore = 100
  const recommendations: string[] = []

  // Check for insecure HTTP
  if (details.httpStatus && !details.isHttps) {
    vulnerabilities.push({
      type: 'Insecure Protocol',
      severity: 'HIGH',
      description: 'Subdomain accessible over insecure HTTP protocol'
    })
    securityScore -= 25
    recommendations.push('🔒 Enable HTTPS and redirect HTTP traffic')
  }

  // Check for potentially sensitive subdomains
  const sensitivePatterns = ['admin', 'test', 'dev', 'staging', 'backup', 'git', 'svn', 'api', 'internal']
  const isSensitive = sensitivePatterns.some(pattern => subdomain.includes(pattern))
  
  if (isSensitive && details.httpStatus === 200) {
    vulnerabilities.push({
      type: 'Exposed Sensitive Service',
      severity: 'HIGH',
      description: 'Potentially sensitive subdomain is publicly accessible'
    })
    securityScore -= 30
    recommendations.push('🛡️ Restrict access to sensitive services with authentication')
  }

  // Check for development/testing environments
  const devPatterns = ['dev', 'test', 'staging', 'beta', 'alpha', 'demo']
  const isDevEnvironment = devPatterns.some(pattern => subdomain.includes(pattern))
  
  if (isDevEnvironment && details.httpStatus === 200) {
    vulnerabilities.push({
      type: 'Exposed Development Environment',
      severity: 'MEDIUM',
      description: 'Development or testing environment is publicly accessible'
    })
    securityScore -= 20
    recommendations.push('🔧 Secure development environments behind VPN or authentication')
  }

  // Check for wildcard subdomains (potential subdomain takeover)
  if (details.cnames && details.cnames.some(cname => 
    cname.includes('amazonaws.com') || cname.includes('github.io') || 
    cname.includes('herokuapp.com') || cname.includes('netlify.app'))) {
    vulnerabilities.push({
      type: 'Potential Subdomain Takeover',
      severity: 'CRITICAL',
      description: 'Subdomain points to external service that might be unclaimed'
    })
    securityScore -= 40
    recommendations.push('🚨 Verify subdomain takeover risk and secure DNS records')
  }

  // Check for missing security headers (if accessible)
  if (details.httpStatus === 200) {
    recommendations.push('🔍 Audit security headers for this subdomain')
    recommendations.push('📊 Monitor subdomain for security vulnerabilities')
  }

  // Determine risk level
  let riskLevel: SubdomainSecurity['riskLevel'] = 'LOW'
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

// Enhanced geolocation lookup
async function getGeolocation(ip: string): Promise<SubdomainDetail['geolocation']> {
  try {
    // Using a free IP geolocation service (in production, use a proper API)
    const response = await fetch(`http://ip-api.com/json/${ip}?fields=country,city,org`, {
      headers: {
        'User-Agent': 'CyberShield-Subdomain-Scanner/2.0'
      }
    })
    
    if (response.ok) {
      const data = await response.json()
      return {
        country: data.country || 'Unknown',
        city: data.city || undefined,
        org: data.org || undefined
      }
    }
  } catch (error) {
    console.log('Geolocation lookup failed for IP:', ip)
  }
  
  return { country: 'Unknown' }
}

export async function POST(request: NextRequest) {
  try {
    const { domain, scanType = 'comprehensive' } = await request.json()
    
    if (!domain) {
      return NextResponse.json({
        success: false,
        message: 'Domain is required'
      }, { status: 400 })
    }

    // Check if running in serverless environment
    const isServerless = process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME || process.env.NETLIFY
    
    if (isServerless) {
      // Use serverless-compatible subdomain enumeration
      return await handleServerlessSubdomainEnum(domain, scanType)
    }

    // Clean the domain name
    const cleanDomain = domain.replace(/^https?:\/\//, '').replace(/^www\./, '').split('/')[0].trim()
    
    console.log(`🔍 Starting comprehensive subdomain enumeration for ${cleanDomain}`)
    const startTime = Date.now()
    const foundSubdomains = new Set<string>()

    // Enhanced subdomain wordlist
    const commonSubdomains = [
      // Web services
      'www', 'api', 'app', 'mobile', 'm', 'cdn', 'static', 'assets', 'media', 'images', 'img',
      // Email services
      'mail', 'webmail', 'smtp', 'pop', 'imap', 'exchange', 'mx', 'mx1', 'mx2', 'email',
      // Development
      'dev', 'test', 'staging', 'beta', 'alpha', 'demo', 'sandbox', 'preview', 'qa',
      // Administration
      'admin', 'cpanel', 'whm', 'panel', 'dashboard', 'control', 'manage', 'portal',
      // Infrastructure
      'ns1', 'ns2', 'dns', 'ftp', 'sftp', 'ssh', 'vpn', 'firewall', 'gateway', 'proxy',
      // Content & Support
      'blog', 'forum', 'news', 'support', 'help', 'docs', 'wiki', 'kb', 'download', 'files',
      // E-commerce
      'shop', 'store', 'cart', 'checkout', 'payment', 'order', 'invoice',
      // Monitoring & Analytics
      'monitor', 'status', 'health', 'stats', 'analytics', 'metrics', 'logs', 'grafana',
      // Security & Auth
      'auth', 'login', 'sso', 'oauth', 'secure', 'ssl', 'cert', 'ca',
      // Cloud & Infrastructure
      'cloud', 'aws', 'gcp', 'azure', 'docker', 'k8s', 'kubernetes',
      // Databases & Services
      'db', 'database', 'mysql', 'postgres', 'redis', 'elastic', 'search',
      // Regional/Language
      'en', 'us', 'uk', 'ca', 'au', 'de', 'fr', 'es', 'it', 'jp', 'cn', 'br',
      // Backup & Version Control
      'backup', 'bak', 'git', 'svn', 'cvs', 'repo', 'archive'
    ]

    // Method 1: Enhanced Certificate Transparency logs
    console.log('📜 Searching Certificate Transparency logs...')
    try {
      const crtResponse = await fetch(`https://crt.sh/?q=${encodeURIComponent(`%.${cleanDomain}`)}&output=json`, {
        headers: {
          'User-Agent': 'CyberShield-Subdomain-Scanner/2.0'
        }
      })

      if (crtResponse.ok) {
        const crtData = await crtResponse.json()
        for (const cert of crtData) {
          const names = cert.name_value?.split('\n') || []
          for (const name of names) {
            const subdomain = name.trim().toLowerCase().replace(/^\*\./, '')
            if (subdomain.endsWith(`.${cleanDomain}`) && !subdomain.includes('*')) {
              foundSubdomains.add(subdomain)
            }
          }
        }
        console.log(`✅ Certificate Transparency: Found ${foundSubdomains.size} subdomains`)
      }
    } catch (error) {
      console.log('❌ Certificate transparency lookup failed:', error)
    }

    // Method 2: DNS brute force with enhanced wordlist
    console.log('🔨 Performing DNS brute force enumeration...')
    const dnsPromises = commonSubdomains.map(async (sub) => {
      const subdomain = `${sub}.${cleanDomain}`
      try {
        const dnsResponse = await fetch(`https://cloudflare-dns.com/dns-query?name=${subdomain}&type=A`, {
          headers: {
            'Accept': 'application/dns-json',
            'User-Agent': 'CyberShield-DNS-Scanner'
          }
        })

        if (dnsResponse.ok) {
          const dnsData = await dnsResponse.json()
          if (dnsData.Answer && dnsData.Answer.length > 0) {
            foundSubdomains.add(subdomain)
            return {
              subdomain,
              ips: dnsData.Answer.filter((a: any) => a.type === 1).map((a: any) => a.data),
              type: 'DNS'
            }
          }
        }
      } catch (error) {
        // DNS lookup failed
      }
      return null
    })

    // Method 3: Enhanced cloud service discovery
    console.log('☁️ Scanning cloud service patterns...')
    const cloudServices = [
      'amazonaws.com', 's3.amazonaws.com', 'cloudfront.net',
      'herokuapp.com', 'herokucdn.com',
      'azurewebsites.net', 'azure.com',
      'netlify.app', 'netlify.com',
      'vercel.app', 'vercel.com',
      'github.io', 'githubusercontent.com',
      'gitlab.io', 'gitlab.com',
      'firebase.com', 'firebaseapp.com',
      'cloudflare.com', 'cloudflaressl.com',
      'fastly.com', 'fastlylb.net'
    ]

    const cloudPromises = cloudServices.map(async (service) => {
      const variations = [
        `${cleanDomain.replace(/\./g, '-')}.${service}`,
        `${cleanDomain.split('.')[0]}.${service}`,
        `${cleanDomain}.${service}`
      ]
      
      for (const cloudSubdomain of variations) {
        try {
          const controller = new AbortController()
          const timeoutId = setTimeout(() => controller.abort(), 3000)
          
          const response = await fetch(`https://${cloudSubdomain}`, {
            method: 'HEAD',
            signal: controller.signal,
            headers: {
              'User-Agent': 'CyberShield-Cloud-Scanner/2.0'
            }
          })
          
          clearTimeout(timeoutId)
          
          if (response.ok || (response.status >= 400 && response.status < 500)) {
            foundSubdomains.add(cloudSubdomain)
            return {
              subdomain: cloudSubdomain,
              type: 'Cloud Service',
              status: response.status
            }
          }
        } catch (error) {
          // Service not found
        }
      }
      return null
    })

    // Wait for all DNS lookups to complete
    const dnsResults = await Promise.all(dnsPromises)
    const cloudResults = await Promise.all(cloudPromises)

    console.log(`🎯 Total unique subdomains discovered: ${foundSubdomains.size}`)

    // Enhanced subdomain analysis with security assessment
    const validSubdomains = Array.from(foundSubdomains).sort()
    const subdomainDetails: SubdomainDetail[] = []

    console.log('🔬 Performing detailed analysis of discovered subdomains...')
    
    // Limit detailed analysis to first 50 subdomains for performance
    const subdomainsToAnalyze = validSubdomains.slice(0, 50)
    
    for (const subdomain of subdomainsToAnalyze) {
      try {
        // Get comprehensive DNS records
        const [aResponse, cnameResponse] = await Promise.all([
          fetch(`https://cloudflare-dns.com/dns-query?name=${subdomain}&type=A`, {
            headers: { 'Accept': 'application/dns-json' }
          }),
          fetch(`https://cloudflare-dns.com/dns-query?name=${subdomain}&type=CNAME`, {
            headers: { 'Accept': 'application/dns-json' }
          })
        ])
        
        let ips: string[] = []
        let cnames: string[] = []
        
        if (aResponse.ok) {
          const aData = await aResponse.json()
          if (aData.Answer) {
            ips = aData.Answer.filter((a: any) => a.type === 1).map((a: any) => a.data)
          }
        }
        
        if (cnameResponse.ok) {
          const cnameData = await cnameResponse.json()
          if (cnameData.Answer) {
            cnames = cnameData.Answer.filter((a: any) => a.type === 5).map((a: any) => a.data)
          }
        }

        // HTTP/HTTPS accessibility check
        let httpStatus = null
        let isHttps = false
        let title: string | undefined
        
        // Try HTTPS first
        try {
          const httpsController = new AbortController()
          const httpsTimeoutId = setTimeout(() => httpsController.abort(), 5000)
          
          const httpResponse = await fetch(`https://${subdomain}`, {
            method: 'GET',
            signal: httpsController.signal,
            headers: {
              'User-Agent': 'CyberShield-Web-Scanner/2.0'
            }
          })
          
          clearTimeout(httpsTimeoutId)
          httpStatus = httpResponse.status
          isHttps = true
          
          // Try to extract title
          if (httpResponse.ok) {
            const html = await httpResponse.text()
            const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i)
            if (titleMatch) {
              title = titleMatch[1].trim().substring(0, 100)
            }
          }
        } catch {
          // Try HTTP as fallback
          try {
            const httpController = new AbortController()
            const httpTimeoutId = setTimeout(() => httpController.abort(), 5000)
            
            const httpResponse = await fetch(`http://${subdomain}`, {
              method: 'GET',
              signal: httpController.signal,
              headers: {
                'User-Agent': 'CyberShield-Web-Scanner/2.0'
              }
            })
            
            clearTimeout(httpTimeoutId)
            httpStatus = httpResponse.status
            isHttps = false
            
            if (httpResponse.ok) {
              const html = await httpResponse.text()
              const titleMatch = html.match(/<title[^>]*>([^<]+)<\/title>/i)
              if (titleMatch) {
                title = titleMatch[1].trim().substring(0, 100)
              }
            }
          } catch {
            // Neither HTTP nor HTTPS accessible
          }
        }

        // Get geolocation for first IP
        let geolocation: SubdomainDetail['geolocation'] | undefined
        if (ips.length > 0) {
          geolocation = await getGeolocation(ips[0])
        }

        // Determine discovery method
        let discoveryMethod = 'Certificate Transparency'
        if (commonSubdomains.some(s => subdomain.startsWith(`${s}.`))) {
          discoveryMethod = 'DNS Brute Force'
        } else if (subdomain.includes('amazonaws.com') || subdomain.includes('.app') || 
                   subdomain.includes('herokuapp.com') || subdomain.includes('netlify')) {
          discoveryMethod = 'Cloud Service'
        }

        const detail: SubdomainDetail = {
          subdomain,
          ips,
          cnames,
          httpStatus,
          isHttps,
          title,
          discoveryMethod,
          geolocation,
          lastSeen: new Date().toISOString()
        }

        // Perform security analysis
        detail.securityAnalysis = analyzeSubdomainSecurity(subdomain, detail)

        subdomainDetails.push(detail)
      } catch (error) {
        subdomainDetails.push({
          subdomain,
          ips: [],
          cnames: [],
          httpStatus: null,
          isHttps: false,
          discoveryMethod: 'Unknown',
          lastSeen: new Date().toISOString()
        })
      }
    }

    const executionTime = Date.now() - startTime

    // Generate security summary
    const criticalRisk = subdomainDetails.filter(s => s.securityAnalysis?.riskLevel === 'CRITICAL').length
    const highRisk = subdomainDetails.filter(s => s.securityAnalysis?.riskLevel === 'HIGH').length
    const accessibleSubdomains = subdomainDetails.filter(s => s.httpStatus === 200).length
    const httpsEnabled = subdomainDetails.filter(s => s.isHttps && s.httpStatus === 200).length

    const summary = `🔍 Subdomain enumeration completed for ${cleanDomain}.\n` +
                   `📊 Discovered ${validSubdomains.length} unique subdomains (analyzed ${subdomainDetails.length}).\n` +
                   `🌐 ${accessibleSubdomains} subdomains are web-accessible, ${httpsEnabled} use HTTPS.\n` +
                   (criticalRisk > 0 ? `🚨 ${criticalRisk} subdomains have CRITICAL security risks!\n` : '') +
                   (highRisk > 0 ? `⚠️ ${highRisk} subdomains have HIGH security risks.\n` : '') +
                   `⏱️ Scan completed in ${(executionTime / 1000).toFixed(2)} seconds.`

    const result = {
      domain: cleanDomain,
      totalFound: validSubdomains.length,
      analyzedCount: subdomainDetails.length,
      subdomains: subdomainDetails.sort((a, b) => {
        // Sort by security risk level, then by subdomain name
        const riskOrder = { 'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'LOW': 3 }
        const aRisk = a.securityAnalysis?.riskLevel || 'LOW'
        const bRisk = b.securityAnalysis?.riskLevel || 'LOW'
        
        if (aRisk !== bRisk) {
          return riskOrder[aRisk] - riskOrder[bRisk]
        }
        
        return a.subdomain.localeCompare(b.subdomain)
      }),
      summary,
      securitySummary: {
        criticalRisk,
        highRisk,
        accessibleSubdomains,
        httpsEnabled,
        totalVulnerabilities: subdomainDetails.reduce((sum, s) => 
          sum + (s.securityAnalysis?.vulnerabilities.length || 0), 0)
      },
      discoveryMethods: [
        'Certificate Transparency Logs (crt.sh)',
        'DNS Brute Force Attack',
        'Cloud Service Pattern Detection',
        'Comprehensive Security Analysis'
      ],
      executionTime,
      timestamp: new Date().toISOString(),
      recommendations: [
        '🔒 Secure all accessible subdomains with HTTPS',
        '🛡️ Implement access controls for sensitive subdomains',
        '🔍 Regularly monitor for new subdomain discoveries',
        '🚫 Remove or secure unused/abandoned subdomains',
        '📊 Set up subdomain monitoring and alerting'
      ]
    }

    return NextResponse.json({
      success: true,
      data: result
    })

  } catch (error) {
    console.error('❌ Subdomain enumeration error:', error)
    return NextResponse.json({
      success: false,
      message: 'Internal server error during subdomain enumeration',
      error: process.env.NODE_ENV === 'development' ? (error instanceof Error ? error.message : 'Unknown error') : undefined
    }, { status: 500 })
  }
}