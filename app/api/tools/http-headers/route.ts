import { NextRequest, NextResponse } from 'next/server'

export async function POST(request: NextRequest) {
  try {
    const { url } = await request.json()
    
    if (!url) {
      return NextResponse.json({
        success: false,
        message: 'URL is required'
      }, { status: 400 })
    }

    // Validate and clean URL
    let targetUrl: URL
    try {
      targetUrl = new URL(url.startsWith('http') ? url : `https://${url}`)
    } catch {
      return NextResponse.json({
        success: false,
        message: 'Invalid URL format. Please provide a valid URL (e.g., https://example.com)'
      }, { status: 400 })
    }

    const startTime = Date.now()

    // Make request to get headers
    const controller = new AbortController()
    const timeoutId = setTimeout(() => controller.abort(), 15000)

    try {
      const response = await fetch(targetUrl.toString(), {
        method: 'GET',
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'gzip, deflate, br',
          'Cache-Control': 'no-cache',
          'Connection': 'keep-alive'
        },
        signal: controller.signal,
        redirect: 'manual' // Don't follow redirects automatically
      })

      clearTimeout(timeoutId)

      const executionTime = Date.now() - startTime

      // Extract headers
      const headers: { [key: string]: string } = {}
      response.headers.forEach((value, key) => {
        headers[key] = value
      })

      // Security analysis
      const securityAnalysis = {
        securityHeaders: {
          'Strict-Transport-Security': {
            present: !!headers['strict-transport-security'],
            value: headers['strict-transport-security'] || null,
            score: !!headers['strict-transport-security'] ? 'Good' : 'Missing',
            description: 'Enforces HTTPS connections'
          },
          'X-Content-Type-Options': {
            present: !!headers['x-content-type-options'],
            value: headers['x-content-type-options'] || null,
            score: headers['x-content-type-options'] === 'nosniff' ? 'Good' : !!headers['x-content-type-options'] ? 'Partial' : 'Missing',
            description: 'Prevents MIME type sniffing'
          },
          'X-Frame-Options': {
            present: !!headers['x-frame-options'],
            value: headers['x-frame-options'] || null,
            score: ['DENY', 'SAMEORIGIN'].includes(headers['x-frame-options']?.toUpperCase()) ? 'Good' : !!headers['x-frame-options'] ? 'Partial' : 'Missing',
            description: 'Protects against clickjacking attacks'
          },
          'X-XSS-Protection': {
            present: !!headers['x-xss-protection'],
            value: headers['x-xss-protection'] || null,
            score: headers['x-xss-protection'] === '1; mode=block' ? 'Good' : !!headers['x-xss-protection'] ? 'Partial' : 'Missing',
            description: 'Enables XSS filtering in browsers'
          },
          'Content-Security-Policy': {
            present: !!headers['content-security-policy'],
            value: headers['content-security-policy'] || null,
            score: !!headers['content-security-policy'] ? 'Good' : 'Missing',
            description: 'Controls resource loading to prevent XSS'
          },
          'Referrer-Policy': {
            present: !!headers['referrer-policy'],
            value: headers['referrer-policy'] || null,
            score: !!headers['referrer-policy'] ? 'Good' : 'Missing',
            description: 'Controls referrer information sent with requests'
          },
          'Permissions-Policy': {
            present: !!headers['permissions-policy'],
            value: headers['permissions-policy'] || null,
            score: !!headers['permissions-policy'] ? 'Good' : 'Missing',
            description: 'Controls browser features and APIs'
          }
        },
        informationDisclosure: {
          server: headers['server'] || 'Not disclosed',
          xPoweredBy: headers['x-powered-by'] || 'Not disclosed',
          technology: [] as string[]
        },
        caching: {
          cacheControl: headers['cache-control'] || 'Not set',
          expires: headers['expires'] || 'Not set',
          etag: headers['etag'] || 'Not set',
          lastModified: headers['last-modified'] || 'Not set'
        },
        cookies: {
          setCookies: response.headers.getSetCookie?.() || [],
          secureFlags: [] as boolean[],
          httpOnlyFlags: [] as boolean[],
          sameSiteFlags: [] as boolean[]
        }
      }

      // Analyze cookies
      if (securityAnalysis.cookies.setCookies.length > 0) {
        securityAnalysis.cookies.setCookies.forEach(cookie => {
          if (cookie.toLowerCase().includes('secure')) {
            securityAnalysis.cookies.secureFlags.push(true)
          }
          if (cookie.toLowerCase().includes('httponly')) {
            securityAnalysis.cookies.httpOnlyFlags.push(true)
          }
          if (cookie.toLowerCase().includes('samesite')) {
            securityAnalysis.cookies.sameSiteFlags.push(true)
          }
        })
      }

      // Technology detection
      const techIndicators = []
      if (headers['server']) techIndicators.push(`Server: ${headers['server']}`)
      if (headers['x-powered-by']) techIndicators.push(`Powered by: ${headers['x-powered-by']}`)
      if (headers['x-aspnet-version']) techIndicators.push(`ASP.NET: ${headers['x-aspnet-version']}`)
      if (headers['x-generator']) techIndicators.push(`Generator: ${headers['x-generator']}`)
      securityAnalysis.informationDisclosure.technology = techIndicators

      // Calculate security score
      const securityHeaders = Object.values(securityAnalysis.securityHeaders)
      const goodCount = securityHeaders.filter(h => h.score === 'Good').length
      const partialCount = securityHeaders.filter(h => h.score === 'Partial').length
      const totalCount = securityHeaders.length
      
      const securityScore = Math.round(((goodCount * 2 + partialCount) / (totalCount * 2)) * 100)
      const securityGrade = securityScore >= 90 ? 'A' : securityScore >= 80 ? 'B' : securityScore >= 70 ? 'C' : securityScore >= 60 ? 'D' : 'F'

      const result = {
        url: targetUrl.toString(),
        statusCode: response.status,
        statusText: response.statusText,
        headers,
        securityAnalysis,
        securityScore: {
          score: securityScore,
          grade: securityGrade,
          summary: `Security score: ${securityScore}/100 (Grade ${securityGrade})`
        },
        responseSize: headers['content-length'] ? parseInt(headers['content-length']) : 0,
        contentType: headers['content-type'] || 'Unknown',
        isRedirect: response.status >= 300 && response.status < 400,
        redirectLocation: headers['location'] || null,
        executionTime,
        timestamp: new Date().toISOString()
      }

      return NextResponse.json({
        success: true,
        data: result
      })

    } catch (fetchError) {
      clearTimeout(timeoutId)
      
      if (fetchError instanceof Error && fetchError.name === 'AbortError') {
        return NextResponse.json({
          success: false,
          message: 'Request timeout - server took too long to respond'
        }, { status: 408 })
      }
      
      throw fetchError
    }

  } catch (error) {
    console.error('HTTP headers analysis error:', error)
    return NextResponse.json({
      success: false,
      message: 'Failed to analyze HTTP headers',
      error: process.env.NODE_ENV === 'development' ? (error instanceof Error ? error.message : 'Unknown error') : undefined
    }, { status: 500 })
  }
}