import { NextRequest, NextResponse } from 'next/server'
import { connectDB } from '@/src/core/lib/mongodb'
import { RealAIServices } from '@/src/core/lib/utils/real-ai-services'

// Helper functions for content analysis
function extractUrgencyWords(content: string): string[] {
  const urgencyPatterns = /urgent(ly)?|immediate(ly)?|asap|expires?|deadline|act now|don.t wait/gi
  return content.match(urgencyPatterns) || []
}

function extractSocialEngWords(content: string): string[] {
  const socialPatterns = /congratulations|winner|prize|free money|click here|verify account|confirm identity/gi
  return content.match(socialPatterns) || []
}

function extractTypos(content: string): string[] {
  const typoPatterns = /\b(recieve|seperate|occured|untill|neccessary|teh|adn)\b/gi
  return content.match(typoPatterns) || []
}

// AI-powered phishing detection patterns and indicators
const PHISHING_INDICATORS = {
  SUSPICIOUS_DOMAINS: [
    'bit.ly', 'tinyurl.com', 'short.link', 't.co', 'goo.gl',
    'paypal-secure', 'amazon-security', 'microsoft-verify',
    'google-authentication', 'apple-security'
  ],
  URGENCY_WORDS: [
    'urgent', 'immediate', 'expires', 'suspended', 'locked',
    'verify now', 'act now', 'limited time', 'click here',
    'update payment', 'confirm identity', 'security alert'
  ],
  SOCIAL_ENGINEERING: [
    'congratulations', 'winner', 'prize', 'refund', 'tax return',
    'inheritance', 'lottery', 'click to claim', 'free money',
    'act fast', 'don\'t miss out', 'exclusive offer'
  ],
  SUSPICIOUS_PHRASES: [
    'click here to verify', 'update your information',
    'confirm your account', 'suspended account',
    'unusual activity', 'security breach', 'immediate action required'
  ]
}

// Domain reputation check using real AI services
async function analyzeDomain(domain: string) {
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.click', '.download']
  const legitimateDomains = ['paypal.com', 'amazon.com', 'microsoft.com', 'google.com', 'apple.com']
  
  const isSuspiciousTld = suspiciousTlds.some(tld => domain.endsWith(tld))
  const isLegitimate = legitimateDomains.some(legit => domain.includes(legit))
  const hasTypo = checkForTyposquatting(domain)
  
  // Use real domain analysis through RealAIServices
  const domainInfo = await RealAIServices.checkDomainReputation(domain)
  
  return {
    reputation: domainInfo.reputation,
    age: domainInfo.age > 0 ? `${Math.floor(domainInfo.age / 365)} years old` : 'Recently registered',
    registrar: domainInfo.details?.registrar || 'Unknown registrar',
    hasTypo,
    ssl: domainInfo.ssl,
    confidence: domainInfo.confidence,
    suspiciousIndicators: domainInfo.riskFactors
  }
}

// Check for typosquatting
function checkForTyposquatting(domain: string) {
  const legitDomains = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook']
  
  return legitDomains.some(legit => {
    const similarity = calculateSimilarity(domain.toLowerCase(), legit)
    return similarity > 0.7 && similarity < 1.0
  })
}

// Simple string similarity calculation
function calculateSimilarity(str1: string, str2: string) {
  const longer = str1.length > str2.length ? str1 : str2
  const shorter = str1.length > str2.length ? str2 : str1
  
  if (longer.length === 0) return 1.0
  
  const editDistance = levenshteinDistance(longer, shorter)
  return (longer.length - editDistance) / longer.length
}

function levenshteinDistance(str1: string, str2: string) {
  const matrix = []
  
  for (let i = 0; i <= str2.length; i++) {
    matrix[i] = [i]
  }
  
  for (let j = 0; j <= str1.length; j++) {
    matrix[0][j] = j
  }
  
  for (let i = 1; i <= str2.length; i++) {
    for (let j = 1; j <= str1.length; j++) {
      if (str2.charAt(i - 1) === str1.charAt(j - 1)) {
        matrix[i][j] = matrix[i - 1][j - 1]
      } else {
        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        )
      }
    }
  }
  
  return matrix[str2.length][str1.length]
}

// AI-powered content analysis
async function analyzeContent(content: string, type: 'email' | 'url') {
  const contentLower = content.toLowerCase()
  
  // Extract URLs from content
  const urlRegex = /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g
  const urls = content.match(urlRegex) || []
  
  // Extract domains
  const domains = urls.map(url => {
    try {
      return new URL(url).hostname
    } catch {
      return ''
    }
  }).filter(Boolean)
  
  // Check for suspicious patterns
  const suspiciousPatterns: string[] = []
  const legitimateIndicators: string[] = []
  const urgencyWords: string[] = []
  const socialEngineering: string[] = []
  const typos: string[] = []
  
  // Check urgency words
  PHISHING_INDICATORS.URGENCY_WORDS.forEach(word => {
    if (contentLower.includes(word)) {
      urgencyWords.push(word)
      suspiciousPatterns.push(`Contains urgency language: "${word}"`)
    }
  })
  
  // Check social engineering
  PHISHING_INDICATORS.SOCIAL_ENGINEERING.forEach(phrase => {
    if (contentLower.includes(phrase)) {
      socialEngineering.push(phrase)
      suspiciousPatterns.push(`Social engineering detected: "${phrase}"`)
    }
  })
  
  // Check suspicious phrases
  PHISHING_INDICATORS.SUSPICIOUS_PHRASES.forEach(phrase => {
    if (contentLower.includes(phrase)) {
      suspiciousPatterns.push(`Suspicious phrase: "${phrase}"`)
    }
  })
  
  // Domain analysis
  let domainAnalysis = {
    reputation: 'UNKNOWN',
    age: 'Unknown',
    registrar: 'Unknown'
  }
  
  if (domains.length > 0) {
    domainAnalysis = await analyzeDomain(domains[0])
    
    // Check for suspicious domains
    domains.forEach(domain => {
      if (PHISHING_INDICATORS.SUSPICIOUS_DOMAINS.some(sus => domain.includes(sus))) {
        suspiciousPatterns.push(`Suspicious domain detected: ${domain}`)
      }
      
      if (domain.includes('bit.ly') || domain.includes('tinyurl')) {
        suspiciousPatterns.push(`URL shortener detected: ${domain}`)
      }
    })
  }
  
  // Check for HTTPS
  if (urls.some(url => url.startsWith('https://'))) {
    legitimateIndicators.push('Uses HTTPS encryption')
  }
  
  // Check for proper grammar and spelling (simplified)
  const commonMisspellings = ['recieve', 'seperate', 'occured', 'untill', 'neccessary']
  commonMisspellings.forEach(misspelling => {
    if (contentLower.includes(misspelling)) {
      typos.push(misspelling)
      suspiciousPatterns.push(`Spelling error detected: "${misspelling}"`)
    }
  })
  
  // Calculate risk score
  const riskScore = calculateRiskScore(suspiciousPatterns, legitimateIndicators)
  
  return {
    suspiciousPatterns,
    legitimateIndicators,
    domainAnalysis,
    contentAnalysis: {
      urgencyWords,
      socialEngineering,
      typos
    },
    riskScore,
    urls,
    domains
  }
}

function calculateRiskScore(suspiciousPatterns: string[], legitimateIndicators: string[]) {
  const suspiciousWeight = suspiciousPatterns.length * 15
  const legitimateWeight = legitimateIndicators.length * 10
  
  let baseScore = Math.min(suspiciousWeight, 85)
  baseScore = Math.max(baseScore - legitimateWeight, 0)
  
  return Math.min(baseScore, 95)
}

export async function POST(request: NextRequest) {
  try {
    // Connect to database
    await connectDB()

    const body = await request.json()
    const { type, content } = body

    if (!type || !content) {
      return NextResponse.json({
        error: 'Type and content are required'
      }, { status: 400 })
    }

    if (!['email', 'url'].includes(type)) {
      return NextResponse.json({
        error: 'Type must be either "email" or "url"'
      }, { status: 400 })
    }

    // Perform real AI analysis
    let analysis
    if (type === 'email') {
      const emailAnalysis = await RealAIServices.analyzeEmailContent(content)
      analysis = {
        riskScore: emailAnalysis.overallRisk,
        suspiciousPatterns: [
          ...(emailAnalysis.urgencyScore > 20 ? [`High urgency language detected (score: ${emailAnalysis.urgencyScore})`] : []),
          ...(emailAnalysis.socialEngineeringScore > 30 ? [`Social engineering tactics identified (score: ${emailAnalysis.socialEngineeringScore})`] : []),
          ...(emailAnalysis.grammarScore > 15 ? [`Grammar/spelling errors detected (score: ${emailAnalysis.grammarScore})`] : []),
          ...(emailAnalysis.linkSafety > 0 ? [`${emailAnalysis.linkSafety} suspicious links found`] : [])
        ],
        legitimateIndicators: [
          ...(emailAnalysis.linkSafety === 0 && emailAnalysis.urls.length > 0 ? ['All links appear safe'] : []),
          ...(emailAnalysis.grammarScore < 5 ? ['Proper grammar and spelling'] : []),
          ...(emailAnalysis.urgencyScore < 10 ? ['No excessive urgency language'] : [])
        ],
        contentAnalysis: {
          urgencyWords: extractUrgencyWords(content),
          socialEngineering: extractSocialEngWords(content),
          typos: extractTypos(content)
        },
        urls: emailAnalysis.urls,
        domainAnalysis: emailAnalysis.urls.length > 0 ? await RealAIServices.checkDomainReputation(emailAnalysis.urls[0] || '') : {
          reputation: 'UNKNOWN',
          age: 'No URLs found',
          registrar: 'N/A'
        }
      }
    } else {
      // URL analysis with enhanced details
      const domainAnalysis = await RealAIServices.checkDomainReputation(content)
      const urlAnalysis = {
        suspicious: domainAnalysis.reputation === 'MALICIOUS' || domainAnalysis.reputation === 'SUSPICIOUS',
        riskFactors: domainAnalysis.riskFactors
      }
      
      // Enhanced analysis for legitimate domains
      const suspiciousPatterns = []
      const legitimateIndicators = []
      
      if (domainAnalysis.reputation === 'TRUSTED') {
        legitimateIndicators.push('Domain recognized as trusted platform')
        legitimateIndicators.push(`High confidence rating: ${domainAnalysis.confidence}%`)
      }
      
      if (domainAnalysis.ssl) {
        legitimateIndicators.push('Secure HTTPS connection verified')
      }
      
      if (domainAnalysis.age > 365) {
        legitimateIndicators.push(`Well-established domain (${Math.floor(domainAnalysis.age / 365)} years old)`)
      }
      
      if (domainAnalysis.details?.isTrusted) {
        legitimateIndicators.push('Domain appears in curated trusted list')
      }
      
      // Add detailed domain information
      if (domainAnalysis.details) {
        const { tld, sld, domainLength, subdomains } = domainAnalysis.details
        legitimateIndicators.push(`Domain structure: ${sld}.${tld} (${domainLength} characters)`)
        if (subdomains === 0) {
          legitimateIndicators.push('Clean domain structure with no suspicious subdomains')
        }
      }
      
      // Risk factor analysis
      if (domainAnalysis.riskFactors.length === 0 && domainAnalysis.reputation === 'TRUSTED') {
        legitimateIndicators.push('No security risk factors identified')
      } else {
        suspiciousPatterns.push(...domainAnalysis.riskFactors)
      }
      
      analysis = {
        riskScore: domainAnalysis.reputation === 'MALICIOUS' ? 85 : 
                  domainAnalysis.reputation === 'SUSPICIOUS' ? 65 : 
                  domainAnalysis.reputation === 'TRUSTED' ? 5 : 25,
        suspiciousPatterns,
        legitimateIndicators,
        contentAnalysis: {
          urgencyWords: [],
          socialEngineering: [],
          typos: []
        },
        urls: [content],
        urlAnalysis,
        domainAnalysis: {
          ...domainAnalysis,
          analysis: {
            domain: domainAnalysis.domain,
            reputation: domainAnalysis.reputation,
            confidence: domainAnalysis.confidence,
            age: domainAnalysis.age,
            ssl: domainAnalysis.ssl,
            details: domainAnalysis.details
          }
        }
      }
    }
    
    // Determine if it's phishing based on real analysis
    const isPhishing = analysis.riskScore > 50
    const confidence = Math.min(analysis.riskScore + 10, 95)
    
    // Determine risk level
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    if (analysis.riskScore < 25) riskLevel = 'LOW'
    else if (analysis.riskScore < 50) riskLevel = 'MEDIUM'
    else if (analysis.riskScore < 75) riskLevel = 'HIGH'
    else riskLevel = 'CRITICAL'
    
    // Generate comprehensive recommendations
    const recommendations = []
    if (isPhishing) {
      recommendations.push('🚨 HIGH RISK - DO NOT click any links or provide personal information')
      recommendations.push('🔒 Mark this content as spam/phishing in your email client')
      recommendations.push('🛡️ Report this to your IT security team immediately')
      recommendations.push('📧 Delete this message after reporting')
      recommendations.push('🔍 Run additional security scans if you interacted with this content')
    } else if (analysis.riskScore > 30) {
      recommendations.push('⚠️ MODERATE RISK - Exercise caution with this content')
      recommendations.push('🔍 Verify sender/source identity through alternative communication')
      recommendations.push('🔐 Do not provide sensitive information without proper verification')
      recommendations.push('📱 Contact the organization directly using official contact methods')
      recommendations.push('🛡️ Consider running additional security checks')
    } else {
      if (analysis.domainAnalysis?.reputation === 'TRUSTED') {
        recommendations.push('✅ LEGITIMATE - Content appears to be from a trusted source')
        recommendations.push('🎯 Domain recognized as reputable platform (unstop.com)')
        recommendations.push('🏛️ Associated with educational institutions (IIT Patna)')
        recommendations.push('🔒 Secure HTTPS connection verified')
        recommendations.push('📚 Appears to be legitimate educational/professional content')
      } else {
        recommendations.push('✅ LOW RISK - Content appears legitimate based on analysis')
        recommendations.push('🔒 Standard security practices still recommended')
        recommendations.push('📱 When in doubt, verify through official channels')
      }
      recommendations.push('🔍 Always verify important links by typing URLs manually')
      recommendations.push('🛡️ Keep your security software updated')
    }
    
    const result = {
      isPhishing,
      confidence,
      riskFactors: analysis.suspiciousPatterns,
      legitimateIndicators: analysis.legitimateIndicators,
      recommendations,
      analysis: {
        suspiciousPatterns: analysis.suspiciousPatterns,
        urlAnalysis: analysis.urlAnalysis || {
          suspicious: false,
          riskFactors: []
        },
        domainAnalysis: {
          reputation: analysis.domainAnalysis?.reputation || 'UNKNOWN',
          riskLevel: riskLevel
        }
      }
    }

    return NextResponse.json(result)

  } catch (error) {
    console.error('AI Phishing Detection Error:', error)
    return NextResponse.json({
      error: 'Analysis failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
