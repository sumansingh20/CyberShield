import { NextRequest, NextResponse } from 'next/server'
import { FraudDetectionAI } from '@/src/core/lib/utils/real-ai-services'

// AI-powered fraud detection patterns and thresholds
const FRAUD_INDICATORS = {
  HIGH_RISK_AMOUNTS: {
    min: 5000, // Transactions over $5000 are flagged
    max: 50000 // Transactions over $50000 are critical
  },
  SUSPICIOUS_TIMES: [
    '12:00 AM', '1:00 AM', '2:00 AM', '3:00 AM', '4:00 AM', '5:00 AM'
  ],
  HIGH_RISK_LOCATIONS: [
    'russia', 'nigeria', 'unknown', 'tor', 'vpn', 'proxy'
  ],
  SUSPICIOUS_MERCHANTS: [
    'cash advance', 'atm', 'casino', 'lottery', 'bitcoin', 'crypto'
  ],
  BEHAVIORAL_RED_FLAGS: [
    'multiple failed attempts', 'new device', 'unusual location',
    'rapid transactions', 'round amounts', 'duplicate transactions'
  ]
}

// Transaction analysis engine
async function analyzeTransaction(transactionData: any) {
  const {
    amount,
    merchant,
    location,
    time,
    paymentMethod,
    description
  } = transactionData

  const suspiciousFactors: string[] = []
  const behavioralPatterns: string[] = []
  const transactionAnomalies: string[] = []
  let riskScore = 0

  // Amount analysis
  const amountNum = parseFloat(amount) || 0
  let amountAnalysis = {
    isUnusualAmount: false,
    comparedToHistory: 'Within normal range'
  }

  if (amountNum > FRAUD_INDICATORS.HIGH_RISK_AMOUNTS.max) {
    riskScore += 40
    suspiciousFactors.push('Extremely high transaction amount')
    transactionAnomalies.push(`Amount $${amountNum} exceeds critical threshold`)
    amountAnalysis.isUnusualAmount = true
    amountAnalysis.comparedToHistory = 'Significantly above average'
  } else if (amountNum > FRAUD_INDICATORS.HIGH_RISK_AMOUNTS.min) {
    riskScore += 25
    suspiciousFactors.push('High-value transaction')
    transactionAnomalies.push(`Amount $${amountNum} flagged as high-risk`)
    amountAnalysis.isUnusualAmount = true
    amountAnalysis.comparedToHistory = 'Above average spending pattern'
  }

  // Round amounts often indicate suspicious activity
  if (amountNum > 0 && amountNum % 100 === 0 && amountNum >= 1000) {
    riskScore += 15
    behavioralPatterns.push('Round amount transaction pattern detected')
  }

  // Time analysis
  const timeAnalysis = {
    isUnusualTime: false,
    patterns: [] as string[]
  }

  if (time && FRAUD_INDICATORS.SUSPICIOUS_TIMES.includes(time)) {
    riskScore += 20
    suspiciousFactors.push('Transaction during suspicious hours')
    timeAnalysis.isUnusualTime = true
    timeAnalysis.patterns.push('Late night/early morning activity')
  }

  // Location analysis
  const locationAnalysis = {
    isUnusualLocation: false,
    riskFactors: [] as string[]
  }

  if (location) {
    const locationLower = location.toLowerCase()
    FRAUD_INDICATORS.HIGH_RISK_LOCATIONS.forEach(riskLocation => {
      if (locationLower.includes(riskLocation)) {
        riskScore += 30
        suspiciousFactors.push(`High-risk location: ${location}`)
        locationAnalysis.isUnusualLocation = true
        locationAnalysis.riskFactors.push(`Flagged location: ${riskLocation}`)
      }
    })

    // Check for foreign locations (simplified)
    const foreignKeywords = ['international', 'foreign', 'overseas', 'abroad']
    if (foreignKeywords.some(keyword => locationLower.includes(keyword))) {
      riskScore += 15
      behavioralPatterns.push('International transaction detected')
      locationAnalysis.riskFactors.push('Cross-border transaction')
    }
  }

  // Merchant analysis
  if (merchant) {
    const merchantLower = merchant.toLowerCase()
    FRAUD_INDICATORS.SUSPICIOUS_MERCHANTS.forEach(suspiciousMerchant => {
      if (merchantLower.includes(suspiciousMerchant)) {
        riskScore += 25
        suspiciousFactors.push(`High-risk merchant category: ${merchant}`)
        transactionAnomalies.push(`Merchant flagged: ${suspiciousMerchant}`)
      }
    })
  }

  // Payment method analysis
  const deviceAnalysis = {
    isNewDevice: false,
    riskIndicators: [] as string[]
  }

  if (paymentMethod) {
    const methodLower = paymentMethod.toLowerCase()
    if (methodLower.includes('new') || methodLower.includes('unknown')) {
      riskScore += 20
      behavioralPatterns.push('New payment method detected')
      deviceAnalysis.isNewDevice = true
      deviceAnalysis.riskIndicators.push('Unrecognized payment method')
    }

    if (methodLower.includes('prepaid') || methodLower.includes('gift card')) {
      riskScore += 30
      suspiciousFactors.push('High-risk payment method (prepaid/gift card)')
      deviceAnalysis.riskIndicators.push('Anonymous payment method')
    }
  }

  // Description analysis
  if (description) {
    const descLower = description.toLowerCase()
    const urgentKeywords = ['urgent', 'emergency', 'immediate', 'asap', 'rush']
    if (urgentKeywords.some(keyword => descLower.includes(keyword))) {
      riskScore += 15
      behavioralPatterns.push('Urgency indicators in description')
    }
  }

  return {
    riskScore: Math.min(riskScore, 100),
    suspiciousFactors,
    behavioralPatterns,
    transactionAnomalies,
    locationAnalysis,
    timeAnalysis,
    deviceAnalysis,
    amountAnalysis
  }
}

// Profile analysis engine
async function analyzeProfile(profileData: string) {
  const profileLower = profileData.toLowerCase()
  const suspiciousFactors: string[] = []
  const behavioralPatterns: string[] = []
  const transactionAnomalies: string[] = []
  let riskScore = 0

  // Check for suspicious keywords
  const suspiciousKeywords = [
    'multiple accounts', 'fake identity', 'stolen card', 'chargeback',
    'dispute', 'refund abuse', 'bot', 'automated', 'script',
    'vpn', 'proxy', 'tor', 'anonymous'
  ]

  suspiciousKeywords.forEach(keyword => {
    if (profileLower.includes(keyword)) {
      riskScore += 20
      suspiciousFactors.push(`Suspicious keyword detected: ${keyword}`)
    }
  })

  // Check for behavioral red flags
  FRAUD_INDICATORS.BEHAVIORAL_RED_FLAGS.forEach(flag => {
    if (profileLower.includes(flag)) {
      riskScore += 15
      behavioralPatterns.push(`Red flag behavior: ${flag}`)
    }
  })

  // Check for rapid transaction patterns
  if (profileLower.includes('rapid') || profileLower.includes('multiple') || profileLower.includes('frequent')) {
    riskScore += 25
    transactionAnomalies.push('Rapid transaction pattern detected')
  }

  // Check for location inconsistencies
  if (profileLower.includes('different location') || profileLower.includes('unusual location')) {
    riskScore += 20
    behavioralPatterns.push('Location inconsistency detected')
  }

  return {
    riskScore: Math.min(riskScore, 100),
    suspiciousFactors,
    behavioralPatterns,
    transactionAnomalies,
    locationAnalysis: {
      isUnusualLocation: profileLower.includes('unusual location'),
      riskFactors: profileLower.includes('vpn') ? ['VPN usage detected'] : []
    },
    timeAnalysis: {
      isUnusualTime: profileLower.includes('unusual time'),
      patterns: profileLower.includes('night') ? ['Late night activity'] : []
    },
    deviceAnalysis: {
      isNewDevice: profileLower.includes('new device'),
      riskIndicators: profileLower.includes('multiple devices') ? ['Multiple device usage'] : []
    },
    amountAnalysis: {
      isUnusualAmount: profileLower.includes('large amount'),
      comparedToHistory: 'Profile-based analysis'
    }
  }
}

// Generate recommendations based on analysis
function generateRecommendations(riskScore: number, analysis: any): string[] {
  const recommendations: string[] = []

  if (riskScore >= 75) {
    recommendations.push('CRITICAL: Block transaction immediately and contact fraud team')
    recommendations.push('Freeze account pending manual review')
    recommendations.push('Request additional verification documents')
  } else if (riskScore >= 50) {
    recommendations.push('HIGH: Require additional authentication (2FA, SMS, etc.)')
    recommendations.push('Flag for manual review within 24 hours')
    recommendations.push('Monitor account for related suspicious activity')
  } else if (riskScore >= 25) {
    recommendations.push('MEDIUM: Apply enhanced monitoring for next 7 days')
    recommendations.push('Consider step-up authentication for similar transactions')
    recommendations.push('Log for behavioral pattern analysis')
  } else {
    recommendations.push('LOW: Continue normal processing')
    recommendations.push('Update baseline behavior model with this transaction')
    recommendations.push('Monitor for pattern changes over time')
  }

  // Specific recommendations based on analysis
  if (analysis.locationAnalysis?.isUnusualLocation) {
    recommendations.push('Verify location through IP geolocation and device fingerprinting')
  }

  if (analysis.timeAnalysis?.isUnusualTime) {
    recommendations.push('Implement time-based transaction limits for unusual hours')
  }

  if (analysis.deviceAnalysis?.isNewDevice) {
    recommendations.push('Device verification required before processing high-value transactions')
  }

  return recommendations
}

export async function POST(request: NextRequest) {
  try {
    // Skip database connection for now to avoid deployment issues
    // await connectDB()

    const body = await request.json()
    console.log('Fraud Analysis Request:', body)
    
    // Handle both direct data and nested data structures
    let analysisData
    let analysisType = 'transaction' // default
    
    if (body.type && body.data) {
      analysisType = body.type
      analysisData = body.data
    } else if (body.amount || body.merchant || body.location) {
      // Direct transaction data
      analysisData = body
      analysisType = 'transaction'
    } else if (typeof body === 'string') {
      // Profile analysis
      analysisData = body
      analysisType = 'profile'
    } else {
      return NextResponse.json({
        error: 'Invalid request format. Expected transaction data or profile data.'
      }, { status: 400 })
    }

    // Perform real AI analysis based on type
    let analysis
    if (analysisType === 'transaction') {
      const realAnalysis = FraudDetectionAI.analyzeTransaction(analysisData)
      const traditionalAnalysis = await analyzeTransaction(analysisData)
      
      // Combine real AI analysis with traditional rule-based analysis
      analysis = {
        riskScore: Math.max(realAnalysis.riskScore, traditionalAnalysis.riskScore),
        suspiciousFactors: [...new Set([...realAnalysis.riskFactors, ...traditionalAnalysis.suspiciousFactors])],
        behavioralPatterns: [...new Set([...realAnalysis.patterns, ...traditionalAnalysis.behavioralPatterns])],
        transactionAnomalies: [...new Set([...realAnalysis.riskFactors, ...traditionalAnalysis.transactionAnomalies])],
        locationAnalysis: {
          isUnusualLocation: traditionalAnalysis.locationAnalysis.isUnusualLocation || realAnalysis.riskFactors.some(f => f.includes('location')),
          riskFactors: [...new Set([...traditionalAnalysis.locationAnalysis.riskFactors, ...realAnalysis.riskFactors.filter(f => f.includes('location'))])]
        },
        timeAnalysis: {
          isUnusualTime: traditionalAnalysis.timeAnalysis.isUnusualTime || realAnalysis.riskFactors.some(f => f.includes('time') || f.includes('hour')),
          patterns: [...new Set([...traditionalAnalysis.timeAnalysis.patterns, ...realAnalysis.patterns.filter(p => p.includes('timing') || p.includes('time'))])]
        },
        deviceAnalysis: {
          isNewDevice: traditionalAnalysis.deviceAnalysis.isNewDevice || realAnalysis.riskFactors.some(f => f.includes('payment method')),
          riskIndicators: [...new Set([...traditionalAnalysis.deviceAnalysis.riskIndicators, ...realAnalysis.riskFactors.filter(f => f.includes('method'))])]
        },
        amountAnalysis: traditionalAnalysis.amountAnalysis
      }
    } else {
      // Enhanced profile analysis
      analysis = await analyzeProfile(analysisData)
    }
    
    // Determine if it's fraudulent based on risk score
    const isFraudulent = analysis.riskScore >= 50
    const confidence = Math.min(analysis.riskScore + 10, 95)
    
    // Determine risk level
    let riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
    if (analysis.riskScore < 25) riskLevel = 'LOW'
    else if (analysis.riskScore < 50) riskLevel = 'MEDIUM'
    else if (analysis.riskScore < 75) riskLevel = 'HIGH'
    else riskLevel = 'CRITICAL'
    
    // Generate reasons
    const reasons = []
    if (analysis.suspiciousFactors.length > 0) {
      reasons.push(`${analysis.suspiciousFactors.length} critical risk factors identified`)
    }
    if (analysis.behavioralPatterns.length > 0) {
      reasons.push(`${analysis.behavioralPatterns.length} suspicious behavioral patterns detected`)
    }
    if (analysis.transactionAnomalies.length > 0) {
      reasons.push(`${analysis.transactionAnomalies.length} transaction anomalies found`)
    }
    if (analysis.riskScore < 25) {
      reasons.push('Transaction appears legitimate based on AI analysis')
    }
    
    // Generate recommendations
    const recommendations = generateRecommendations(analysis.riskScore, analysis)
    
    const result = {
      isFraud: isFraudulent,
      riskScore: analysis.riskScore,
      riskLevel,
      confidence,
      reasons,
      analysis: {
        suspiciousFactors: analysis.suspiciousFactors,
        behavioralPatterns: analysis.behavioralPatterns,
        transactionAnomalies: analysis.transactionAnomalies,
        locationAnalysis: {
          isUnusualLocation: analysis.locationAnalysis.isUnusualLocation,
          riskFactors: analysis.locationAnalysis.riskFactors
        },
        timeAnalysis: {
          isUnusualTime: analysis.timeAnalysis.isUnusualTime,
          riskFactors: analysis.timeAnalysis.patterns || []
        }
      },
      recommendations
    }

    return NextResponse.json(result)

  } catch (error) {
    console.error('AI Fraud Detection Error:', error)
    return NextResponse.json({
      error: 'Analysis failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
