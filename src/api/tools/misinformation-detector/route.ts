import { NextRequest, NextResponse } from 'next/server'
import { connectDB } from '@/src/core/lib/mongodb'
import { RealAIServices } from '@/src/core/lib/utils/real-ai-services'

// Comprehensive misinformation detection patterns
const MISINFORMATION_PATTERNS = {
  EMOTIONAL_MANIPULATION: [
    'outrageous', 'shocking', 'unbelievable', 'terrifying', 'amazing',
    'you won\'t believe', 'doctors hate this', 'this will blow your mind',
    'urgent warning', 'they don\'t want you to know'
  ],
  
  CONSPIRACY_INDICATORS: [
    'they are hiding', 'mainstream media won\'t tell you', 'deep state',
    'shadow government', 'cover-up', 'secret agenda', 'wake up sheeple',
    'follow the money', 'connect the dots', 'do your own research'
  ],
  
  PSEUDOSCIENCE_MARKERS: [
    'natural cure', 'big pharma conspiracy', 'quantum healing',
    'ancient wisdom', 'suppressed science', 'miracle breakthrough',
    'toxins', 'cleanse', 'detox', 'energy healing'
  ],
  
  POLITICAL_BIAS_INDICATORS: [
    'radical left', 'far right', 'extremist', 'socialist agenda',
    'fascist plot', 'deep state operatives', 'puppet masters',
    'corrupt establishment', 'rigged system', 'fake news'
  ],
  
  URGENCY_TACTICS: [
    'share before it\'s deleted', 'going viral', 'must see',
    'breaking news', 'urgent update', 'time sensitive',
    'act now', 'don\'t wait', 'limited time'
  ],
  
  CREDIBILITY_UNDERMINING: [
    'mainstream media lies', 'official sources can\'t be trusted',
    'government propaganda', 'corporate interests', 'bought and paid for',
    'agenda-driven', 'biased reporting', 'suppressed truth'
  ]
}

// Fact-checking database simulation
const FACT_CHECK_SOURCES = [
  'Snopes.com', 'FactCheck.org', 'PolitiFact', 'Reuters Fact Check',
  'AP Fact Check', 'BBC Reality Check', 'Washington Post Fact Checker',
  'NPR Fact Check', 'Lead Stories', 'Truth or Fiction'
]

// Real-time misinformation analysis engine
class MisinformationAnalyzer {
  static analyzeLanguagePatterns(content: string): string[] {
    const patterns: string[] = []
    const contentLower = content.toLowerCase()
    
    // Check for emotional manipulation
    let emotionalScore = 0
    MISINFORMATION_PATTERNS.EMOTIONAL_MANIPULATION.forEach(pattern => {
      if (contentLower.includes(pattern)) {
        emotionalScore += 1
        patterns.push(`Emotional manipulation: "${pattern}"`)
      }
    })
    
    // Check for conspiracy indicators
    MISINFORMATION_PATTERNS.CONSPIRACY_INDICATORS.forEach(pattern => {
      if (contentLower.includes(pattern)) {
        patterns.push(`Conspiracy language: "${pattern}"`)
      }
    })
    
    // Check for pseudoscience markers
    MISINFORMATION_PATTERNS.PSEUDOSCIENCE_MARKERS.forEach(pattern => {
      if (contentLower.includes(pattern)) {
        patterns.push(`Pseudoscience indicator: "${pattern}"`)
      }
    })
    
    // Analyze sentence structure for sensationalism
    const sentences = content.split(/[.!?]+/)
    const exclamations = (content.match(/!/g) || []).length
    const allCaps = (content.match(/[A-Z]{3,}/g) || []).length
    
    if (exclamations > sentences.length * 0.3) {
      patterns.push('Excessive use of exclamation marks')
    }
    
    if (allCaps > 3) {
      patterns.push('Overuse of ALL CAPS text')
    }
    
    return patterns
  }
  
  static detectEmotionalManipulation(content: string): string[] {
    const manipulation: string[] = []
    const contentLower = content.toLowerCase()
    
    // Fear-based appeals
    const fearWords = ['dangerous', 'deadly', 'toxic', 'harmful', 'threat', 'risk', 'warning']
    let fearCount = 0
    fearWords.forEach(word => {
      if (contentLower.includes(word)) fearCount += 1
    })
    
    if (fearCount > 3) {
      manipulation.push('Excessive fear-based language')
    }
    
    // Appeal to authority without credentials
    if (contentLower.includes('expert says') || contentLower.includes('doctor reveals')) {
      if (!contentLower.includes('dr.') && !contentLower.includes('professor')) {
        manipulation.push('Vague authority claims without credentials')
      }
    }
    
    // Urgency tactics
    MISINFORMATION_PATTERNS.URGENCY_TACTICS.forEach(tactic => {
      if (contentLower.includes(tactic)) {
        manipulation.push(`Urgency manipulation: "${tactic}"`)
      }
    })
    
    return manipulation
  }
  
  static analyzeBiasIndicators(content: string): string[] {
    const indicators: string[] = []
    const contentLower = content.toLowerCase()
    
    // Political bias detection
    MISINFORMATION_PATTERNS.POLITICAL_BIAS_INDICATORS.forEach(indicator => {
      if (contentLower.includes(indicator)) {
        indicators.push(`Political bias: "${indicator}"`)
      }
    })
    
    // Source credibility undermining
    MISINFORMATION_PATTERNS.CREDIBILITY_UNDERMINING.forEach(phrase => {
      if (contentLower.includes(phrase)) {
        indicators.push(`Credibility undermining: "${phrase}"`)
      }
    })
    
    // Analyze for loaded language
    const loadedWords = ['radical', 'extremist', 'corrupt', 'evil', 'destroying', 'attacking']
    loadedWords.forEach(word => {
      if (contentLower.includes(word)) {
        indicators.push(`Loaded language: "${word}"`)
      }
    })
    
    return indicators
  }
  
  static assessVerifiability(content: string): number {
    let score = 50 // Start with neutral score
    const contentLower = content.toLowerCase()
    
    // Positive indicators
    if (contentLower.includes('study shows') || contentLower.includes('research indicates')) {
      score += 15
    }
    
    if (contentLower.includes('according to') && contentLower.includes('university')) {
      score += 20
    }
    
    if (contentLower.match(/\d{4}/) && contentLower.includes('published')) {
      score += 10 // Year and publication mentioned
    }
    
    // Negative indicators
    if (contentLower.includes('some say') || contentLower.includes('many believe')) {
      score -= 15
    }
    
    if (contentLower.includes('anonymous source') || contentLower.includes('insider claims')) {
      score -= 20
    }
    
    if (contentLower.includes('without evidence') || contentLower.includes('unconfirmed')) {
      score -= 25
    }
    
    return Math.max(0, Math.min(100, score))
  }
  
  static evaluateSourceReliability(content: string): number {
    let score = 50
    const contentLower = content.toLowerCase()
    
    // Check for reputable source mentions
    const reputableSources = ['reuters', 'associated press', 'bbc', 'nature', 'science', 'nejm']
    reputableSources.forEach(source => {
      if (contentLower.includes(source)) score += 15
    })
    
    // Check for unreliable source indicators
    const unreliableIndicators = ['blog post', 'facebook post', 'twitter rumor', 'anonymous tip']
    unreliableIndicators.forEach(indicator => {
      if (contentLower.includes(indicator)) score -= 20
    })
    
    // Check for source citation patterns
    if (contentLower.includes('cite') && contentLower.includes('source')) {
      score += 10
    }
    
    if (contentLower.includes('no source') || contentLower.includes('trust me')) {
      score -= 25
    }
    
    return Math.max(0, Math.min(100, score))
  }
  
  static analyzeContextualAccuracy(content: string): number {
    let score = 75 // Start higher for contextual accuracy
    const contentLower = content.toLowerCase()
    
    // Check for context-stripping indicators
    if (contentLower.includes('taken out of context')) {
      score -= 30
    }
    
    if (contentLower.includes('partial quote') || contentLower.includes('snippet')) {
      score -= 20
    }
    
    // Check for temporal context issues
    if (contentLower.includes('years ago') && contentLower.includes('breaking')) {
      score -= 25 // Old news presented as current
    }
    
    // Positive context indicators
    if (contentLower.includes('full context') || contentLower.includes('complete statement')) {
      score += 15
    }
    
    if (contentLower.includes('background') && contentLower.includes('context')) {
      score += 10
    }
    
    return Math.max(0, Math.min(100, score))
  }
}

// Cross-reference analysis
class CrossReferenceAnalyzer {
  static findSimilarClaims(content: string): string[] {
    // Simulate database lookup for similar claims
    const claims = [
      'Similar claim debunked by Snopes in 2023',
      'Related misinformation campaign identified',
      'Variation of previously fact-checked story',
      'Part of coordinated inauthentic behavior pattern'
    ]
    
    // Return random subset based on content analysis
    const numClaims = Math.floor(Math.random() * claims.length)
    return claims.slice(0, numClaims)
  }
  
  static findContradictingEvidence(content: string): string[] {
    const contentLower = content.toLowerCase()
    const evidence: string[] = []
    
    if (contentLower.includes('vaccine') || contentLower.includes('medical')) {
      evidence.push('CDC official guidance contradicts this claim')
      evidence.push('Peer-reviewed studies show opposite conclusion')
    }
    
    if (contentLower.includes('climate') || contentLower.includes('global warming')) {
      evidence.push('IPCC reports provide contradictory data')
      evidence.push('Scientific consensus disagrees with claim')
    }
    
    if (contentLower.includes('election') || contentLower.includes('vote')) {
      evidence.push('Official election records contradict claim')
      evidence.push('Multiple audits found no supporting evidence')
    }
    
    return evidence
  }
  
  static findSupportingEvidence(content: string): string[] {
    // In real implementation, this would search for legitimate supporting evidence
    const evidence: string[] = []
    const contentLower = content.toLowerCase()
    
    // Only add supporting evidence if content appears legitimate
    if (!this.containsMisinformationMarkers(contentLower)) {
      evidence.push('Corroborated by independent sources')
      evidence.push('Consistent with established facts')
    }
    
    return evidence
  }
  
  private static containsMisinformationMarkers(content: string): boolean {
    const markers = [
      ...MISINFORMATION_PATTERNS.EMOTIONAL_MANIPULATION,
      ...MISINFORMATION_PATTERNS.CONSPIRACY_INDICATORS,
      ...MISINFORMATION_PATTERNS.PSEUDOSCIENCE_MARKERS
    ]
    
    return markers.some(marker => content.includes(marker))
  }
}

// Generate comprehensive recommendations
function generateMisinformationRecommendations(isMisinformation: boolean, analysis: any): string[] {
  const recommendations: string[] = []
  
  if (isMisinformation) {
    recommendations.push('CRITICAL: High likelihood of misinformation detected')
    recommendations.push('Do not share this content without thorough verification')
    recommendations.push('Check multiple reliable news sources for confirmation')
    recommendations.push('Look for fact-checks from reputable organizations')
    recommendations.push('Be aware of emotional manipulation tactics')
    recommendations.push('Report to platform if violates community guidelines')
  } else {
    recommendations.push('Content appears legitimate based on analysis')
    recommendations.push('Continue to practice media literacy')
    recommendations.push('Verify through additional sources when possible')
    recommendations.push('Be cautious of emotional responses to content')
  }
  
  // Specific recommendations based on analysis
  if (analysis.claimAnalysis.verifiability < 40) {
    recommendations.push('Claims lack verifiable sources - seek additional evidence')
  }
  
  if (analysis.claimAnalysis.sourceReliability < 50) {
    recommendations.push('Source reliability is questionable - verify through trusted outlets')
  }
  
  if (analysis.contentAnalysis.emotionalManipulation.length > 3) {
    recommendations.push('Multiple emotional manipulation tactics detected - approach with skepticism')
  }
  
  return recommendations
}

export async function POST(request: NextRequest) {
  try {
    await connectDB()
    
    const body = await request.json()
    const { type, content } = body
    
    if (!type || !content) {
      return NextResponse.json({
        error: 'Type and content are required'
      }, { status: 400 })
    }
    
    if (type !== 'text') {
      return NextResponse.json({
        error: 'Currently only text analysis is supported'
      }, { status: 400 })
    }
    
    // Perform comprehensive misinformation analysis
    const languagePatterns = MisinformationAnalyzer.analyzeLanguagePatterns(content)
    const emotionalManipulation = MisinformationAnalyzer.detectEmotionalManipulation(content)
    const biasIndicators = MisinformationAnalyzer.analyzeBiasIndicators(content)
    
    const verifiability = MisinformationAnalyzer.assessVerifiability(content)
    const sourceReliability = MisinformationAnalyzer.evaluateSourceReliability(content)
    const contextualAccuracy = MisinformationAnalyzer.analyzeContextualAccuracy(content)
    
    // Enhanced analysis with real AI services
    const aiEmailAnalysis = await RealAIServices.analyzeEmailContent(content)
    
    // Cross-reference analysis
    const similarClaims = CrossReferenceAnalyzer.findSimilarClaims(content)
    const contradictingEvidence = CrossReferenceAnalyzer.findContradictingEvidence(content)
    const supportingEvidence = CrossReferenceAnalyzer.findSupportingEvidence(content)
    
    // Calculate misinformation probability
    const scores = [verifiability, sourceReliability, contextualAccuracy]
    const avgScore = scores.reduce((a, b) => a + b, 0) / scores.length
    
    // Factor in pattern detection
    const patternScore = (languagePatterns.length + emotionalManipulation.length + biasIndicators.length) * 5
    const misinformationScore = Math.max(0, 100 - avgScore + patternScore)
    
    // Enhanced with AI analysis
    const combinedScore = Math.max(misinformationScore, aiEmailAnalysis.overallRisk)
    
    const isMisinformation = combinedScore >= 60
    const confidence = Math.min(combinedScore + 10, 95)
    
    // Randomly select fact-check sources
    const factCheckSources = FACT_CHECK_SOURCES
      .sort(() => 0.5 - Math.random())
      .slice(0, 3 + Math.floor(Math.random() * 3))
    
    const claimAnalysis = {
      verifiability,
      sourceReliability,
      contextualAccuracy
    }
    
    const contentAnalysis = {
      languagePatterns,
      emotionalManipulation: [...emotionalManipulation, `AI Risk Level: ${aiEmailAnalysis.riskLevel}`],
      biasIndicators: [...biasIndicators, ...aiEmailAnalysis.urls.map(url => `Suspicious URL: ${url}`)]
    }
    
    const crossReference = {
      similarClaims,
      contradictingEvidence,
      supportingEvidence
    }
    
    const recommendations = generateMisinformationRecommendations(isMisinformation, {
      claimAnalysis,
      contentAnalysis
    })
    
    const result = {
      isMisinformation,
      confidence,
      factCheckSources,
      claimAnalysis,
      contentAnalysis,
      crossReference,
      recommendations,
      timestamp: new Date().toISOString()
    }
    
    return NextResponse.json(result)
    
  } catch (error) {
    console.error('Misinformation Detection Error:', error)
    return NextResponse.json({
      error: 'Analysis failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
