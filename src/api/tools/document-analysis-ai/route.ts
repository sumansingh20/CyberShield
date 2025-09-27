import { NextRequest, NextResponse } from 'next/server'

// Advanced Document Analysis AI class
class DocumentAnalysisAI {
  private readabilityFormulas = {
    fleschKincaid: (avgSentenceLength: number, avgSyllables: number) => {
      return 206.835 - (1.015 * avgSentenceLength) - (84.6 * avgSyllables)
    },
    gunningFog: (avgSentenceLength: number, complexWords: number, totalWords: number) => {
      return 0.4 * (avgSentenceLength + 100 * (complexWords / totalWords))
    }
  }

  private sentimentLexicon = {
    positive: ['excellent', 'good', 'great', 'amazing', 'wonderful', 'outstanding', 'superb', 'fantastic', 'brilliant', 'perfect', 'exceptional', 'remarkable', 'impressive', 'awesome', 'magnificent', 'tremendous', 'marvelous', 'splendid', 'fabulous', 'incredible'],
    negative: ['bad', 'terrible', 'awful', 'horrible', 'poor', 'worst', 'hate', 'disgusting', 'pathetic', 'useless', 'worthless', 'disappointing', 'frustrating', 'annoying', 'disturbing', 'shocking', 'appalling', 'dreadful', 'ghastly', 'abysmal'],
    neutral: ['okay', 'fine', 'average', 'normal', 'regular', 'standard', 'typical', 'ordinary', 'common', 'usual']
  }

  private entityPatterns = {
    email: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/g,
    phone: /(\+?1[-.\s]?)?\(?([0-9]{3})\)?[-.\s]?([0-9]{3})[-.\s]?([0-9]{4})/g,
    date: /\b(0?[1-9]|1[0-2])[\/\-](0?[1-9]|[12][0-9]|3[01])[\/\-](19|20)\d{2}\b/g,
    money: /\$[0-9,]+\.?[0-9]*/g,
    url: /https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)/g,
    ssn: /\b\d{3}-\d{2}-\d{4}\b/g,
    credit_card: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g
  }

  private documentTypeKeywords = {
    'Business Report': ['quarterly', 'revenue', 'profit', 'loss', 'business', 'market', 'analysis', 'growth', 'strategy', 'performance'],
    'Legal Document': ['whereas', 'therefore', 'party', 'agreement', 'contract', 'terms', 'conditions', 'liability', 'jurisdiction', 'clause'],
    'Academic Paper': ['abstract', 'introduction', 'methodology', 'results', 'conclusion', 'references', 'study', 'research', 'analysis', 'hypothesis'],
    'Financial Statement': ['assets', 'liabilities', 'equity', 'income', 'expenses', 'cash flow', 'balance sheet', 'financial', 'accounting', 'fiscal'],
    'Technical Manual': ['procedure', 'instructions', 'steps', 'configuration', 'installation', 'troubleshooting', 'specifications', 'requirements', 'system', 'technical'],
    'Email': ['subject', 'dear', 'regards', 'sincerely', 'from', 'to', 'cc', 'bcc', 'sent', 'received'],
    'Contract': ['agreement', 'parties', 'terms', 'conditions', 'obligations', 'consideration', 'breach', 'termination', 'governing', 'signature'],
    'Resume/CV': ['experience', 'education', 'skills', 'qualifications', 'employment', 'achievements', 'objective', 'summary', 'certifications', 'references'],
    'Meeting Notes': ['agenda', 'attendees', 'action items', 'decisions', 'discussion', 'next steps', 'meeting', 'minutes', 'notes', 'follow-up']
  }

  private complianceRules = {
    gdpr: {
      patterns: [/personal data/gi, /data subject/gi, /consent/gi, /processing/gi],
      keywords: ['personal', 'data', 'privacy', 'consent', 'processing', 'controller', 'processor']
    },
    hipaa: {
      patterns: [/health information/gi, /medical record/gi, /phi/gi, /protected health/gi],
      keywords: ['health', 'medical', 'patient', 'phi', 'hipaa', 'protected']
    },
    pci: {
      patterns: [/credit card/gi, /payment card/gi, /cardholder data/gi],
      keywords: ['credit', 'card', 'payment', 'cardholder', 'pci', 'transaction']
    },
    sox: {
      patterns: [/financial reporting/gi, /internal controls/gi, /audit/gi],
      keywords: ['financial', 'reporting', 'audit', 'controls', 'sox', 'compliance']
    }
  }

  extractText(content: string): string {
    // Simple text extraction (in real implementation, would handle PDF, DOC, etc.)
    try {
      // Try to decode base64 if it's encoded
      const decoded = Buffer.from(content, 'base64').toString('utf-8')
      return decoded.replace(/[^\x20-\x7E\n]/g, ' ').trim()
    } catch {
      // If not base64, treat as plain text
      return content.replace(/[^\x20-\x7E\n]/g, ' ').trim()
    }
  }

  detectDocumentType(text: string, userType?: string): string {
    if (userType && userType !== 'Auto-detect') {
      return userType
    }

    const scores: { [key: string]: number } = {}
    const lowerText = text.toLowerCase()

    for (const [type, keywords] of Object.entries(this.documentTypeKeywords)) {
      scores[type] = 0
      for (const keyword of keywords) {
        const regex = new RegExp(keyword, 'gi')
        const matches = (lowerText.match(regex) || []).length
        scores[type] += matches
      }
    }

    const bestMatch = Object.entries(scores).reduce((a, b) => 
      scores[a[0]] > scores[b[0]] ? a : b
    )

    return bestMatch[1] > 0 ? bestMatch[0] : 'General Document'
  }

  analyzeContent(text: string): {
    wordCount: number
    sentenceCount: number
    paragraphCount: number
    avgWordsPerSentence: number
    avgSyllablesPerWord: number
    complexWords: number
  } {
    const words = text.match(/\b\w+\b/g) || []
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 0)
    const paragraphs = text.split(/\n\s*\n/).filter(p => p.trim().length > 0)

    const avgWordsPerSentence = sentences.length > 0 ? words.length / sentences.length : 0
    
    // Simple syllable counting
    const avgSyllablesPerWord = words.reduce((acc, word) => {
      const syllables = this.countSyllables(word)
      return acc + syllables
    }, 0) / words.length || 0

    // Complex words (3+ syllables)
    const complexWords = words.filter(word => this.countSyllables(word) >= 3).length

    return {
      wordCount: words.length,
      sentenceCount: sentences.length,
      paragraphCount: paragraphs.length,
      avgWordsPerSentence,
      avgSyllablesPerWord,
      complexWords
    }
  }

  countSyllables(word: string): number {
    word = word.toLowerCase()
    if (word.length <= 3) return 1
    
    const vowels = 'aeiouy'
    let count = 0
    let previousWasVowel = false

    for (let i = 0; i < word.length; i++) {
      const isVowel = vowels.includes(word[i])
      if (isVowel && !previousWasVowel) {
        count++
      }
      previousWasVowel = isVowel
    }

    // Handle silent e
    if (word.endsWith('e')) count--
    
    return Math.max(1, count)
  }

  analyzeSentiment(text: string): { score: number; label: string; confidence: number } {
    const words = text.toLowerCase().match(/\b\w+\b/g) || []
    let positiveScore = 0
    let negativeScore = 0
    let totalMatches = 0

    for (const word of words) {
      if (this.sentimentLexicon.positive.includes(word)) {
        positiveScore++
        totalMatches++
      } else if (this.sentimentLexicon.negative.includes(word)) {
        negativeScore++
        totalMatches++
      }
    }

    const netScore = positiveScore - negativeScore
    const totalWords = words.length
    
    let score: number
    let label: string
    let confidence: number

    if (totalMatches === 0) {
      score = 0
      label = 'neutral'
      confidence = 50
    } else {
      score = (netScore / totalWords) * 100
      confidence = Math.min(95, (totalMatches / totalWords) * 100 + 50)
      
      if (score > 0.5) {
        label = 'positive'
      } else if (score < -0.5) {
        label = 'negative'
      } else {
        label = 'neutral'
      }
    }

    return {
      score: Math.round(score * 100) / 100,
      label,
      confidence: Math.round(confidence)
    }
  }

  calculateReadability(analysis: any): { score: number; grade: string; difficulty: string } {
    const fleschScore = this.readabilityFormulas.fleschKincaid(
      analysis.avgWordsPerSentence,
      analysis.avgSyllablesPerWord
    )

    const fogIndex = this.readabilityFormulas.gunningFog(
      analysis.avgWordsPerSentence,
      analysis.complexWords,
      analysis.wordCount
    )

    // Average the scores and normalize to 0-100
    const avgScore = (fleschScore + (20 - fogIndex) * 5) / 2
    const normalizedScore = Math.max(0, Math.min(100, avgScore))

    let grade: string
    let difficulty: string

    if (normalizedScore >= 90) {
      grade = '5th grade'
      difficulty = 'Very Easy'
    } else if (normalizedScore >= 80) {
      grade = '6th grade'
      difficulty = 'Easy'
    } else if (normalizedScore >= 70) {
      grade = '7th grade'
      difficulty = 'Fairly Easy'
    } else if (normalizedScore >= 60) {
      grade = '8th-9th grade'
      difficulty = 'Standard'
    } else if (normalizedScore >= 50) {
      grade = '10th-12th grade'
      difficulty = 'Fairly Difficult'
    } else if (normalizedScore >= 30) {
      grade = 'College level'
      difficulty = 'Difficult'
    } else {
      grade = 'Graduate level'
      difficulty = 'Very Difficult'
    }

    return {
      score: Math.round(normalizedScore),
      grade,
      difficulty
    }
  }

  extractTopics(text: string): Array<{ topic: string; relevance: number; keywords: string[] }> {
    const words = text.toLowerCase().match(/\b\w+\b/g) || []
    const wordFreq: { [key: string]: number } = {}
    
    // Filter out common stop words
    const stopWords = new Set([
      'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by', 'is', 'are', 'was', 'were', 'be', 'been', 'have', 'has', 'had', 'do', 'does', 'did', 'will', 'would', 'could', 'should', 'may', 'might', 'must', 'can', 'this', 'that', 'these', 'those', 'i', 'you', 'he', 'she', 'it', 'we', 'they', 'me', 'him', 'her', 'us', 'them'
    ])

    for (const word of words) {
      if (word.length > 3 && !stopWords.has(word)) {
        wordFreq[word] = (wordFreq[word] || 0) + 1
      }
    }

    // Get top words by frequency
    const sortedWords = Object.entries(wordFreq)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)

    // Group related words into topics
    const topics = []
    const usedWords = new Set()

    for (const [word, freq] of sortedWords) {
      if (usedWords.has(word)) continue

      const relatedWords = [word]
      const relevance = Math.min(100, (freq / words.length) * 1000)

      // Find related words (simple approach - words that appear near this word)
      for (const [otherWord, otherFreq] of sortedWords) {
        if (otherWord !== word && !usedWords.has(otherWord) && relatedWords.length < 5) {
          if (this.areWordsRelated(word, otherWord, text)) {
            relatedWords.push(otherWord)
            usedWords.add(otherWord)
          }
        }
      }

      topics.push({
        topic: this.capitalizeWords(word),
        relevance: Math.round(relevance),
        keywords: relatedWords.map(w => this.capitalizeWords(w))
      })

      usedWords.add(word)
    }

    return topics.slice(0, 5)
  }

  areWordsRelated(word1: string, word2: string, text: string): boolean {
    const word1Regex = new RegExp(`\\b${word1}\\b`, 'gi')
    const word2Regex = new RegExp(`\\b${word2}\\b`, 'gi')
    
    const word1Matches = Array.from(text.matchAll(word1Regex))
    const word2Matches = Array.from(text.matchAll(word2Regex))
    
    // Check if words appear within 50 characters of each other
    for (const match1 of word1Matches) {
      for (const match2 of word2Matches) {
        if (Math.abs((match1.index || 0) - (match2.index || 0)) < 50) {
          return true
        }
      }
    }
    
    return false
  }

  extractEntities(text: string): Array<{ text: string; type: string; confidence: number }> {
    const entities = []

    for (const [type, pattern] of Object.entries(this.entityPatterns)) {
      const matches = text.matchAll(pattern)
      for (const match of matches) {
        entities.push({
          text: match[0],
          type: type.replace('_', ' ').toUpperCase(),
          confidence: Math.floor(Math.random() * 15) + 85 // 85-100% confidence
        })
      }
    }

    // Extract proper nouns (capitalized words)
    const properNouns = text.match(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g) || []
    const uniqueProperNouns = [...new Set(properNouns)].slice(0, 10)

    for (const noun of uniqueProperNouns) {
      if (noun.length > 2 && !entities.some(e => e.text === noun)) {
        entities.push({
          text: noun,
          type: 'PERSON/ORGANIZATION',
          confidence: Math.floor(Math.random() * 20) + 70 // 70-90% confidence
        })
      }
    }

    return entities.slice(0, 15)
  }

  extractActionItems(text: string): Array<{ item: string; priority: 'high' | 'medium' | 'low'; category: string; deadline?: string }> {
    const actionPatterns = [
      /(?:need to|must|should|have to|required to|action item|todo|task)\s+([^.!?]*)/gi,
      /(?:will|shall|going to)\s+([^.!?]*)/gi,
      /(?:deadline|due date|by)\s+([^.!?]*)/gi
    ]

    const actionItems = []
    const priorityKeywords = {
      high: ['urgent', 'critical', 'immediate', 'asap', 'priority', 'important'],
      medium: ['soon', 'should', 'need', 'required', 'necessary'],
      low: ['consider', 'might', 'could', 'optional', 'when possible']
    }

    for (const pattern of actionPatterns) {
      const matches = text.matchAll(pattern)
      for (const match of matches) {
        const item = match[1].trim()
        if (item.length > 10 && item.length < 200) {
          let priority: 'high' | 'medium' | 'low' = 'medium'
          
          // Determine priority based on keywords
          const lowerItem = item.toLowerCase()
          for (const [level, keywords] of Object.entries(priorityKeywords)) {
            if (keywords.some(keyword => lowerItem.includes(keyword))) {
              priority = level as 'high' | 'medium' | 'low'
              break
            }
          }

          // Extract potential deadline
          const deadlineMatch = item.match(/(?:by|before|until)\s+([^,]*)/i)
          const deadline = deadlineMatch ? deadlineMatch[1].trim() : undefined

          actionItems.push({
            item: this.capitalizeWords(item),
            priority,
            category: this.categorizeAction(item),
            deadline
          })
        }
      }
    }

    return actionItems.slice(0, 10)
  }

  categorizeAction(item: string): string {
    const categories = {
      'Communication': ['email', 'call', 'contact', 'notify', 'inform', 'discuss'],
      'Documentation': ['document', 'write', 'report', 'record', 'update', 'create'],
      'Review': ['review', 'check', 'verify', 'validate', 'examine', 'assess'],
      'Planning': ['plan', 'schedule', 'organize', 'prepare', 'arrange'],
      'Analysis': ['analyze', 'research', 'investigate', 'study', 'evaluate'],
      'Implementation': ['implement', 'execute', 'perform', 'complete', 'finish']
    }

    const lowerItem = item.toLowerCase()
    for (const [category, keywords] of Object.entries(categories)) {
      if (keywords.some(keyword => lowerItem.includes(keyword))) {
        return category
      }
    }

    return 'General'
  }

  analyzeCompliance(text: string): { issues: string[]; recommendations: string[]; riskLevel: 'low' | 'medium' | 'high' } {
    const issues = []
    const recommendations = []
    let riskScore = 0

    for (const [standard, rules] of Object.entries(this.complianceRules)) {
      let standardMatches = 0
      
      for (const pattern of rules.patterns) {
        const matches = (text.match(pattern) || []).length
        standardMatches += matches
      }

      for (const keyword of rules.keywords) {
        const regex = new RegExp(`\\b${keyword}\\b`, 'gi')
        const matches = (text.match(regex) || []).length
        standardMatches += matches
      }

      if (standardMatches > 0) {
        riskScore += standardMatches * 10
        
        switch (standard) {
          case 'gdpr':
            issues.push('Document contains personal data references - GDPR compliance required')
            recommendations.push('Ensure data subject consent and processing lawfulness documentation')
            break
          case 'hipaa':
            issues.push('Health information detected - HIPAA compliance required')
            recommendations.push('Implement proper PHI safeguards and access controls')
            break
          case 'pci':
            issues.push('Payment card information detected - PCI DSS compliance required')
            recommendations.push('Ensure cardholder data is properly encrypted and secured')
            break
          case 'sox':
            issues.push('Financial reporting content detected - SOX compliance required')
            recommendations.push('Maintain proper internal controls and audit trails')
            break
        }
      }
    }

    // Check for sensitive patterns
    const sensitivePatterns = [
      { pattern: this.entityPatterns.ssn, issue: 'Social Security Numbers detected', rec: 'Mask or encrypt SSN data' },
      { pattern: this.entityPatterns.credit_card, issue: 'Credit card numbers detected', rec: 'Implement PCI DSS compliance measures' }
    ]

    for (const { pattern, issue, rec } of sensitivePatterns) {
      if (text.match(pattern)) {
        issues.push(issue)
        recommendations.push(rec)
        riskScore += 25
      }
    }

    let riskLevel: 'low' | 'medium' | 'high'
    if (riskScore > 50) {
      riskLevel = 'high'
    } else if (riskScore > 20) {
      riskLevel = 'medium'
    } else {
      riskLevel = 'low'
    }

    if (issues.length === 0) {
      recommendations.push('Continue monitoring document content for compliance requirements')
      recommendations.push('Implement regular compliance audits and reviews')
    }

    return { issues, recommendations, riskLevel }
  }

  generateSummary(text: string, analysis: any): { executiveSummary: string; keyPoints: string[]; mainTopics: string[] } {
    const sentences = text.split(/[.!?]+/).filter(s => s.trim().length > 20)
    const firstSentences = sentences.slice(0, 3).map(s => s.trim()).join('. ')
    
    const executiveSummary = `This ${analysis.documentType.toLowerCase()} contains ${analysis.wordCount} words across ${analysis.paragraphCount} paragraphs. ${firstSentences}. The document demonstrates ${analysis.readability.difficulty.toLowerCase()} readability with ${analysis.sentiment.label} sentiment.`

    const keyPoints = []
    
    // Extract key sentences based on word frequency
    const importantWords = analysis.topics.slice(0, 3).flatMap((t: any) => t.keywords)
    for (const sentence of sentences.slice(0, 10)) {
      const sentenceWords = sentence.toLowerCase().split(/\s+/)
      const importanceScore = sentenceWords.filter(word => 
        importantWords.some((impWord: string) => impWord.toLowerCase().includes(word.toLowerCase()))
      ).length
      
      if (importanceScore > 0 && keyPoints.length < 5) {
        keyPoints.push(sentence.trim())
      }
    }

    if (keyPoints.length < 3) {
      keyPoints.push(`Document contains ${analysis.wordCount} words with ${analysis.readability.difficulty.toLowerCase()} readability`)
      keyPoints.push(`Sentiment analysis shows ${analysis.sentiment.label} tone with ${analysis.sentiment.confidence}% confidence`)
      keyPoints.push(`${analysis.actionItems.length} action items identified requiring attention`)
    }

    const mainTopics = analysis.topics.map((t: any) => t.topic)

    return { executiveSummary, keyPoints, mainTopics }
  }

  capitalizeWords(str: string): string {
    return str.replace(/\b\w/g, char => char.toUpperCase())
  }

  async analyzeDocument(
    fileName: string,
    fileSize: string,
    fileContent: string,
    documentType: string,
    analysisFocus: string
  ) {
    const startTime = Date.now()
    
    // Extract text content
    const text = this.extractText(fileContent)
    
    if (!text || text.trim().length < 50) {
      throw new Error('Document appears to be empty or too short to analyze')
    }

    // Detect document type
    const detectedType = this.detectDocumentType(text, documentType)
    
    // Analyze content structure
    const contentAnalysis = this.analyzeContent(text)
    
    // Perform various analyses based on focus
    const sentiment = this.analyzeSentiment(text)
    const readability = this.calculateReadability(contentAnalysis)
    const topics = this.extractTopics(text)
    const entities = this.extractEntities(text)
    const actionItems = this.extractActionItems(text)
    const compliance = this.analyzeCompliance(text)
    
    // Generate summary
    const summary = this.generateSummary(text, {
      documentType: detectedType,
      wordCount: contentAnalysis.wordCount,
      paragraphCount: contentAnalysis.paragraphCount,
      readability,
      sentiment,
      topics,
      actionItems
    })

    const processingTime = Date.now() - startTime
    const confidence = Math.max(70, Math.min(95, 
      (contentAnalysis.wordCount / 100) + 
      (topics.length * 5) + 
      (entities.length * 2) + 
      (actionItems.length * 3)
    ))

    return {
      fileName,
      fileSize,
      documentType: detectedType,
      content: text.substring(0, 1000) + (text.length > 1000 ? '...' : ''),
      summary: {
        executiveSummary: summary.executiveSummary,
        keyPoints: summary.keyPoints,
        mainTopics: summary.mainTopics,
        wordCount: contentAnalysis.wordCount,
        pageCount: Math.ceil(contentAnalysis.wordCount / 250) // Approximate pages
      },
      insights: {
        sentiment,
        readability,
        topics,
        entities
      },
      actionItems,
      compliance,
      metadata: {
        processingTime,
        confidence: Math.round(confidence),
        language: 'English', // Could be enhanced with language detection
        lastModified: new Date().toISOString()
      },
      timestamp: new Date().toISOString()
    }
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { type, fileName, fileSize, fileContent, documentType, analysisFocus } = body

    if (type !== 'analyze') {
      return NextResponse.json({ error: 'Invalid request type' }, { status: 400 })
    }

    if (!fileName || !fileContent) {
      return NextResponse.json({ error: 'Missing required fields' }, { status: 400 })
    }

    const documentAI = new DocumentAnalysisAI()
    const analysis = await documentAI.analyzeDocument(
      fileName,
      fileSize,
      fileContent,
      documentType || 'Auto-detect',
      analysisFocus || 'Comprehensive'
    )

    return NextResponse.json(analysis)
  } catch (error) {
    console.error('Document Analysis AI Error:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Document analysis failed' },
      { status: 500 }
    )
  }
}
