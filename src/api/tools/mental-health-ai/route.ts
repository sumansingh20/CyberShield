import { NextRequest, NextResponse } from 'next/server'

interface MoodEntry {
  id: string
  mood: 'very_sad' | 'sad' | 'neutral' | 'happy' | 'very_happy'
  intensity: number
  factors: string[]
  notes: string
  timestamp: string
}

interface MentalHealthAnalysis {
  userId: string
  currentMood: {
    mood: string
    intensity: number
    description: string
    color: string
  }
  moodTrends: {
    weeklyAverage: number
    monthlyAverage: number
    trend: 'improving' | 'stable' | 'declining'
    streaks: {
      current: number
      longest: number
    }
  }
  wellnessScore: {
    overall: number
    categories: {
      emotional: number
      social: number
      physical: number
      mental: number
    }
  }
  recommendations: Array<{
    type: 'activity' | 'therapy' | 'lifestyle' | 'professional'
    title: string
    description: string
    priority: 'low' | 'medium' | 'high'
    duration: string
    category: string
  }>
  insights: {
    patterns: string[]
    triggers: string[]
    strengths: string[]
    concerns: string[]
  }
  resources: Array<{
    type: 'article' | 'exercise' | 'meditation' | 'helpline'
    title: string
    description: string
    url?: string
    duration?: string
  }>
  riskAssessment: {
    level: 'low' | 'moderate' | 'high'
    factors: string[]
    recommendations: string[]
    emergencyContacts: Array<{
      name: string
      number: string
      available: string
    }>
  }
  timestamp: string
}

class MentalHealthAI {
  private static instance: MentalHealthAI
  
  private constructor() {}
  
  static getInstance(): MentalHealthAI {
    if (!MentalHealthAI.instance) {
      MentalHealthAI.instance = new MentalHealthAI()
    }
    return MentalHealthAI.instance
  }

  analyzeMoodPatterns(moodHistory: MoodEntry[]): MentalHealthAnalysis {
    const currentEntry = moodHistory[0]
    
    // Calculate mood averages
    const recentEntries = moodHistory.slice(0, 7) // Last week
    const monthlyEntries = moodHistory.slice(0, 30) // Last month
    
    const weeklyAverage = this.calculateMoodAverage(recentEntries)
    const monthlyAverage = this.calculateMoodAverage(monthlyEntries)
    
    // Determine trend
    const trend = this.determineMoodTrend(moodHistory)
    
    // Calculate streaks
    const streaks = this.calculateMoodStreaks(moodHistory)
    
    // Generate wellness score
    const wellnessScore = this.calculateWellnessScore(moodHistory, currentEntry)
    
    // Generate insights
    const insights = this.generateInsights(moodHistory)
    
    // Generate recommendations
    const recommendations = this.generateRecommendations(currentEntry, insights, wellnessScore)
    
    // Risk assessment
    const riskAssessment = this.assessRisk(moodHistory, currentEntry)
    
    // Generate resources
    const resources = this.generateResources(currentEntry, riskAssessment)

    return {
      userId: 'current_user',
      currentMood: this.describeMood(currentEntry),
      moodTrends: {
        weeklyAverage,
        monthlyAverage,
        trend,
        streaks
      },
      wellnessScore,
      recommendations,
      insights,
      resources,
      riskAssessment,
      timestamp: new Date().toISOString()
    }
  }

  private describeMood(entry: MoodEntry) {
    const moodDescriptions: Record<string, string> = {
      very_sad: 'Very Low',
      sad: 'Low',
      neutral: 'Balanced',
      happy: 'Good',
      very_happy: 'Excellent'
    }

    const moodColors: Record<string, string> = {
      very_sad: '#ef4444',
      sad: '#f97316',
      neutral: '#6b7280',
      happy: '#22c55e',
      very_happy: '#3b82f6'
    }

    return {
      mood: entry.mood,
      intensity: entry.intensity,
      description: moodDescriptions[entry.mood] || 'Unknown',
      color: moodColors[entry.mood] || '#6b7280'
    }
  }

  private calculateMoodAverage(entries: MoodEntry[]): number {
    if (entries.length === 0) return 5
    
    const moodValues: Record<string, number> = {
      very_sad: 2,
      sad: 4,
      neutral: 5,
      happy: 7,
      very_happy: 9
    }
    
    const total = entries.reduce((sum, entry) => {
      const baseValue = moodValues[entry.mood] || 5
      return sum + (baseValue * (entry.intensity / 10))
    }, 0)
    
    return Math.round((total / entries.length) * 10) / 10
  }

  private determineMoodTrend(moodHistory: MoodEntry[]): 'improving' | 'stable' | 'declining' {
    if (moodHistory.length < 3) return 'stable'
    
    const recent = this.calculateMoodAverage(moodHistory.slice(0, 3))
    const previous = this.calculateMoodAverage(moodHistory.slice(3, 6))
    
    if (recent > previous + 0.5) return 'improving'
    if (recent < previous - 0.5) return 'declining'
    return 'stable'
  }

  private calculateMoodStreaks(moodHistory: MoodEntry[]): { current: number; longest: number } {
    if (moodHistory.length === 0) return { current: 0, longest: 0 }
    
    let currentStreak = 1
    let longestStreak = 1
    let tempStreak = 1
    
    const isPositiveMood = (mood: string) => ['happy', 'very_happy'].includes(mood)
    
    const currentMoodPositive = isPositiveMood(moodHistory[0].mood)
    
    for (let i = 1; i < moodHistory.length; i++) {
      const prevPositive = isPositiveMood(moodHistory[i-1].mood)
      const currPositive = isPositiveMood(moodHistory[i].mood)
      
      if (prevPositive === currPositive) {
        tempStreak++
        if (i === 1 || (currentMoodPositive === currPositive)) {
          currentStreak = tempStreak
        }
      } else {
        longestStreak = Math.max(longestStreak, tempStreak)
        tempStreak = 1
        if (i === 1) currentStreak = 1
      }
    }
    
    longestStreak = Math.max(longestStreak, tempStreak)
    
    return { current: currentStreak, longest: longestStreak }
  }

  private calculateWellnessScore(moodHistory: MoodEntry[], currentEntry: MoodEntry) {
    const moodAverage = this.calculateMoodAverage(moodHistory.slice(0, 7))
    const consistencyScore = this.calculateConsistency(moodHistory)
    const factorDiversityScore = this.calculateFactorDiversity(moodHistory)
    
    const emotional = Math.min(100, Math.max(0, (moodAverage / 10) * 100))
    const social = this.calculateSocialScore(moodHistory)
    const physical = this.calculatePhysicalScore(moodHistory)
    const mental = Math.min(100, Math.max(0, (consistencyScore + factorDiversityScore) / 2 * 100))
    
    const overall = Math.round((emotional + social + physical + mental) / 4)
    
    return {
      overall,
      categories: {
        emotional: Math.round(emotional),
        social: Math.round(social),
        physical: Math.round(physical),
        mental: Math.round(mental)
      }
    }
  }

  private calculateConsistency(moodHistory: MoodEntry[]): number {
    if (moodHistory.length < 2) return 0.5
    
    let variance = 0
    const average = this.calculateMoodAverage(moodHistory)
    
    for (const entry of moodHistory) {
      const moodValue = this.getMoodValue(entry.mood) * (entry.intensity / 10)
      variance += Math.pow(moodValue - average, 2)
    }
    
    const standardDeviation = Math.sqrt(variance / moodHistory.length)
    return Math.max(0, 1 - (standardDeviation / 5)) // Normalize to 0-1
  }

  private calculateFactorDiversity(moodHistory: MoodEntry[]): number {
    const allFactors = new Set()
    moodHistory.forEach(entry => {
      entry.factors.forEach(factor => allFactors.add(factor))
    })
    
    return Math.min(1, allFactors.size / 12) // Assuming 12 possible factors
  }

  private calculateSocialScore(moodHistory: MoodEntry[]): number {
    const socialFactors = ['Relationships', 'Family', 'Social Media']
    let socialEntries = 0
    let positiveSocialEntries = 0
    
    moodHistory.forEach(entry => {
      const hasSocialFactor = entry.factors.some(factor => socialFactors.includes(factor))
      if (hasSocialFactor) {
        socialEntries++
        if (['happy', 'very_happy'].includes(entry.mood)) {
          positiveSocialEntries++
        }
      }
    })
    
    if (socialEntries === 0) return 70 // Neutral assumption
    return (positiveSocialEntries / socialEntries) * 100
  }

  private calculatePhysicalScore(moodHistory: MoodEntry[]): number {
    const physicalFactors = ['Exercise', 'Sleep', 'Health', 'Food']
    let physicalEntries = 0
    let positivePhysicalEntries = 0
    
    moodHistory.forEach(entry => {
      const hasPhysicalFactor = entry.factors.some(factor => physicalFactors.includes(factor))
      if (hasPhysicalFactor) {
        physicalEntries++
        if (['happy', 'very_happy'].includes(entry.mood)) {
          positivePhysicalEntries++
        }
      }
    })
    
    if (physicalEntries === 0) return 70 // Neutral assumption
    return (positivePhysicalEntries / physicalEntries) * 100
  }

  private getMoodValue(mood: string): number {
    const values: Record<string, number> = {
      very_sad: 2,
      sad: 4,
      neutral: 5,
      happy: 7,
      very_happy: 9
    }
    return values[mood] || 5
  }

  private generateInsights(moodHistory: MoodEntry[]) {
    const patterns: string[] = []
    const triggers: string[] = []
    const strengths: string[] = []
    const concerns: string[] = []

    // Analyze patterns
    const factorFrequency: Record<string, number> = {}
    const factorMoodImpact: Record<string, number[]> = {}
    
    moodHistory.forEach(entry => {
      entry.factors.forEach(factor => {
        factorFrequency[factor] = (factorFrequency[factor] || 0) + 1
        if (!factorMoodImpact[factor]) factorMoodImpact[factor] = []
        factorMoodImpact[factor].push(this.getMoodValue(entry.mood))
      })
    })

    // Find patterns
    Object.entries(factorFrequency).forEach(([factor, frequency]) => {
      if (frequency >= 3) {
        const avgMoodImpact = factorMoodImpact[factor].reduce((a, b) => a + b, 0) / factorMoodImpact[factor].length
        
        if (avgMoodImpact >= 7) {
          patterns.push(`${factor} consistently improves your mood`)
          strengths.push(`Positive relationship with ${factor.toLowerCase()}`)
        } else if (avgMoodImpact <= 4) {
          patterns.push(`${factor} tends to negatively affect your mood`)
          triggers.push(`${factor} appears to be a mood trigger`)
        }
      }
    })

    // Analyze time patterns
    const recentMood = this.calculateMoodAverage(moodHistory.slice(0, 7))
    const olderMood = this.calculateMoodAverage(moodHistory.slice(7, 14))
    
    if (recentMood > olderMood + 0.5) {
      patterns.push('Your mood has been improving over the past week')
      strengths.push('Positive momentum in recent mood trends')
    } else if (recentMood < olderMood - 0.5) {
      patterns.push('Your mood has been declining recently')
      concerns.push('Recent downward trend in mood ratings')
    }

    // Check for concerning patterns
    const lowMoodCount = moodHistory.slice(0, 7).filter(entry => 
      ['very_sad', 'sad'].includes(entry.mood)
    ).length
    
    if (lowMoodCount >= 4) {
      concerns.push('Multiple low mood entries in the past week')
    }

    // Add default insights if none found
    if (patterns.length === 0) {
      patterns.push('Building consistent mood tracking habits')
    }
    if (strengths.length === 0) {
      strengths.push('Taking proactive steps to monitor mental health')
    }

    return { patterns, triggers, strengths, concerns }
  }

  private generateRecommendations(currentEntry: MoodEntry, insights: any, wellnessScore: any) {
    const recommendations: Array<{
      type: 'activity' | 'therapy' | 'lifestyle' | 'professional'
      title: string
      description: string
      priority: 'low' | 'medium' | 'high'
      duration: string
      category: string
    }> = []

    // Mood-based recommendations
    if (['very_sad', 'sad'].includes(currentEntry.mood)) {
      recommendations.push({
        type: 'activity',
        title: 'Gentle Movement Exercise',
        description: 'Light physical activity like walking or stretching can help improve mood naturally',
        priority: 'high',
        duration: '15-30 minutes',
        category: 'Physical Wellness'
      })
      
      recommendations.push({
        type: 'therapy',
        title: 'Breathing Exercise',
        description: 'Practice deep breathing techniques to help regulate emotions and reduce stress',
        priority: 'high',
        duration: '5-10 minutes',
        category: 'Emotional Regulation'
      })
    }

    // Factor-based recommendations
    if (currentEntry.factors.includes('Work/School')) {
      recommendations.push({
        type: 'lifestyle',
        title: 'Work-Life Balance Check',
        description: 'Review your daily schedule and identify opportunities for better balance',
        priority: 'medium',
        duration: '20 minutes',
        category: 'Life Balance'
      })
    }

    if (currentEntry.factors.includes('Sleep')) {
      recommendations.push({
        type: 'lifestyle',
        title: 'Sleep Hygiene Review',
        description: 'Establish a consistent bedtime routine and optimize your sleep environment',
        priority: 'high',
        duration: 'Ongoing',
        category: 'Sleep Health'
      })
    }

    if (currentEntry.factors.includes('Relationships')) {
      recommendations.push({
        type: 'activity',
        title: 'Social Connection',
        description: 'Reach out to a trusted friend or family member for support or conversation',
        priority: 'medium',
        duration: '30-60 minutes',
        category: 'Social Wellness'
      })
    }

    // Wellness score based recommendations
    if (wellnessScore.overall < 60) {
      recommendations.push({
        type: 'professional',
        title: 'Consider Professional Support',
        description: 'Speaking with a mental health professional can provide additional strategies and support',
        priority: 'high',
        duration: 'As needed',
        category: 'Professional Care'
      })
    }

    // General wellness recommendations
    recommendations.push({
      type: 'activity',
      title: 'Mindfulness Meditation',
      description: 'Practice present-moment awareness to reduce anxiety and improve emotional regulation',
      priority: 'medium',
      duration: '10-20 minutes',
      category: 'Mindfulness'
    })

    recommendations.push({
      type: 'lifestyle',
      title: 'Gratitude Practice',
      description: 'Write down three things you\'re grateful for each day to boost positive emotions',
      priority: 'low',
      duration: '5 minutes',
      category: 'Positive Psychology'
    })

    return recommendations
  }

  private assessRisk(moodHistory: MoodEntry[], currentEntry: MoodEntry) {
    let riskLevel: 'low' | 'moderate' | 'high' = 'low'
    const factors: string[] = []
    const recommendations: string[] = []

    // Check recent mood patterns
    const recentLowMoods = moodHistory.slice(0, 7).filter(entry => 
      ['very_sad', 'sad'].includes(entry.mood)
    ).length

    const currentIntensity = currentEntry.intensity
    const currentMoodLow = ['very_sad', 'sad'].includes(currentEntry.mood)

    if (recentLowMoods >= 5 || (currentMoodLow && currentIntensity <= 3)) {
      riskLevel = 'high'
      factors.push('Persistent low mood over recent period')
      factors.push('Significant impact on daily functioning likely')
      recommendations.push('Seek immediate professional mental health support')
      recommendations.push('Consider contacting a crisis helpline if needed')
    } else if (recentLowMoods >= 3 || (currentMoodLow && currentIntensity <= 5)) {
      riskLevel = 'moderate'
      factors.push('Multiple recent low mood episodes')
      recommendations.push('Consider scheduling appointment with mental health professional')
      recommendations.push('Increase self-care activities and social support')
    } else {
      factors.push('No immediate risk factors identified')
      recommendations.push('Continue regular mood monitoring')
      recommendations.push('Maintain healthy lifestyle habits')
    }

    const emergencyContacts = [
      {
        name: 'National Suicide Prevention Lifeline',
        number: '988',
        available: '24/7'
      },
      {
        name: 'Crisis Text Line',
        number: 'Text HOME to 741741',
        available: '24/7'
      },
      {
        name: 'SAMHSA National Helpline',
        number: '1-800-662-4357',
        available: '24/7'
      }
    ]

    return {
      level: riskLevel,
      factors,
      recommendations,
      emergencyContacts
    }
  }

  private generateResources(currentEntry: MoodEntry, riskAssessment: any) {
    const resources: Array<{
      type: 'article' | 'exercise' | 'meditation' | 'helpline'
      title: string
      description: string
      url?: string
      duration?: string
    }> = []

    // Mood-specific resources
    if (['very_sad', 'sad'].includes(currentEntry.mood)) {
      resources.push({
        type: 'meditation',
        title: 'Guided Meditation for Difficult Emotions',
        description: 'A 10-minute guided meditation to help process and accept difficult feelings',
        duration: '10 minutes'
      })

      resources.push({
        type: 'article',
        title: 'Understanding Depression and Low Mood',
        description: 'Educational resource about the nature of depression and evidence-based treatments',
      })
    }

    // General mental health resources
    resources.push({
      type: 'exercise',
      title: 'Progressive Muscle Relaxation',
      description: 'A systematic relaxation technique to reduce physical tension and mental stress',
      duration: '15-20 minutes'
    })

    resources.push({
      type: 'meditation',
      title: 'Daily Mindfulness Practice',
      description: 'Simple mindfulness exercises to incorporate throughout your day',
      duration: '5-15 minutes'
    })

    resources.push({
      type: 'article',
      title: 'Building Emotional Resilience',
      description: 'Strategies for developing emotional strength and coping skills',
    })

    // Risk-based resources
    if (riskAssessment.level === 'high') {
      resources.unshift({
        type: 'helpline',
        title: 'Immediate Crisis Support',
        description: 'Free, confidential support available 24/7 for people in emotional distress',
      })
    }

    resources.push({
      type: 'exercise',
      title: 'Journaling for Mental Health',
      description: 'Structured writing exercises to process emotions and track progress',
      duration: '10-30 minutes'
    })

    return resources
  }

  generateChatResponse(message: string, context: any): string {
    const lowercaseMessage = message.toLowerCase()
    
    // Crisis detection
    const crisisKeywords = ['suicide', 'kill myself', 'end it all', 'can\'t go on', 'hopeless', 'worthless']
    if (crisisKeywords.some(keyword => lowercaseMessage.includes(keyword))) {
      return `I'm very concerned about what you're sharing. Your life has value and there are people who want to help. Please consider reaching out immediately:

• National Suicide Prevention Lifeline: 988
• Crisis Text Line: Text HOME to 741741
• Or contact your local emergency services: 911

If you're not in immediate danger but need support, I'm here to listen and help you find resources. Would you like me to suggest some coping strategies for right now?`
    }

    // Mood-related responses
    if (lowercaseMessage.includes('sad') || lowercaseMessage.includes('depressed') || lowercaseMessage.includes('down')) {
      return `I hear that you're feeling sad right now. That takes courage to share. Sadness is a natural human emotion, even though it doesn't feel good. 

Some things that might help:
• Take a few deep breaths with me - in for 4, hold for 4, out for 4
• Can you think of one small thing that brought you comfort recently?
• Sometimes moving our body gently (even just stretching) can help shift our emotional state

What feels most manageable for you right now? I'm here to support you through this.`
    }

    if (lowercaseMessage.includes('anxious') || lowercaseMessage.includes('worried') || lowercaseMessage.includes('stress')) {
      return `Anxiety can feel overwhelming, but you're taking a positive step by reaching out. Let's work through this together.

Try this grounding technique:
• Name 5 things you can see around you
• Name 4 things you can touch
• Name 3 things you can hear
• Name 2 things you can smell
• Name 1 thing you can taste

This helps bring your mind back to the present moment. Anxiety often focuses on future worries, but right now, in this moment, you are safe. What's one small step you could take today to care for yourself?`
    }

    if (lowercaseMessage.includes('angry') || lowercaseMessage.includes('frustrated') || lowercaseMessage.includes('mad')) {
      return `Anger is a valid emotion - it often tells us that something important to us feels threatened or violated. Let's channel that energy constructively.

Some healthy ways to process anger:
• Physical release: Go for a walk, do jumping jacks, or squeeze a stress ball
• Express it safely: Write in a journal, talk to a trusted friend, or record a voice memo
• Breathe: Try the 4-7-8 technique - breathe in for 4, hold for 7, out for 8

What do you think might be underneath the anger? Sometimes anger protects other feelings like hurt or fear. I'm here to help you explore this safely.`
    }

    // General supportive responses
    if (lowercaseMessage.includes('lonely') || lowercaseMessage.includes('alone')) {
      return `Loneliness can feel so heavy, but please know that reaching out here shows your strength. You're not as alone as you might feel right now.

Consider these connection opportunities:
• Reach out to one person - even a simple "thinking of you" text
• Join an online community around an interest you have
• Volunteer for a cause you care about
• Practice self-compassion - talk to yourself like you would a good friend

What's one small way you could connect with another person today? Even small connections can help ease the feeling of loneliness.`
    }

    if (lowercaseMessage.includes('sleep') || lowercaseMessage.includes('tired') || lowercaseMessage.includes('insomnia')) {
      return `Sleep difficulties can really impact our mental health. Good sleep hygiene can make a big difference:

• Keep a consistent sleep schedule, even on weekends
• Create a relaxing bedtime routine (no screens 1 hour before bed)
• Make your bedroom cool, dark, and quiet
• Avoid caffeine after 2 PM and large meals before bed
• Try progressive muscle relaxation or gentle breathing exercises

If sleep problems persist, consider talking to a healthcare provider. Quality sleep is fundamental to mental wellness. What's one small change you could try tonight?`
    }

    // Default supportive response
    const responses = [
      `Thank you for sharing with me. It sounds like you're going through something challenging right now. Remember that seeking support - even from an AI companion like me - shows strength and self-awareness.

What's one thing that's been on your mind lately? I'm here to listen and offer support.`,

      `I appreciate you taking the time to check in with me. Everyone faces ups and downs in their mental health journey, and it's okay to not be okay sometimes.

Is there something specific you'd like to talk through, or would you prefer some general wellness suggestions? I'm here to support you however feels most helpful.`,

      `It's good to connect with you. Mental health is just as important as physical health, and taking time to reflect and seek support is a positive step.

How are you feeling right now, and what would be most helpful for you in this moment? Whether you need practical strategies, someone to listen, or just a moment of encouragement, I'm here for you.`
    ]

    return responses[Math.floor(Math.random() * responses.length)]
  }
}

export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { type, moodHistory, currentEntry, message, context } = body

    const mentalHealthAI = MentalHealthAI.getInstance()

    if (type === 'analyze') {
      if (!moodHistory || !Array.isArray(moodHistory)) {
        return NextResponse.json(
          { error: 'Mood history is required for analysis' },
          { status: 400 }
        )
      }

      const analysis = mentalHealthAI.analyzeMoodPatterns(moodHistory)
      return NextResponse.json(analysis)
    }

    if (type === 'chat') {
      if (!message || typeof message !== 'string') {
        return NextResponse.json(
          { error: 'Message is required for chat' },
          { status: 400 }
        )
      }

      const response = mentalHealthAI.generateChatResponse(message, context)
      return NextResponse.json({ response })
    }

    return NextResponse.json(
      { error: 'Invalid request type' },
      { status: 400 }
    )

  } catch (error) {
    console.error('Mental Health AI Error:', error)
    return NextResponse.json(
      { error: 'Mental health analysis failed' },
      { status: 500 }
    )
  }
}
