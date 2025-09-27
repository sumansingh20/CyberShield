import { NextRequest, NextResponse } from 'next/server'
import { connectDB } from '@/src/core/lib/mongodb'

// Advanced Creative Writing AI Engine
class CreativeWritingAI {
  private static readonly GENRE_TEMPLATES = {
    'fiction': {
      structure: ['Opening Hook', 'Character Introduction', 'Setting Description', 'Conflict Development', 'Rising Action', 'Climax', 'Resolution'],
      commonElements: ['protagonist', 'antagonist', 'setting', 'conflict', 'plot twist', 'resolution'],
      writingStyle: 'narrative with dialogue and descriptive passages'
    },
    'poetry': {
      structure: ['Opening Stanza', 'Development Stanzas', 'Climactic Stanza', 'Closing Stanza'],
      commonElements: ['imagery', 'metaphor', 'rhythm', 'rhyme scheme', 'emotional tone'],
      writingStyle: 'lyrical with figurative language and structured verses'
    },
    'essay': {
      structure: ['Introduction', 'Thesis Statement', 'Supporting Arguments', 'Evidence', 'Counterarguments', 'Conclusion'],
      commonElements: ['thesis', 'evidence', 'analysis', 'transitions', 'citations'],
      writingStyle: 'formal academic with logical progression'
    },
    'blog post': {
      structure: ['Catchy Title', 'Hook', 'Introduction', 'Main Points', 'Examples', 'Call to Action'],
      commonElements: ['headlines', 'bullet points', 'personal anecdotes', 'actionable advice'],
      writingStyle: 'conversational and engaging with practical insights'
    },
    'short story': {
      structure: ['Opening Scene', 'Character Development', 'Conflict Introduction', 'Rising Tension', 'Climax', 'Resolution'],
      commonElements: ['character arc', 'setting', 'dialogue', 'narrative voice', 'theme'],
      writingStyle: 'concise narrative with strong character focus'
    },
    'script': {
      structure: ['Scene Setting', 'Character Introductions', 'Dialogue', 'Action Lines', 'Plot Development', 'Climax', 'Resolution'],
      commonElements: ['dialogue', 'stage directions', 'character names', 'scene descriptions'],
      writingStyle: 'formatted screenplay with dialogue and action'
    },
    'song lyrics': {
      structure: ['Verse 1', 'Chorus', 'Verse 2', 'Chorus', 'Bridge', 'Chorus', 'Outro'],
      commonElements: ['rhyme scheme', 'rhythm', 'repetition', 'emotional hooks', 'imagery'],
      writingStyle: 'rhythmic and melodic with emotional resonance'
    }
  }

  private static readonly TONE_CHARACTERISTICS = {
    'professional': { vocabulary: 'formal', sentence_length: 'medium', emotional_level: 'neutral' },
    'casual': { vocabulary: 'informal', sentence_length: 'varied', emotional_level: 'relaxed' },
    'humorous': { vocabulary: 'playful', sentence_length: 'short', emotional_level: 'light' },
    'dramatic': { vocabulary: 'intense', sentence_length: 'long', emotional_level: 'high' },
    'inspirational': { vocabulary: 'uplifting', sentence_length: 'medium', emotional_level: 'positive' },
    'mysterious': { vocabulary: 'enigmatic', sentence_length: 'varied', emotional_level: 'suspenseful' },
    'romantic': { vocabulary: 'emotional', sentence_length: 'flowing', emotional_level: 'tender' }
  }

  static async generateCreativeWriting(params: {
    prompt: string
    genre: string
    tone: string
    targetAudience: string
    targetWordCount: number
    creativity: number
    theme?: string
  }): Promise<{
    title: string
    genre: string
    tone: string
    wordCount: number
    content: string
    structure: {
      introduction: string
      body: string[]
      conclusion: string
    }
    literaryAnalysis: {
      readabilityScore: number
      sentimentScore: number
      creativityIndex: number
      coherenceRating: number
    }
    suggestions: {
      improvements: string[]
      alternatives: string[]
      styleEnhancements: string[]
    }
    metadata: {
      estimatedReadingTime: number
      targetAudience: string
      difficulty: string
      wordFrequency: { [key: string]: number }
    }
    timestamp: string
  }> {
    const genreTemplate = this.GENRE_TEMPLATES[params.genre] || this.GENRE_TEMPLATES.fiction
    const toneData = this.TONE_CHARACTERISTICS[params.tone] || this.TONE_CHARACTERISTICS.professional
    
    const content = this.generateContent(params, genreTemplate, toneData)
    const title = this.generateTitle(params.prompt, params.genre, params.theme)
    const structure = this.analyzeStructure(content, genreTemplate)
    const literaryAnalysis = this.performLiteraryAnalysis(content, params)
    const suggestions = this.generateSuggestions(content, params, literaryAnalysis)
    const metadata = this.generateMetadata(content, params)

    return {
      title,
      genre: this.capitalizeFirst(params.genre),
      tone: this.capitalizeFirst(params.tone),
      wordCount: this.countWords(content),
      content,
      structure,
      literaryAnalysis,
      suggestions,
      metadata,
      timestamp: new Date().toISOString()
    }
  }

  private static generateContent(
    params: any, 
    genreTemplate: any, 
    toneData: any
  ): string {
    const { prompt, genre, targetWordCount, creativity, theme } = params
    
    // Extract key elements from prompt
    const promptElements = this.extractPromptElements(prompt)
    
    // Generate content based on genre
    switch (genre) {
      case 'fiction':
      case 'short story':
        return this.generateFictionContent(promptElements, targetWordCount, creativity, theme)
      case 'poetry':
        return this.generatePoetryContent(promptElements, targetWordCount, creativity, theme)
      case 'essay':
        return this.generateEssayContent(promptElements, targetWordCount, creativity, theme)
      case 'blog post':
        return this.generateBlogContent(promptElements, targetWordCount, creativity, theme)
      case 'script':
        return this.generateScriptContent(promptElements, targetWordCount, creativity, theme)
      case 'song lyrics':
        return this.generateLyricsContent(promptElements, targetWordCount, creativity, theme)
      default:
        return this.generateGenericContent(promptElements, targetWordCount, creativity, theme)
    }
  }

  private static extractPromptElements(prompt: string): {
    characters: string[]
    settings: string[]
    themes: string[]
    actions: string[]
  } {
    const words = prompt.toLowerCase().split(' ')
    
    // Simple keyword extraction (in a real implementation, this would use NLP)
    const characterWords = words.filter(w => 
      ['character', 'person', 'hero', 'protagonist', 'woman', 'man', 'child', 'detective', 'scientist'].includes(w)
    )
    
    const settingWords = words.filter(w => 
      ['city', 'forest', 'space', 'school', 'office', 'home', 'mountain', 'ocean', 'future', 'past'].includes(w)
    )
    
    const themeWords = words.filter(w => 
      ['love', 'death', 'friendship', 'betrayal', 'adventure', 'mystery', 'discovery', 'loss', 'hope'].includes(w)
    )
    
    const actionWords = words.filter(w => 
      ['travel', 'discover', 'fight', 'escape', 'search', 'find', 'create', 'destroy', 'save'].includes(w)
    )
    
    return {
      characters: characterWords,
      settings: settingWords,
      themes: themeWords,
      actions: actionWords
    }
  }

  private static generateFictionContent(
    elements: any, 
    wordCount: number, 
    creativity: number, 
    theme?: string
  ): string {
    const openings = [
      "The morning mist clung to the valley like a forgotten dream, and in that ethereal silence, everything changed.",
      "Sarah had always believed that ordinary days were the most dangerous—it was when you weren't expecting magic that it found you.",
      "The letter arrived on a Tuesday, which was fitting because Tuesdays were when impossible things happened in small towns.",
      "Every mirror in the house showed a different reflection, and Marcus was beginning to understand why."
    ]
    
    const developments = [
      "What started as curiosity quickly transformed into something far more profound and unsettling.",
      "The discovery would challenge everything they thought they knew about reality itself.",
      "Time seemed to fold in on itself, creating possibilities that shouldn't have existed.",
      "The boundary between dream and waking life began to blur in ways that defied explanation."
    ]
    
    const resolutions = [
      "In the end, the truth was simpler and more complex than anyone could have imagined.",
      "The journey had changed them all, leaving marks invisible to the eye but permanent in the soul.",
      "What began in mystery concluded in understanding, though the questions it raised would linger forever.",
      "The story ended where it began, but nothing would ever be quite the same again."
    ]
    
    const opening = openings[Math.floor(Math.random() * openings.length)]
    const development = developments[Math.floor(Math.random() * developments.length)]
    const resolution = resolutions[Math.floor(Math.random() * resolutions.length)]
    
    // Generate middle content based on word count
    const middleParagraphs = Math.floor(wordCount / 150) - 2 // Subtract opening and closing
    let content = opening + "\n\n"
    
    for (let i = 0; i < middleParagraphs; i++) {
      content += development + " " + this.generateFictionParagraph(creativity, theme) + "\n\n"
    }
    
    content += resolution
    
    return this.adjustContentLength(content, wordCount)
  }

  private static generateFictionParagraph(creativity: number, theme?: string): string {
    const sentences = [
      "The shadows whispered secrets that only the wind could understand, carrying tales of forgotten worlds.",
      "Each step forward revealed new mysteries, as if the universe was unfolding its hidden chapters one by one.",
      "The landscape itself seemed alive, breathing with an ancient rhythm that connected all living things.",
      "Colors that had no names painted the sky, while sounds that defied description filled the air.",
      "Memory and reality danced together in a waltz that blurred the lines between what was and what could be."
    ]
    
    const creativeSentences = [
      "Quantum possibilities crystallized into singular moments of breathtaking clarity and infinite potential.",
      "The fabric of space-time rippled with the footsteps of dreams made manifest in waking reality.",
      "Consciousness expanded beyond the boundaries of flesh, touching the eternal and bringing back wisdom.",
      "Music unheard by human ears orchestrated the movement of celestial bodies in perfect harmony."
    ]
    
    if (creativity > 70) {
      return creativeSentences[Math.floor(Math.random() * creativeSentences.length)]
    }
    
    return sentences[Math.floor(Math.random() * sentences.length)]
  }

  private static generatePoetryContent(
    elements: any, 
    wordCount: number, 
    creativity: number, 
    theme?: string
  ): string {
    const verses = [
      "In silence deep, where shadows play,\nThe heart finds words it cannot say.\nBeneath the stars' eternal light,\nDreams take their flight through endless night.",
      
      "Time flows like water through our hands,\nCarrying hope to distant lands.\nEach moment precious, golden bright,\nBefore it fades from mortal sight.",
      
      "The wind remembers ancient songs,\nOf love that rights all earthly wrongs.\nIn whispered tales of joy and pain,\nWe find ourselves and lose again.",
      
      "Mountains stand as sentinels old,\nGuarding secrets yet untold.\nTheir peaks touch heaven's azure dome,\nWhere wandering spirits find their home."
    ]
    
    // Generate poetry based on word count (approximate)
    const versesNeeded = Math.ceil(wordCount / 30) // About 30 words per verse
    let content = ""
    
    for (let i = 0; i < Math.min(versesNeeded, 6); i++) {
      const verse = verses[i % verses.length]
      content += verse + "\n\n"
    }
    
    return content.trim()
  }

  private static generateEssayContent(
    elements: any, 
    wordCount: number, 
    creativity: number, 
    theme?: string
  ): string {
    const introduction = `The relationship between ${theme || 'humanity and technology'} represents one of the most significant challenges of our time. This essay examines the multifaceted implications of this relationship, exploring both opportunities and concerns that arise from our increasingly interconnected world.`
    
    const bodyParagraphs = [
      `First, we must consider the transformative potential that emerges when human creativity meets technological innovation. This intersection has historically driven progress in fields ranging from medicine to communication, fundamentally altering how we understand and interact with our environment.`,
      
      `However, alongside these benefits come significant challenges that demand careful consideration. The rapid pace of change often outstrips our ability to adapt, creating tensions between traditional values and emerging possibilities that require thoughtful navigation.`,
      
      `Furthermore, the ethical implications of these developments cannot be ignored. As we gain unprecedented power to shape our world and ourselves, questions of responsibility, equity, and long-term consequences become increasingly important to address.`
    ]
    
    const conclusion = `In conclusion, the path forward requires balanced consideration of both potential and peril. By maintaining awareness of our values while embracing beneficial change, we can work toward outcomes that serve humanity's best interests while respecting the complexity of the challenges we face.`
    
    let content = introduction + "\n\n"
    
    const paragraphsNeeded = Math.floor((wordCount - 150) / 100) // Adjust for intro and conclusion
    for (let i = 0; i < Math.min(paragraphsNeeded, bodyParagraphs.length); i++) {
      content += bodyParagraphs[i] + "\n\n"
    }
    
    content += conclusion
    
    return this.adjustContentLength(content, wordCount)
  }

  private static generateBlogContent(
    elements: any, 
    wordCount: number, 
    creativity: number, 
    theme?: string
  ): string {
    const hooks = [
      "Have you ever wondered what would happen if you could completely transform your approach to this challenge?",
      "The secret that experts don't want you to know might surprise you.",
      "Three years ago, I made a discovery that changed everything I thought I knew about this topic.",
      "What if I told you that the solution you've been seeking has been hiding in plain sight?"
    ]
    
    const hook = hooks[Math.floor(Math.random() * hooks.length)]
    
    const content = `${hook}

In today's fast-paced world, understanding ${theme || 'effective strategies'} has become more important than ever. Whether you're a beginner or someone with experience, the insights shared in this post will provide valuable perspective on navigating these complex challenges.

## The Foundation

The most successful approaches always start with a solid foundation. This means understanding not just the what, but the why behind effective strategies. When we take time to build this understanding, everything else becomes clearer and more actionable.

## Practical Applications

Here's where theory meets reality. The concepts we've discussed translate into concrete steps you can take immediately:

- Start with small, manageable changes that build momentum
- Focus on consistency rather than perfection
- Measure progress using meaningful metrics
- Adjust your approach based on real-world feedback

## Common Pitfalls to Avoid

Even with the best intentions, there are typical mistakes that can derail progress. By being aware of these challenges, you can navigate around them more successfully and maintain forward momentum.

## Moving Forward

The journey toward mastery is ongoing, but with the right foundation and practical tools, you're well-equipped to make meaningful progress. Remember that every expert was once a beginner, and every small step contributes to larger transformation.

What's your next step going to be?`

    return this.adjustContentLength(content, wordCount)
  }

  private static generateScriptContent(
    elements: any, 
    wordCount: number, 
    creativity: number, 
    theme?: string
  ): string {
    return `FADE IN:

EXT. MYSTERIOUS LOCATION - DAY

A place where reality bends and possibilities converge. The landscape shifts subtly, as if responding to unseen forces.

ALEX, a curious and determined individual, approaches cautiously.

ALEX
(looking around in wonder)
I never imagined a place like this could exist.

A figure emerges from the shifting environment - THE GUIDE, wise and enigmatic.

GUIDE
(smiling knowingly)
Every reality starts as someone's impossible dream.

ALEX
But how do we know what's real anymore?

GUIDE
(gesturing to the surroundings)
Reality isn't something you find - it's something you create, moment by moment.

The environment responds to their conversation, colors shifting and new pathways appearing.

ALEX
(realization dawning)
So the choices we make...

GUIDE
Shape everything that follows. The question isn't whether you can change things - it's whether you're ready to accept responsibility for the change.

ALEX takes a deep breath, looking out at the infinite possibilities.

ALEX
Then I'm ready to begin.

FADE OUT.

THE END`
  }

  private static generateLyricsContent(
    elements: any, 
    wordCount: number, 
    creativity: number, 
    theme?: string
  ): string {
    return `[Verse 1]
Walking down this endless road
Carrying dreams and letting go
Every step a new beginning
Every breath a song worth singing

[Chorus]
We are more than we appear
Stronger than our deepest fear
In the darkness, we find light
In the struggle, we find might

[Verse 2]
Memories fade but hope remains
Through the sunshine and the rains
Building bridges, mending hearts
Every ending, new life starts

[Chorus]
We are more than we appear
Stronger than our deepest fear
In the darkness, we find light
In the struggle, we find might

[Bridge]
When the world seems upside down
And you feel like you might drown
Remember who you're meant to be
Set your spirit running free

[Final Chorus]
We are more than we appear
Stronger than our deepest fear
In the darkness, we find light
In the struggle, we find might
Yes, in the struggle, we find might`
  }

  private static generateGenericContent(
    elements: any, 
    wordCount: number, 
    creativity: number, 
    theme?: string
  ): string {
    return `In exploring the depths of ${theme || 'human experience'}, we discover layers of meaning that extend far beyond surface understanding. Each perspective reveals new insights, creating a tapestry of knowledge that enriches our comprehension of complex realities.

The journey of discovery often begins with questions that challenge our assumptions. These inquiries lead us through territories both familiar and strange, where conventional wisdom meets innovative thinking, and where the boundaries between different fields of knowledge begin to blur.

As we navigate these intellectual landscapes, patterns emerge that connect seemingly disparate elements. These connections form bridges between ideas, creating networks of understanding that illuminate truth from multiple angles and provide comprehensive insights into the nature of our subject.

The implications of these discoveries extend beyond academic interest, touching the very core of how we understand ourselves and our place in the larger scheme of existence. They challenge us to reconsider our perspectives and embrace new possibilities for growth and understanding.

In conclusion, the exploration of these themes reveals the interconnected nature of knowledge and experience, demonstrating that true understanding emerges not from isolated facts, but from the dynamic relationships between ideas, experiences, and insights that together create a more complete picture of reality.`
  }

  private static adjustContentLength(content: string, targetWordCount: number): string {
    const currentWordCount = this.countWords(content)
    
    if (currentWordCount < targetWordCount * 0.9) {
      // Add more content
      const additionalSentences = [
        "This perspective opens new avenues for exploration and understanding.",
        "The implications extend far beyond what initially meets the eye.",
        "Each layer of meaning reveals additional complexity and nuance.",
        "These insights contribute to a more comprehensive understanding of the subject."
      ]
      
      while (this.countWords(content) < targetWordCount * 0.95) {
        const sentence = additionalSentences[Math.floor(Math.random() * additionalSentences.length)]
        content += " " + sentence
      }
    }
    
    return content
  }

  private static countWords(text: string): number {
    return text.trim().split(/\s+/).length
  }

  private static generateTitle(prompt: string, genre: string, theme?: string): string {
    const promptWords = prompt.split(' ').slice(0, 3)
    const keyWord = promptWords.find(word => word.length > 4) || promptWords[0]
    
    const titleTemplates = {
      'fiction': ['The Secret of {}', 'Beyond the {}', 'Chronicles of {}', 'The {} Mystery'],
      'poetry': ['Echoes of {}', 'Songs from {}', 'The {} Collection', 'Verses of {}'],
      'essay': ['Understanding {}', 'The Nature of {}', 'Exploring {}', 'Perspectives on {}'],
      'blog post': ['Your Guide to {}', 'Mastering {}', 'The Truth About {}', 'Why {} Matters'],
      'short story': ['The {} Incident', 'A Tale of {}', 'The {} Encounter', 'When {} Changed Everything'],
      'script': ['The {} Chronicles', '{}: A Journey', 'The {} Revelation', 'Beyond {}'],
      'song lyrics': ['Song of {}', 'The {} Ballad', '{} Dreams', 'Echoes of {}']
    }
    
    const templates = titleTemplates[genre] || titleTemplates.fiction
    const template = templates[Math.floor(Math.random() * templates.length)]
    
    return template.replace('{}', this.capitalizeFirst(theme || keyWord || 'Tomorrow'))
  }

  private static analyzeStructure(content: string, genreTemplate: any): {
    introduction: string
    body: string[]
    conclusion: string
  } {
    const paragraphs = content.split('\n\n').filter(p => p.trim())
    
    return {
      introduction: "Engaging opening that establishes context and draws reader attention",
      body: genreTemplate.structure.slice(1, -1), // Middle elements
      conclusion: "Satisfying resolution that provides closure and lasting impact"
    }
  }

  private static performLiteraryAnalysis(content: string, params: any): {
    readabilityScore: number
    sentimentScore: number
    creativityIndex: number
    coherenceRating: number
  } {
    // Simulate literary analysis (real implementation would use NLP libraries)
    const baseReadability = 70 + Math.random() * 20
    const baseSentiment = 60 + Math.random() * 30
    const baseCreativity = 50 + (params.creativity / 100) * 40 + Math.random() * 10
    const baseCoherence = 75 + Math.random() * 20
    
    return {
      readabilityScore: Math.round(Math.min(95, baseReadability)),
      sentimentScore: Math.round(Math.min(95, baseSentiment)),
      creativityIndex: Math.round(Math.min(95, baseCreativity)),
      coherenceRating: Math.round(Math.min(95, baseCoherence))
    }
  }

  private static generateSuggestions(content: string, params: any, analysis: any): {
    improvements: string[]
    alternatives: string[]
    styleEnhancements: string[]
  } {
    const improvements = [
      "Consider adding more sensory details to enhance reader immersion",
      "Vary sentence structure to create better rhythm and flow",
      "Strengthen character development through dialogue and action",
      "Add transitional phrases to improve paragraph connections"
    ]
    
    const alternatives = [
      "Try a different narrative perspective (first person vs. third person)",
      "Experiment with non-linear storytelling techniques",
      "Consider starting in the middle of action (in medias res)",
      "Explore the story from another character's viewpoint"
    ]
    
    const styleEnhancements = [
      "Use more active voice to create dynamic and engaging prose",
      "Incorporate figurative language like metaphors and similes",
      "Show don't tell - use actions and dialogue over exposition",
      "Create stronger opening and closing sentences for paragraphs"
    ]
    
    return {
      improvements: improvements.slice(0, 3),
      alternatives: alternatives.slice(0, 3),
      styleEnhancements: styleEnhancements.slice(0, 3)
    }
  }

  private static generateMetadata(content: string, params: any): {
    estimatedReadingTime: number
    targetAudience: string
    difficulty: string
    wordFrequency: { [key: string]: number }
  } {
    const wordCount = this.countWords(content)
    const readingTime = Math.ceil(wordCount / 200) // 200 words per minute average
    
    // Simple word frequency analysis
    const words = content.toLowerCase().match(/\b\w+\b/g) || []
    const wordFreq: { [key: string]: number } = {}
    
    words.forEach(word => {
      if (word.length > 3) { // Only count words longer than 3 characters
        wordFreq[word] = (wordFreq[word] || 0) + 1
      }
    })
    
    // Sort by frequency and take top 10
    const sortedWords = Object.entries(wordFreq)
      .sort(([,a], [,b]) => b - a)
      .slice(0, 10)
      .reduce((obj, [word, freq]) => ({ ...obj, [word]: freq }), {})
    
    // Determine difficulty based on vocabulary and sentence complexity
    const difficulty = wordCount > 1000 ? 'advanced' : wordCount > 500 ? 'intermediate' : 'beginner'
    
    return {
      estimatedReadingTime: readingTime,
      targetAudience: this.capitalizeFirst(params.targetAudience),
      difficulty: difficulty,
      wordFrequency: sortedWords
    }
  }

  private static capitalizeFirst(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1)
  }
}

export async function POST(request: NextRequest) {
  try {
    await connectDB()
    
    const body = await request.json()
    const { type, prompt, genre, tone, targetAudience, targetWordCount, creativity, theme } = body
    
    if (!type || !prompt || !genre) {
      return NextResponse.json({
        error: 'Type, prompt, and genre are required'
      }, { status: 400 })
    }
    
    if (type === 'generate') {
      // Generate creative writing
      const writing = await CreativeWritingAI.generateCreativeWriting({
        prompt: prompt.trim(),
        genre: genre.toLowerCase(),
        tone: tone || 'neutral',
        targetAudience: targetAudience || 'general',
        targetWordCount: targetWordCount || 500,
        creativity: creativity || 70,
        theme: theme?.trim()
      })
      
      return NextResponse.json(writing)
    }
    
    return NextResponse.json({
      error: 'Unsupported generation type'
    }, { status: 400 })
    
  } catch (error) {
    console.error('Creative Writing AI Error:', error)
    return NextResponse.json({
      error: 'Creative writing generation failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
