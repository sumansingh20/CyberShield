import { NextRequest, NextResponse } from 'next/server'

interface LectureSummary {
  id: string
  title: string
  subject: string
  duration: string
  lecturer: string
  keyTopics: string[]
  mainSummary: string
  detailedNotes: {
    section: string
    timestamp?: string
    content: string
    importance: 'high' | 'medium' | 'low'
    concepts: string[]
  }[]
  keyInsights: {
    type: 'definition' | 'formula' | 'principle' | 'example' | 'question'
    title: string
    content: string
    timestamp?: string
  }[]
  studyGuide: {
    learningObjectives: string[]
    keyTerms: Array<{
      term: string
      definition: string
    }>
    practiceQuestions: Array<{
      question: string
      type: 'multiple_choice' | 'short_answer' | 'essay'
      difficulty: 'easy' | 'medium' | 'hard'
      hint?: string
    }>
    additionalResources: Array<{
      type: 'reading' | 'video' | 'exercise' | 'reference'
      title: string
      description: string
      url?: string
    }>
  }
  comprehensionScore: {
    overall: number
    categories: {
      conceptual: number
      factual: number
      analytical: number
      practical: number
    }
  }
  metadata: {
    processingTime: number
    wordCount: number
    complexity: 'beginner' | 'intermediate' | 'advanced'
    tags: string[]
    createdAt: string
  }
}

class LectureSummarizerAI {
  private static instance: LectureSummarizerAI
  
  private constructor() {}
  
  static getInstance(): LectureSummarizerAI {
    if (!LectureSummarizerAI.instance) {
      LectureSummarizerAI.instance = new LectureSummarizerAI()
    }
    return LectureSummarizerAI.instance
  }

  async processLecture(
    title: string,
    subject: string,
    lecturer: string,
    content: string,
    audioFile?: File
  ): Promise<LectureSummary> {
    const startTime = Date.now()
    
    // Simulate audio transcription if audio file is provided
    let transcribedContent = content
    if (audioFile && !content.trim()) {
      transcribedContent = await this.simulateTranscription(audioFile)
    }

    // If no content available, generate sample content
    if (!transcribedContent.trim()) {
      transcribedContent = this.generateSampleContent(title, subject)
    }

    const wordCount = transcribedContent.split(' ').length
    const complexity = this.determineComplexity(transcribedContent, subject)
    
    // Extract key topics
    const keyTopics = this.extractKeyTopics(transcribedContent, subject)
    
    // Generate main summary
    const mainSummary = this.generateMainSummary(transcribedContent, keyTopics)
    
    // Create detailed notes
    const detailedNotes = this.createDetailedNotes(transcribedContent)
    
    // Extract key insights
    const keyInsights = this.extractKeyInsights(transcribedContent, subject)
    
    // Generate study guide
    const studyGuide = this.generateStudyGuide(transcribedContent, keyTopics, subject)
    
    // Calculate comprehension scores
    const comprehensionScore = this.calculateComprehensionScore(transcribedContent, subject)
    
    // Generate metadata tags
    const tags = this.generateTags(transcribedContent, subject, keyTopics)
    
    const processingTime = Math.round((Date.now() - startTime) / 1000)

    return {
      id: `lecture_${Date.now()}`,
      title: title || 'Untitled Lecture',
      subject: subject || 'General',
      duration: this.estimateDuration(wordCount),
      lecturer: lecturer || 'Unknown',
      keyTopics,
      mainSummary,
      detailedNotes,
      keyInsights,
      studyGuide,
      comprehensionScore,
      metadata: {
        processingTime,
        wordCount,
        complexity,
        tags,
        createdAt: new Date().toISOString()
      }
    }
  }

  private async simulateTranscription(audioFile: File): Promise<string> {
    // Simulate audio transcription processing
    await new Promise(resolve => setTimeout(resolve, 2000))
    
    // Return simulated transcription based on file name or type
    const fileName = audioFile.name.toLowerCase()
    
    if (fileName.includes('math') || fileName.includes('calculus')) {
      return `Welcome to today's calculus lecture. We'll be covering differential equations and their applications in real-world scenarios. 
      
      Let's start with the definition of a differential equation. A differential equation is an equation that relates a function with its derivatives. For example, dy/dx = 2x is a simple differential equation.
      
      There are several types of differential equations: ordinary differential equations (ODEs) and partial differential equations (PDEs). Today we'll focus on ODEs.
      
      The order of a differential equation is determined by the highest derivative present in the equation. A first-order ODE contains only first derivatives, while a second-order ODE contains second derivatives.
      
      Now, let's look at some solution methods. The separation of variables method is one of the most fundamental techniques for solving first-order ODEs.
      
      For homework, please practice problems 1-10 from chapter 5, focusing on separable equations and linear first-order equations.`
    }
    
    if (fileName.includes('computer') || fileName.includes('programming')) {
      return `Today we're going to discuss machine learning algorithms and their practical applications in software development.
      
      Machine learning is a subset of artificial intelligence that enables computers to learn and make decisions from data without being explicitly programmed for every scenario.
      
      There are three main types of machine learning: supervised learning, unsupervised learning, and reinforcement learning.
      
      Supervised learning uses labeled data to train models. Examples include classification problems like email spam detection and regression problems like predicting house prices.
      
      Unsupervised learning finds patterns in data without labels. Clustering algorithms like K-means and dimensionality reduction techniques like PCA are common examples.
      
      Reinforcement learning involves agents learning through interaction with an environment, receiving rewards or penalties for actions.
      
      Popular algorithms include linear regression, decision trees, random forests, support vector machines, and neural networks.
      
      For your project, choose a dataset and implement at least two different algorithms to compare their performance.`
    }
    
    // Default transcription
    return `Welcome to today's lecture. We'll be covering several important concepts that are fundamental to understanding this subject area.
    
    First, let's establish the basic definitions and terminology that we'll be using throughout this session. Understanding these foundational concepts is crucial for grasping the more advanced topics we'll discuss later.
    
    The main theme of today's discussion revolves around the practical applications and theoretical frameworks that govern this field of study.
    
    We'll examine several case studies and examples to illustrate these concepts in real-world contexts. This will help you understand not just the what, but the why and how of these principles.
    
    As we progress through the material, please feel free to ask questions. Understanding these concepts thoroughly is more important than covering everything quickly.
    
    For next class, please review the assigned readings and come prepared to discuss the implications of what we've covered today.`
  }

  private generateSampleContent(title: string, subject: string): string {
    const subjectContent: Record<string, string> = {
      'Computer Science': `Introduction to ${title}

Today's lecture covers fundamental concepts in computer science, focusing on algorithmic thinking and problem-solving methodologies.

We begin with an overview of computational complexity, discussing time and space complexity analysis. Understanding Big O notation is crucial for evaluating algorithm efficiency.

Data structures form the backbone of efficient programming. We'll examine arrays, linked lists, stacks, queues, trees, and graphs, discussing when to use each structure.

Object-oriented programming principles include encapsulation, inheritance, and polymorphism. These concepts help organize code and promote reusability.

Database design principles cover normalization, entity-relationship models, and query optimization techniques.

Software engineering practices emphasize version control, testing methodologies, and documentation standards.

For your assignment, implement a binary search tree with insertion, deletion, and traversal operations.`,

      'Mathematics': `Mathematical Foundations: ${title}

Today we explore advanced mathematical concepts and their practical applications.

We begin with fundamental theorems and proofs, establishing the logical framework for mathematical reasoning.

Calculus concepts include limits, derivatives, and integrals. These tools are essential for modeling continuous change and optimization problems.

Linear algebra introduces vectors, matrices, and eigenvalues. These concepts are fundamental in many applications including computer graphics and machine learning.

Probability theory covers random variables, probability distributions, and statistical inference methods.

Discrete mathematics includes set theory, combinatorics, and graph theory, providing tools for computer science applications.

Mathematical modeling techniques help translate real-world problems into mathematical formulations.

Practice problems focus on proof techniques and problem-solving strategies.`,

      'Physics': `Physics Principles: ${title}

Our exploration of physics begins with fundamental laws governing the natural world.

Classical mechanics covers Newton's laws, energy conservation, and momentum principles. These form the foundation for understanding motion and forces.

Thermodynamics introduces concepts of heat, temperature, and entropy. These principles govern energy transfer and system behavior.

Electromagnetism explains electric and magnetic phenomena, including field theory and wave propagation.

Quantum mechanics reveals the behavior of matter and energy at atomic scales, challenging classical intuitions.

Relativity theory addresses the relationship between space, time, and gravity at cosmic scales.

Laboratory techniques emphasize measurement accuracy, error analysis, and experimental design.

Problem-solving approaches combine theoretical understanding with mathematical techniques.`,

      'default': `Academic Lecture: ${title}

Welcome to today's comprehensive lecture covering key concepts in this subject area.

We'll establish foundational knowledge through clear definitions and examples, building understanding systematically.

Theoretical frameworks provide the conceptual structure for organizing information and making connections between ideas.

Practical applications demonstrate how these concepts apply in real-world contexts, making abstract ideas concrete.

Case studies illustrate successful implementations and common challenges encountered in practice.

Critical thinking exercises encourage analysis, evaluation, and synthesis of complex information.

Research methodologies guide systematic investigation and evidence-based conclusions.

Assessment strategies ensure comprehension and provide feedback for continued learning.`
    }

    return subjectContent[subject] || subjectContent['default']
  }

  private extractKeyTopics(content: string, subject: string): string[] {
    const words = content.toLowerCase().split(/\W+/)
    const topics: string[] = []

    // Subject-specific keywords
    const subjectKeywords: Record<string, string[]> = {
      'Computer Science': ['algorithm', 'data structure', 'programming', 'database', 'software', 'coding', 'optimization', 'complexity', 'object-oriented', 'debugging'],
      'Mathematics': ['theorem', 'proof', 'equation', 'function', 'calculus', 'algebra', 'geometry', 'statistics', 'probability', 'matrix'],
      'Physics': ['force', 'energy', 'momentum', 'wave', 'particle', 'field', 'quantum', 'relativity', 'thermodynamics', 'mechanics'],
      'Chemistry': ['molecule', 'atom', 'reaction', 'bond', 'element', 'compound', 'solution', 'acid', 'base', 'catalyst'],
      'Biology': ['cell', 'gene', 'protein', 'organism', 'evolution', 'ecology', 'metabolism', 'reproduction', 'adaptation', 'species']
    }

    const keywords = subjectKeywords[subject] || []
    
    // Find mentioned keywords
    keywords.forEach(keyword => {
      if (words.includes(keyword)) {
        topics.push(keyword.charAt(0).toUpperCase() + keyword.slice(1))
      }
    })

    // Extract concepts from context
    const sentences = content.split(/[.!?]+/)
    sentences.forEach(sentence => {
      const lowerSentence = sentence.toLowerCase()
      
      // Look for definition patterns
      if (lowerSentence.includes('definition of') || lowerSentence.includes('defined as')) {
        const match = sentence.match(/definition of (\w+)|(\w+) (?:is )?defined as/i)
        if (match) {
          const concept = (match[1] || match[2])?.trim()
          if (concept && concept.length > 2) {
            topics.push(concept.charAt(0).toUpperCase() + concept.slice(1))
          }
        }
      }

      // Look for concept introductions
      if (lowerSentence.includes('concept of') || lowerSentence.includes('theory of')) {
        const match = sentence.match(/(?:concept|theory) of (\w+(?:\s+\w+)?)/i)
        if (match) {
          const concept = match[1]?.trim()
          if (concept && concept.length > 2) {
            topics.push(concept.charAt(0).toUpperCase() + concept.slice(1))
          }
        }
      }
    })

    // Add default topics if none found
    if (topics.length === 0) {
      const defaultTopics: Record<string, string[]> = {
        'Computer Science': ['Algorithms', 'Data Structures', 'Programming Concepts'],
        'Mathematics': ['Mathematical Concepts', 'Problem Solving', 'Theoretical Foundations'],
        'Physics': ['Physical Laws', 'Scientific Method', 'Experimental Techniques'],
        'default': ['Key Concepts', 'Theoretical Framework', 'Practical Applications']
      }
      
      topics.push(...(defaultTopics[subject] || defaultTopics['default']))
    }

    return [...new Set(topics)].slice(0, 8) // Remove duplicates and limit to 8 topics
  }

  private generateMainSummary(content: string, keyTopics: string[]): string {
    const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 10)
    const importantSentences: string[] = []

    // Find sentences containing key topics
    sentences.forEach(sentence => {
      const lowerSentence = sentence.toLowerCase()
      const topicMatches = keyTopics.filter(topic => 
        lowerSentence.includes(topic.toLowerCase())
      ).length

      if (topicMatches > 0) {
        importantSentences.push(sentence.trim())
      }
    })

    // If no topic-specific sentences, use first few sentences
    if (importantSentences.length === 0) {
      importantSentences.push(...sentences.slice(0, 3))
    }

    // Create summary from important sentences
    const summary = importantSentences
      .slice(0, 5)
      .join('. ')
      .replace(/\s+/g, ' ')
      .trim()

    return summary || 'This lecture covers fundamental concepts and their practical applications in the field.'
  }

  private createDetailedNotes(content: string): Array<{
    section: string
    timestamp?: string
    content: string
    importance: 'high' | 'medium' | 'low'
    concepts: string[]
  }> {
    const paragraphs = content.split(/\n\n+/).filter(p => p.trim().length > 50)
    const notes: Array<{
      section: string
      timestamp?: string
      content: string
      importance: 'high' | 'medium' | 'low'
      concepts: string[]
    }> = []

    paragraphs.forEach((paragraph, index) => {
      const sectionTitles = [
        'Introduction and Overview',
        'Core Concepts',
        'Theoretical Framework',
        'Practical Applications',
        'Case Studies and Examples',
        'Implementation Details',
        'Summary and Conclusions'
      ]

      const section = sectionTitles[index] || `Section ${index + 1}`
      const importance = this.determineImportance(paragraph)
      const concepts = this.extractConceptsFromText(paragraph)
      const timestamp = this.generateTimestamp(index, paragraphs.length)

      notes.push({
        section,
        timestamp,
        content: paragraph.trim(),
        importance,
        concepts
      })
    })

    return notes
  }

  private determineImportance(text: string): 'high' | 'medium' | 'low' {
    const lowerText = text.toLowerCase()
    
    // High importance indicators
    const highImportanceKeywords = [
      'important', 'crucial', 'essential', 'fundamental', 'key concept',
      'remember', 'note that', 'pay attention', 'critical', 'must understand'
    ]
    
    // Medium importance indicators
    const mediumImportanceKeywords = [
      'example', 'for instance', 'consider', 'let\'s look at', 'application',
      'useful', 'practical', 'technique', 'method', 'approach'
    ]

    if (highImportanceKeywords.some(keyword => lowerText.includes(keyword))) {
      return 'high'
    }
    
    if (mediumImportanceKeywords.some(keyword => lowerText.includes(keyword))) {
      return 'medium'
    }
    
    return 'low'
  }

  private extractConceptsFromText(text: string): string[] {
    const concepts: string[] = []
    const words = text.split(/\W+/).filter(word => word.length > 3)
    
    // Look for capitalized terms (likely concepts)
    const capitalizedTerms = text.match(/\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b/g) || []
    concepts.push(...capitalizedTerms.slice(0, 3))
    
    // Look for quoted terms
    const quotedTerms = text.match(/"([^"]+)"/g) || []
    concepts.push(...quotedTerms.map(term => term.replace(/"/g, '')))
    
    // Look for emphasized terms (in definitions)
    const definitionPattern = /(\w+(?:\s+\w+)*)\s+(?:is|are|means?|refers? to)/gi
    const matches = [...text.matchAll(definitionPattern)]
    concepts.push(...matches.map(match => match[1]).slice(0, 2))

    return [...new Set(concepts)].slice(0, 5)
  }

  private generateTimestamp(index: number, total: number): string {
    const totalMinutes = 45 // Assume 45-minute lecture
    const timePerSection = totalMinutes / total
    const minutes = Math.floor(index * timePerSection)
    const seconds = Math.floor((index * timePerSection - minutes) * 60)
    
    return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`
  }

  private extractKeyInsights(content: string, subject: string): Array<{
    type: 'definition' | 'formula' | 'principle' | 'example' | 'question'
    title: string
    content: string
    timestamp?: string
  }> {
    const insights: Array<{
      type: 'definition' | 'formula' | 'principle' | 'example' | 'question'
      title: string
      content: string
      timestamp?: string
    }> = []

    const sentences = content.split(/[.!?]+/).filter(s => s.trim().length > 10)
    
    sentences.forEach((sentence, index) => {
      const lowerSentence = sentence.toLowerCase().trim()
      
      // Look for definitions
      if (lowerSentence.includes('definition') || lowerSentence.includes('defined as') || lowerSentence.includes('is a')) {
        insights.push({
          type: 'definition',
          title: this.extractConceptName(sentence),
          content: sentence.trim(),
          timestamp: this.generateTimestampFromIndex(index, sentences.length)
        })
      }
      
      // Look for formulas (math/science)
      if (/[=+\-*/()^]/.test(sentence) && (subject.includes('Math') || subject.includes('Physics'))) {
        insights.push({
          type: 'formula',
          title: 'Mathematical Formula',
          content: sentence.trim(),
          timestamp: this.generateTimestampFromIndex(index, sentences.length)
        })
      }
      
      // Look for principles
      if (lowerSentence.includes('principle') || lowerSentence.includes('law') || lowerSentence.includes('rule')) {
        insights.push({
          type: 'principle',
          title: this.extractConceptName(sentence),
          content: sentence.trim(),
          timestamp: this.generateTimestampFromIndex(index, sentences.length)
        })
      }
      
      // Look for examples
      if (lowerSentence.includes('example') || lowerSentence.includes('for instance') || lowerSentence.includes('such as')) {
        insights.push({
          type: 'example',
          title: 'Example',
          content: sentence.trim(),
          timestamp: this.generateTimestampFromIndex(index, sentences.length)
        })
      }
      
      // Look for questions
      if (sentence.trim().endsWith('?')) {
        insights.push({
          type: 'question',
          title: 'Key Question',
          content: sentence.trim(),
          timestamp: this.generateTimestampFromIndex(index, sentences.length)
        })
      }
    })

    // Add default insights if none found
    if (insights.length === 0) {
      insights.push({
        type: 'principle',
        title: 'Core Principle',
        content: 'Understanding the fundamental concepts is essential for mastering this subject area.',
        timestamp: '05:00'
      })
    }

    return insights.slice(0, 8)
  }

  private extractConceptName(sentence: string): string {
    // Try to extract the main concept being defined or discussed
    const definitionMatch = sentence.match(/(?:definition of|defined as|is a)\s+([^,.\n]+)/i)
    if (definitionMatch) {
      return definitionMatch[1].trim()
    }
    
    const conceptMatch = sentence.match(/([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)/);
    if (conceptMatch) {
      return conceptMatch[1]
    }
    
    // Fallback to first few words
    const words = sentence.trim().split(' ').slice(0, 3).join(' ')
    return words || 'Key Concept'
  }

  private generateTimestampFromIndex(index: number, total: number): string {
    const totalMinutes = 45
    const timePerSentence = totalMinutes / total
    const minutes = Math.floor(index * timePerSentence)
    const seconds = Math.floor((index * timePerSentence - minutes) * 60)
    
    return `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`
  }

  private generateStudyGuide(content: string, keyTopics: string[], subject: string) {
    const learningObjectives = this.generateLearningObjectives(content, keyTopics)
    const keyTerms = this.generateKeyTerms(content, subject)
    const practiceQuestions = this.generatePracticeQuestions(content, keyTopics, subject)
    const additionalResources = this.generateAdditionalResources(subject, keyTopics)

    return {
      learningObjectives,
      keyTerms,
      practiceQuestions,
      additionalResources
    }
  }

  private generateLearningObjectives(content: string, keyTopics: string[]): string[] {
    const objectives: string[] = []
    
    // Generate objectives based on key topics
    keyTopics.forEach(topic => {
      objectives.push(`Understand the fundamental concepts of ${topic.toLowerCase()}`)
    })
    
    // Add general objectives
    objectives.push('Apply theoretical knowledge to practical problems')
    objectives.push('Analyze complex scenarios using learned principles')
    objectives.push('Evaluate different approaches and methodologies')
    
    return objectives.slice(0, 6)
  }

  private generateKeyTerms(content: string, subject: string): Array<{ term: string; definition: string }> {
    const terms: Array<{ term: string; definition: string }> = []
    
    // Subject-specific terms
    const subjectTerms: Record<string, Array<{ term: string; definition: string }>> = {
      'Computer Science': [
        { term: 'Algorithm', definition: 'A step-by-step procedure for solving a problem or completing a task' },
        { term: 'Data Structure', definition: 'A way of organizing and storing data to enable efficient access and modification' },
        { term: 'Complexity', definition: 'A measure of the computational resources required by an algorithm' },
        { term: 'Recursion', definition: 'A programming technique where a function calls itself to solve smaller instances of the same problem' }
      ],
      'Mathematics': [
        { term: 'Function', definition: 'A relation that assigns exactly one output value for each input value' },
        { term: 'Derivative', definition: 'A measure of how a function changes as its input changes' },
        { term: 'Integral', definition: 'A mathematical concept representing the area under a curve or the reverse of differentiation' },
        { term: 'Matrix', definition: 'A rectangular array of numbers, symbols, or expressions arranged in rows and columns' }
      ],
      'Physics': [
        { term: 'Force', definition: 'An interaction that changes the motion of an object when unopposed' },
        { term: 'Energy', definition: 'The capacity to do work or produce change' },
        { term: 'Momentum', definition: 'The product of an object\'s mass and velocity' },
        { term: 'Wave', definition: 'A disturbance that travels through space and time, transferring energy' }
      ]
    }
    
    // Use subject-specific terms or generate generic ones
    const specificTerms = subjectTerms[subject] || [
      { term: 'Concept', definition: 'An abstract idea or general notion' },
      { term: 'Theory', definition: 'A well-substantiated explanation of some aspect of the natural world' },
      { term: 'Method', definition: 'A particular procedure for accomplishing or approaching something' },
      { term: 'Application', definition: 'The practical use or implementation of an idea or theory' }
    ]
    
    terms.push(...specificTerms)
    
    // Try to extract terms from content
    const sentences = content.split(/[.!?]+/)
    sentences.forEach(sentence => {
      const definitionMatch = sentence.match(/([A-Z][a-z]+(?:\s+[A-Z][a-z]+)*)\s+(?:is|are|means?|refers? to)\s+([^.!?]+)/i)
      if (definitionMatch && terms.length < 8) {
        terms.push({
          term: definitionMatch[1].trim(),
          definition: definitionMatch[2].trim()
        })
      }
    })
    
    return terms.slice(0, 6)
  }

  private generatePracticeQuestions(content: string, keyTopics: string[], subject: string): Array<{
    question: string
    type: 'multiple_choice' | 'short_answer' | 'essay'
    difficulty: 'easy' | 'medium' | 'hard'
    hint?: string
  }> {
    const questions: Array<{
      question: string
      type: 'multiple_choice' | 'short_answer' | 'essay'
      difficulty: 'easy' | 'medium' | 'hard'
      hint?: string
    }> = []
    
    // Generate questions based on key topics
    keyTopics.forEach((topic, index) => {
      // Easy question
      questions.push({
        question: `Define ${topic} and explain its basic characteristics.`,
        type: 'short_answer',
        difficulty: 'easy',
        hint: `Think about the fundamental definition and key features of ${topic.toLowerCase()}`
      })
      
      // Medium question
      if (index < 2) {
        questions.push({
          question: `Compare and contrast ${topic} with related concepts. Provide specific examples.`,
          type: 'essay',
          difficulty: 'medium',
          hint: 'Consider similarities, differences, and practical applications'
        })
      }
    })
    
    // Add subject-specific questions
    const subjectQuestions: Record<string, Array<{
      question: string
      type: 'multiple_choice' | 'short_answer' | 'essay'
      difficulty: 'easy' | 'medium' | 'hard'
      hint?: string
    }>> = {
      'Computer Science': [
        {
          question: 'What is the time complexity of binary search?',
          type: 'multiple_choice',
          difficulty: 'medium',
          hint: 'Consider how the search space is reduced with each comparison'
        },
        {
          question: 'Explain the difference between stack and queue data structures.',
          type: 'short_answer',
          difficulty: 'easy',
          hint: 'Think about LIFO vs FIFO principles'
        }
      ],
      'Mathematics': [
        {
          question: 'Calculate the derivative of f(x) = x² + 3x + 2',
          type: 'short_answer',
          difficulty: 'easy',
          hint: 'Apply the power rule and sum rule'
        },
        {
          question: 'Prove that the sum of angles in a triangle equals 180 degrees.',
          type: 'essay',
          difficulty: 'hard',
          hint: 'Consider using parallel lines and alternate angles'
        }
      ]
    }
    
    // Add subject-specific questions if available
    if (subjectQuestions[subject]) {
      questions.push(...subjectQuestions[subject])
    }
    
    // Add a challenging synthesis question
    questions.push({
      question: `Analyze how the concepts covered in this lecture relate to real-world applications. Provide specific examples and explain the connections.`,
      type: 'essay',
      difficulty: 'hard',
      hint: 'Think about practical implementations and interdisciplinary connections'
    })
    
    return questions.slice(0, 6)
  }

  private generateAdditionalResources(subject: string, keyTopics: string[]): Array<{
    type: 'reading' | 'video' | 'exercise' | 'reference'
    title: string
    description: string
    url?: string
  }> {
    const resources: Array<{
      type: 'reading' | 'video' | 'exercise' | 'reference'
      title: string
      description: string
      url?: string
    }> = []
    
    // Subject-specific resources
    const subjectResources: Record<string, Array<{
      type: 'reading' | 'video' | 'exercise' | 'reference'
      title: string
      description: string
      url?: string
    }>> = {
      'Computer Science': [
        {
          type: 'reading',
          title: 'Introduction to Algorithms (CLRS)',
          description: 'Comprehensive textbook covering fundamental algorithms and data structures'
        },
        {
          type: 'video',
          title: 'MIT OpenCourseWare - Algorithms',
          description: 'Free video lectures on algorithmic thinking and analysis'
        },
        {
          type: 'exercise',
          title: 'LeetCode Practice Problems',
          description: 'Coding challenges to reinforce algorithmic concepts'
        }
      ],
      'Mathematics': [
        {
          type: 'reading',
          title: 'Khan Academy - Calculus',
          description: 'Step-by-step explanations of calculus concepts with practice problems'
        },
        {
          type: 'video',
          title: '3Blue1Brown - Essence of Calculus',
          description: 'Visual explanations of calculus concepts and intuition'
        },
        {
          type: 'reference',
          title: 'Wolfram MathWorld',
          description: 'Comprehensive mathematics reference with definitions and examples'
        }
      ],
      'Physics': [
        {
          type: 'reading',
          title: 'Feynman Lectures on Physics',
          description: 'Classic physics textbook with clear explanations and insights'
        },
        {
          type: 'video',
          title: 'Walter Lewin Physics Lectures',
          description: 'Engaging physics demonstrations and explanations'
        },
        {
          type: 'exercise',
          title: 'PhET Interactive Simulations',
          description: 'Interactive physics simulations for hands-on learning'
        }
      ]
    }
    
    // Use subject-specific resources or generic ones
    const specificResources = subjectResources[subject] || [
      {
        type: 'reading',
        title: 'Recommended Textbook',
        description: 'Standard textbook covering the fundamental concepts in this field'
      },
      {
        type: 'video',
        title: 'Educational Video Series',
        description: 'Video lectures explaining key concepts with visual examples'
      },
      {
        type: 'exercise',
        title: 'Practice Problems',
        description: 'Structured exercises to reinforce learning and test understanding'
      }
    ]
    
    resources.push(...specificResources)
    
    // Add topic-specific resources
    keyTopics.slice(0, 2).forEach(topic => {
      resources.push({
        type: 'reference',
        title: `${topic} Reference Guide`,
        description: `Detailed reference material specifically focused on ${topic.toLowerCase()}`
      })
    })
    
    return resources.slice(0, 5)
  }

  private calculateComprehensionScore(content: string, subject: string) {
    const wordCount = content.split(' ').length
    const sentences = content.split(/[.!?]+/).length
    const avgSentenceLength = wordCount / sentences
    
    // Base scores on content characteristics
    let conceptual = 75
    let factual = 80
    let analytical = 70
    let practical = 65
    
    // Adjust based on content complexity
    if (avgSentenceLength > 20) {
      conceptual += 10
      analytical += 10
    }
    
    // Adjust based on subject
    const subjectAdjustments: Record<string, { conceptual: number; factual: number; analytical: number; practical: number }> = {
      'Computer Science': { conceptual: 5, factual: 0, analytical: 10, practical: 15 },
      'Mathematics': { conceptual: 10, factual: 5, analytical: 15, practical: 5 },
      'Physics': { conceptual: 10, factual: 10, analytical: 10, practical: 10 }
    }
    
    const adjustments = subjectAdjustments[subject] || { conceptual: 0, factual: 0, analytical: 0, practical: 0 }
    
    conceptual = Math.min(100, Math.max(0, conceptual + adjustments.conceptual))
    factual = Math.min(100, Math.max(0, factual + adjustments.factual))
    analytical = Math.min(100, Math.max(0, analytical + adjustments.analytical))
    practical = Math.min(100, Math.max(0, practical + adjustments.practical))
    
    const overall = Math.round((conceptual + factual + analytical + practical) / 4)
    
    return {
      overall,
      categories: {
        conceptual,
        factual,
        analytical,
        practical
      }
    }
  }

  private determineComplexity(content: string, subject: string): 'beginner' | 'intermediate' | 'advanced' {
    const wordCount = content.split(' ').length
    const sentences = content.split(/[.!?]+/).length
    const avgSentenceLength = wordCount / sentences
    
    // Count technical terms (words longer than 8 characters)
    const technicalTerms = content.split(' ').filter(word => word.length > 8).length
    const technicalDensity = technicalTerms / wordCount
    
    // Complexity indicators
    let complexityScore = 0
    
    if (avgSentenceLength > 15) complexityScore += 1
    if (technicalDensity > 0.1) complexityScore += 1
    if (wordCount > 1000) complexityScore += 1
    if (content.includes('theorem') || content.includes('proof')) complexityScore += 1
    if (subject === 'Mathematics' || subject === 'Physics') complexityScore += 1
    
    if (complexityScore >= 4) return 'advanced'
    if (complexityScore >= 2) return 'intermediate'
    return 'beginner'
  }

  private estimateDuration(wordCount: number): string {
    // Average speaking rate is about 150-160 words per minute
    const minutes = Math.round(wordCount / 155)
    
    if (minutes < 60) {
      return `${minutes} minutes`
    } else {
      const hours = Math.floor(minutes / 60)
      const remainingMinutes = minutes % 60
      return `${hours}h ${remainingMinutes}m`
    }
  }

  private generateTags(content: string, subject: string, keyTopics: string[]): string[] {
    const tags: string[] = []
    
    // Add subject as primary tag
    tags.push(subject)
    
    // Add key topics as tags
    tags.push(...keyTopics.slice(0, 3))
    
    // Add complexity-based tags
    const lowerContent = content.toLowerCase()
    if (lowerContent.includes('beginner') || lowerContent.includes('introduction')) {
      tags.push('Introductory')
    }
    if (lowerContent.includes('advanced') || lowerContent.includes('complex')) {
      tags.push('Advanced')
    }
    
    // Add format-based tags
    if (lowerContent.includes('example') || lowerContent.includes('case study')) {
      tags.push('Examples')
    }
    if (lowerContent.includes('problem') || lowerContent.includes('exercise')) {
      tags.push('Problem Solving')
    }
    if (lowerContent.includes('theory') || lowerContent.includes('principle')) {
      tags.push('Theoretical')
    }
    if (lowerContent.includes('practical') || lowerContent.includes('application')) {
      tags.push('Applied')
    }
    
    return [...new Set(tags)].slice(0, 8)
  }
}

export async function POST(request: NextRequest) {
  try {
    const formData = await request.formData()
    
    const title = formData.get('title') as string
    const subject = formData.get('subject') as string
    const type = formData.get('type') as string
    const lecturer = formData.get('lecturer') as string
    const content = formData.get('content') as string
    const audioFile = formData.get('audioFile') as File | null

    const summarizerAI = LectureSummarizerAI.getInstance()
    
    const summary = await summarizerAI.processLecture(
      title,
      subject,
      lecturer,
      content,
      audioFile || undefined
    )

    return NextResponse.json(summary)

  } catch (error) {
    console.error('Lecture Summarizer Error:', error)
    return NextResponse.json(
      { error: 'Lecture processing failed' },
      { status: 500 }
    )
  }
}
