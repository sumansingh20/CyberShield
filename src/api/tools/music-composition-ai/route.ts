import { NextRequest, NextResponse } from 'next/server'
import { connectDB } from '@/src/core/lib/mongodb'

// Music theory and composition algorithms
class MusicCompositionAI {
  private static readonly NOTE_FREQUENCIES = {
    'C': 261.63, 'C#': 277.18, 'D': 293.66, 'D#': 311.13,
    'E': 329.63, 'F': 349.23, 'F#': 369.99, 'G': 392.00,
    'G#': 415.30, 'A': 440.00, 'A#': 466.16, 'B': 493.88
  }

  private static readonly CHORD_PROGRESSIONS = {
    'classical': ['I', 'V', 'vi', 'IV', 'I', 'V', 'I'],
    'jazz': ['IIMaj7', 'V7', 'IMaj7', 'VIMaj7', 'IIMaj7', 'V7', 'IMaj7'],
    'pop': ['I', 'V', 'vi', 'IV', 'I', 'V', 'vi', 'IV'],
    'rock': ['I', 'bVII', 'IV', 'I', 'V', 'IV', 'I'],
    'blues': ['I7', 'I7', 'I7', 'I7', 'IV7', 'IV7', 'I7', 'I7', 'V7', 'IV7', 'I7', 'V7'],
    'electronic': ['i', 'VI', 'III', 'VII', 'i', 'VI', 'III', 'VII'],
    'ambient': ['IMaj7', 'IIIMaj7', 'VIMaj7', 'IVMaj7', 'IMaj7', 'VIMaj7'],
    'folk': ['I', 'IV', 'V', 'I', 'vi', 'IV', 'V', 'I']
  }

  private static readonly SCALE_PATTERNS = {
    'major': [0, 2, 4, 5, 7, 9, 11],
    'minor': [0, 2, 3, 5, 7, 8, 10],
    'dorian': [0, 2, 3, 5, 7, 9, 10],
    'mixolydian': [0, 2, 4, 5, 7, 9, 10],
    'pentatonic': [0, 2, 4, 7, 9],
    'blues': [0, 3, 5, 6, 7, 10]
  }

  static async composeMusic(params: {
    genre: string
    key: string
    timeSignature: string
    tempo: number
    complexity: number
    duration: number
    inspiration?: string
  }): Promise<{
    title: string
    genre: string
    tempo: number
    key: string
    timeSignature: string
    structure: string[]
    melody: {
      notes: string[]
      rhythm: string[]
      chords: string[]
    }
    audioAnalysis: {
      harmonicComplexity: number
      melodicMovement: number
      rhythmicVariation: number
    }
    generatedScore: string
    timestamp: string
  }> {
    const rootNote = this.parseKey(params.key)
    const scale = this.generateScale(rootNote, params.key.includes('Minor') ? 'minor' : 'major')
    const chordProgression = this.generateChordProgression(params.genre, params.complexity)
    const melody = this.generateMelody(scale, params.complexity, params.duration, params.tempo)
    const structure = this.generateSongStructure(params.genre, params.duration)
    const score = this.generateMusicalScore(melody, chordProgression, params)
    
    return {
      title: this.generateTitle(params.genre, params.inspiration),
      genre: this.capitalizeFirst(params.genre),
      tempo: params.tempo,
      key: params.key,
      timeSignature: params.timeSignature,
      structure: structure,
      melody: {
        notes: melody.notes,
        rhythm: melody.rhythm,
        chords: chordProgression.chords
      },
      audioAnalysis: {
        harmonicComplexity: this.calculateHarmonicComplexity(chordProgression, params.complexity),
        melodicMovement: this.calculateMelodicMovement(melody),
        rhythmicVariation: this.calculateRhythmicVariation(melody.rhythm, params.complexity)
      },
      generatedScore: score,
      timestamp: new Date().toISOString()
    }
  }

  private static parseKey(key: string): string {
    return key.split(' ')[0]
  }

  private static generateScale(rootNote: string, scaleType: string): string[] {
    const pattern = this.SCALE_PATTERNS[scaleType] || this.SCALE_PATTERNS.major
    const notes = ['C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#', 'A', 'A#', 'B']
    const rootIndex = notes.indexOf(rootNote)
    
    return pattern.map(interval => {
      const noteIndex = (rootIndex + interval) % 12
      return notes[noteIndex]
    })
  }

  private static generateChordProgression(genre: string, complexity: number): {
    chords: string[]
    romanNumerals: string[]
  } {
    const baseProgression = this.CHORD_PROGRESSIONS[genre] || this.CHORD_PROGRESSIONS.pop
    let chords = [...baseProgression]
    
    // Add complexity variations
    if (complexity > 70) {
      chords = this.addComplexityToProgression(chords)
    }
    
    // Convert roman numerals to actual chords
    const actualChords = chords.map(roman => this.convertRomanToChord(roman))
    
    return {
      chords: actualChords,
      romanNumerals: chords
    }
  }

  private static addComplexityToProgression(progression: string[]): string[] {
    const complexVariations = {
      'I': ['IMaj7', 'Iadd9', 'I6'],
      'V': ['V7', 'V9', 'V13'],
      'vi': ['vi7', 'viadd9', 'vi/III'],
      'IV': ['IVMaj7', 'IVadd9', 'IV6']
    }
    
    return progression.map(chord => {
      const variations = complexVariations[chord as keyof typeof complexVariations]
      return variations ? variations[Math.floor(Math.random() * variations.length)] : chord
    })
  }

  private static convertRomanToChord(roman: string): string {
    // Simplified chord conversion
    const chordMap: { [key: string]: string } = {
      'I': 'C', 'IMaj7': 'CMaj7', 'Iadd9': 'Cadd9',
      'V': 'G', 'V7': 'G7', 'V9': 'G9',
      'vi': 'Am', 'vi7': 'Am7', 'viadd9': 'Amadd9',
      'IV': 'F', 'IVMaj7': 'FMaj7', 'IVadd9': 'Fadd9',
      'ii': 'Dm', 'IIMaj7': 'DMaj7',
      'iii': 'Em', 'III': 'E',
      'VII': 'B', 'bVII': 'Bb'
    }
    
    return chordMap[roman] || 'C'
  }

  private static generateMelody(
    scale: string[], 
    complexity: number, 
    duration: number, 
    tempo: number
  ): {
    notes: string[]
    rhythm: string[]
  } {
    const noteCount = Math.floor((duration * tempo) / 240) // Approximate notes based on tempo
    const notes: string[] = []
    const rhythm: string[] = []
    
    // Generate melodic line with varying complexity
    for (let i = 0; i < noteCount; i++) {
      // Choose notes from scale with some chromatic passing tones for complexity
      if (complexity > 60 && Math.random() < 0.2) {
        // Add chromatic notes
        const chromaticNotes = ['C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#', 'A', 'A#', 'B']
        notes.push(chromaticNotes[Math.floor(Math.random() * chromaticNotes.length)])
      } else {
        notes.push(scale[Math.floor(Math.random() * scale.length)])
      }
      
      // Generate rhythm patterns
      const rhythmValues = this.generateRhythmPattern(complexity)
      rhythm.push(rhythmValues[i % rhythmValues.length])
    }
    
    return { notes, rhythm }
  }

  private static generateRhythmPattern(complexity: number): string[] {
    if (complexity < 30) {
      // Simple rhythms
      return ['quarter', 'quarter', 'half', 'quarter', 'quarter', 'half']
    } else if (complexity < 70) {
      // Moderate rhythms
      return ['eighth', 'eighth', 'quarter', 'eighth', 'eighth', 'quarter', 'eighth', 'eighth']
    } else {
      // Complex rhythms
      return ['sixteenth', 'sixteenth', 'eighth', 'sixteenth', 'eighth', 'quarter', 'triplet', 'sixteenth']
    }
  }

  private static generateSongStructure(genre: string, duration: number): string[] {
    const structures = {
      'classical': ['Introduction', 'Exposition', 'Development', 'Recapitulation', 'Coda'],
      'pop': ['Intro', 'Verse 1', 'Chorus', 'Verse 2', 'Chorus', 'Bridge', 'Chorus', 'Outro'],
      'jazz': ['Head', 'Solo Section', 'Comping', 'Trading Fours', 'Head Out'],
      'blues': ['Intro', '12-Bar Blues', '12-Bar Blues', 'Solo', '12-Bar Blues', 'Outro'],
      'electronic': ['Intro', 'Build-up', 'Drop', 'Breakdown', 'Build-up', 'Drop', 'Outro'],
      'rock': ['Intro', 'Verse', 'Chorus', 'Verse', 'Chorus', 'Solo', 'Chorus', 'Outro']
    }
    
    let structure = structures[genre] || structures.pop
    
    // Adjust structure length based on duration
    if (duration < 90) {
      structure = structure.slice(0, Math.max(4, Math.floor(structure.length * 0.7)))
    } else if (duration > 180) {
      structure = [...structure, 'Extended Solo', 'Final Chorus', 'Extended Outro']
    }
    
    return structure
  }

  private static generateMusicalScore(
    melody: { notes: string[], rhythm: string[] },
    chordProgression: { chords: string[] },
    params: any
  ): string {
    const scoreHeader = `Title: ${this.generateTitle(params.genre, params.inspiration)}
Composer: AI Music Generator
Key: ${params.key}
Time Signature: ${params.timeSignature}
Tempo: ${params.tempo} BPM

`

    const melodyLine = `Melody Line:
${melody.notes.slice(0, 16).map((note, i) => 
  `${note}(${melody.rhythm[i] || 'quarter'})`
).join(' - ')}

`

    const chordChart = `Chord Progression:
${chordProgression.chords.map((chord, i) => 
  `| ${chord.padEnd(6)} |`
).join('')}

`

    const notation = `Musical Notation (Simplified):
Measure 1: ${melody.notes.slice(0, 4).join(' ')} | ${chordProgression.chords[0] || 'C'}
Measure 2: ${melody.notes.slice(4, 8).join(' ')} | ${chordProgression.chords[1] || 'G'}
Measure 3: ${melody.notes.slice(8, 12).join(' ')} | ${chordProgression.chords[2] || 'Am'}
Measure 4: ${melody.notes.slice(12, 16).join(' ')} | ${chordProgression.chords[3] || 'F'}

Performance Notes:
- Dynamics: Start mp, build to mf in chorus
- Articulation: Legato in verses, staccato in rhythmic sections
- Expression: ${this.getExpressionMarking(params.genre)}
`

    return scoreHeader + melodyLine + chordChart + notation
  }

  private static getExpressionMarking(genre: string): string {
    const expressions = {
      'classical': 'Espressivo with classical phrasing',
      'jazz': 'Swing feel with syncopated rhythms',
      'blues': 'Soulful with blues inflections',
      'pop': 'Catchy and accessible phrasing',
      'rock': 'Energetic with strong downbeats',
      'electronic': 'Precise timing with electronic textures',
      'ambient': 'Ethereal and spacious',
      'folk': 'Natural and storytelling approach'
    }
    
    return expressions[genre] || 'Expressive and musical'
  }

  private static generateTitle(genre: string, inspiration?: string): string {
    if (inspiration) {
      const inspirationWords = inspiration.split(' ').filter(word => word.length > 3)
      if (inspirationWords.length > 0) {
        const randomWord = inspirationWords[Math.floor(Math.random() * inspirationWords.length)]
        return `${randomWord} ${this.getGenreTitle(genre)}`
      }
    }
    
    const titles = {
      'classical': ['Sonata in AI', 'Digital Symphony', 'Algorithmic Prelude', 'Binary Variations'],
      'jazz': ['AI Blue Note', 'Synthetic Swing', 'Digital Bebop', 'Cyber Jazz Suite'],
      'pop': ['Electronic Dreams', 'Digital Love', 'AI Anthem', 'Future Pop'],
      'rock': ['Silicon Thunder', 'Digital Revolution', 'AI Rock Anthem', 'Electric Storm'],
      'blues': ['Binary Blues', 'Digital Delta', 'AI Lament', 'Cyber Blues'],
      'electronic': ['Neural Network', 'Digital Pulse', 'Synthetic Waves', 'AI Frequency'],
      'ambient': ['Digital Atmosphere', 'AI Soundscape', 'Synthetic Space', 'Electronic Meditation'],
      'folk': ['Digital Folk Tale', 'AI Ballad', 'Synthetic Stories', 'Electronic Tradition']
    }
    
    const genreTitles = titles[genre] || titles.pop
    return genreTitles[Math.floor(Math.random() * genreTitles.length)]
  }

  private static getGenreTitle(genre: string): string {
    const suffixes = {
      'classical': 'Movement',
      'jazz': 'Standard',
      'pop': 'Hit',
      'rock': 'Anthem',
      'blues': 'Blues',
      'electronic': 'Track',
      'ambient': 'Soundscape',
      'folk': 'Ballad'
    }
    
    return suffixes[genre] || 'Song'
  }

  private static calculateHarmonicComplexity(
    chordProgression: { chords: string[] }, 
    complexity: number
  ): number {
    let baseComplexity = 40
    
    // Add complexity based on chord types
    const complexChords = chordProgression.chords.filter(chord => 
      chord.includes('7') || chord.includes('9') || chord.includes('add') || chord.includes('Maj7')
    )
    
    baseComplexity += (complexChords.length / chordProgression.chords.length) * 30
    baseComplexity += (complexity / 100) * 30
    
    return Math.min(95, Math.round(baseComplexity))
  }

  private static calculateMelodicMovement(melody: { notes: string[] }): number {
    let movement = 0
    const noteValues = melody.notes.map(note => {
      const noteMap: { [key: string]: number } = {
        'C': 0, 'C#': 1, 'D': 2, 'D#': 3, 'E': 4, 'F': 5,
        'F#': 6, 'G': 7, 'G#': 8, 'A': 9, 'A#': 10, 'B': 11
      }
      return noteMap[note] || 0
    })
    
    for (let i = 1; i < noteValues.length; i++) {
      movement += Math.abs(noteValues[i] - noteValues[i - 1])
    }
    
    const averageMovement = movement / (noteValues.length - 1)
    return Math.min(95, Math.round((averageMovement / 6) * 100))
  }

  private static calculateRhythmicVariation(rhythm: string[], complexity: number): number {
    const uniqueRhythms = new Set(rhythm)
    const baseVariation = (uniqueRhythms.size / rhythm.length) * 60
    const complexityBonus = (complexity / 100) * 40
    
    return Math.min(95, Math.round(baseVariation + complexityBonus))
  }

  private static capitalizeFirst(str: string): string {
    return str.charAt(0).toUpperCase() + str.slice(1)
  }
}

export async function POST(request: NextRequest) {
  try {
    await connectDB()
    
    const body = await request.json()
    const { type, genre, key, timeSignature, tempo, complexity, duration, inspiration } = body
    
    if (!type || !genre) {
      return NextResponse.json({
        error: 'Type and genre are required'
      }, { status: 400 })
    }
    
    if (type === 'compose') {
      // Generate music composition
      const composition = await MusicCompositionAI.composeMusic({
        genre: genre.toLowerCase(),
        key: key || 'C Major',
        timeSignature: timeSignature || '4/4',
        tempo: tempo || 120,
        complexity: complexity || 50,
        duration: duration || 60,
        inspiration
      })
      
      return NextResponse.json(composition)
    }
    
    return NextResponse.json({
      error: 'Unsupported composition type'
    }, { status: 400 })
    
  } catch (error) {
    console.error('Music Composition AI Error:', error)
    return NextResponse.json({
      error: 'Music composition failed',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 })
  }
}
