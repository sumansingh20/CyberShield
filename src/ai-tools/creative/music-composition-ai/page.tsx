'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Label } from '@/src/ui/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Badge } from '@/src/ui/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Progress } from '@/src/ui/components/ui/progress'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Slider } from '@/src/ui/components/ui/slider'
import { Music, Play, Pause, Download, Share, Volume2, AlertTriangle, Settings, BarChart3 } from 'lucide-react'

interface MusicComposition {
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
  audioUrl?: string
  timestamp: string
}

const MUSIC_GENRES = [
  'Classical',
  'Jazz',
  'Pop',
  'Rock',
  'Electronic',
  'Ambient',
  'Folk',
  'Blues',
  'Funk',
  'Hip Hop',
  'R&B',
  'Country'
]

const MUSICAL_KEYS = [
  'C Major', 'C Minor',
  'D Major', 'D Minor',
  'E Major', 'E Minor',
  'F Major', 'F Minor',
  'G Major', 'G Minor',
  'A Major', 'A Minor',
  'B Major', 'B Minor'
]

const TIME_SIGNATURES = [
  '4/4', '3/4', '2/4', '6/8', '9/8', '12/8', '5/4', '7/8'
]

export default function MusicCompositionAIPage() {
  const [genre, setGenre] = useState('')
  const [musicalKey, setMusicalKey] = useState('')
  const [timeSignature, setTimeSignature] = useState('')
  const [tempo, setTempo] = useState([120])
  const [inspiration, setInspiration] = useState('')
  const [complexity, setComplexity] = useState([50])
  const [duration, setDuration] = useState([60])
  const [isComposing, setIsComposing] = useState(false)
  const [progress, setProgress] = useState(0)
  const [composition, setComposition] = useState<MusicComposition | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [isPlaying, setIsPlaying] = useState(false)

  const handleCompose = async () => {
    if (!genre) {
      setError('Please select a music genre')
      return
    }

    setIsComposing(true)
    setError(null)
    setProgress(0)

    // Simulate composition progress
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval)
          return 90
        }
        return prev + 15
      })
    }, 300)

    try {
      const response = await fetch('/api/tools/music-composition-ai', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'compose',
          genre: genre.toLowerCase(),
          key: musicalKey || 'C Major',
          timeSignature: timeSignature || '4/4',
          tempo: tempo[0],
          inspiration: inspiration.trim() || undefined,
          complexity: complexity[0],
          duration: duration[0]
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Music composition failed')
      }

      setComposition(data)
      setProgress(100)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Music composition failed')
    } finally {
      clearInterval(progressInterval)
      setIsComposing(false)
      setTimeout(() => setProgress(0), 1000)
    }
  }

  const togglePlayback = () => {
    setIsPlaying(!isPlaying)
    // In a real implementation, this would control audio playback
  }

  const downloadComposition = () => {
    if (!composition) return

    const content = `Music Composition: ${composition.title}
Genre: ${composition.genre}
Key: ${composition.key}
Tempo: ${composition.tempo} BPM
Time Signature: ${composition.timeSignature}
Generated: ${new Date(composition.timestamp).toLocaleString()}

SONG STRUCTURE:
${composition.structure.map((section, i) => `${i + 1}. ${section}`).join('\n')}

MUSICAL SCORE:
${composition.generatedScore}

MELODY NOTES:
${composition.melody.notes.join(' - ')}

CHORD PROGRESSION:
${composition.melody.chords.join(' | ')}

AUDIO ANALYSIS:
- Harmonic Complexity: ${composition.audioAnalysis.harmonicComplexity}%
- Melodic Movement: ${composition.audioAnalysis.melodicMovement}%
- Rhythmic Variation: ${composition.audioAnalysis.rhythmicVariation}%`

    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${composition.title.replace(/\s+/g, '_')}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const getGenreColor = (genre: string): string => {
    const colors: { [key: string]: string } = {
      classical: 'bg-purple-100 text-purple-800',
      jazz: 'bg-yellow-100 text-yellow-800',
      pop: 'bg-pink-100 text-pink-800',
      rock: 'bg-red-100 text-red-800',
      electronic: 'bg-blue-100 text-blue-800',
      ambient: 'bg-green-100 text-green-800',
      folk: 'bg-orange-100 text-orange-800',
      blues: 'bg-indigo-100 text-indigo-800'
    }
    return colors[genre.toLowerCase()] || 'bg-gray-100 text-gray-800'
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-transparent">
          AI Music Composition
        </h1>
        <p className="text-lg text-muted-foreground">
          Generate original musical compositions with AI-powered melody, harmony, and rhythm generation
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Composition Settings */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Music className="w-5 h-5" />
                Composition Settings
              </CardTitle>
              <CardDescription>
                Configure musical parameters for AI composition
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="genre">Music Genre *</Label>
                <Select value={genre} onValueChange={setGenre} disabled={isComposing}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select genre" />
                  </SelectTrigger>
                  <SelectContent>
                    {MUSIC_GENRES.map((g) => (
                      <SelectItem key={g} value={g}>
                        {g}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="key">Musical Key</Label>
                  <Select value={musicalKey} onValueChange={setMusicalKey} disabled={isComposing}>
                    <SelectTrigger>
                      <SelectValue placeholder="C Major" />
                    </SelectTrigger>
                    <SelectContent>
                      {MUSICAL_KEYS.map((key) => (
                        <SelectItem key={key} value={key}>
                          {key}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="timeSignature">Time Signature</Label>
                  <Select value={timeSignature} onValueChange={setTimeSignature} disabled={isComposing}>
                    <SelectTrigger>
                      <SelectValue placeholder="4/4" />
                    </SelectTrigger>
                    <SelectContent>
                      {TIME_SIGNATURES.map((sig) => (
                        <SelectItem key={sig} value={sig}>
                          {sig}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-3">
                <Label>Tempo: {tempo[0]} BPM</Label>
                <Slider
                  value={tempo}
                  onValueChange={setTempo}
                  min={60}
                  max={200}
                  step={5}
                  disabled={isComposing}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Slow (60)</span>
                  <span>Moderate (120)</span>
                  <span>Fast (200)</span>
                </div>
              </div>

              <div className="space-y-3">
                <Label>Complexity: {complexity[0]}%</Label>
                <Slider
                  value={complexity}
                  onValueChange={setComplexity}
                  min={10}
                  max={100}
                  step={10}
                  disabled={isComposing}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Simple</span>
                  <span>Moderate</span>
                  <span>Complex</span>
                </div>
              </div>

              <div className="space-y-3">
                <Label>Duration: {duration[0]} seconds</Label>
                <Slider
                  value={duration}
                  onValueChange={setDuration}
                  min={30}
                  max={300}
                  step={15}
                  disabled={isComposing}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>30s</span>
                  <span>2m</span>
                  <span>5m</span>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="inspiration">Inspiration/Theme</Label>
                <Textarea
                  id="inspiration"
                  placeholder="Describe the mood, theme, or inspiration for your composition..."
                  value={inspiration}
                  onChange={(e) => setInspiration(e.target.value)}
                  rows={3}
                  disabled={isComposing}
                />
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              {isComposing && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Composing music...</span>
                    <span className="text-sm font-medium">{progress}%</span>
                  </div>
                  <Progress value={progress} />
                </div>
              )}

              <Button 
                onClick={handleCompose} 
                disabled={isComposing || !genre}
                className="w-full"
              >
                <Music className="w-4 h-4 mr-2" />
                {isComposing ? 'Composing...' : 'Generate Composition'}
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Results */}
        <div className="lg:col-span-2">
          {composition && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Music className="w-5 h-5" />
                      {composition.title}
                    </CardTitle>
                    <CardDescription>
                      AI-generated {composition.genre} composition in {composition.key}
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={getGenreColor(composition.genre)}>
                      {composition.genre}
                    </Badge>
                    <Badge variant="outline">
                      {composition.tempo} BPM
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="player" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="player">Player</TabsTrigger>
                    <TabsTrigger value="score">Score</TabsTrigger>
                    <TabsTrigger value="analysis">Analysis</TabsTrigger>
                    <TabsTrigger value="structure">Structure</TabsTrigger>
                  </TabsList>

                  <TabsContent value="player" className="space-y-6">
                    {/* Audio Player Interface */}
                    <Card>
                      <CardContent className="pt-6">
                        <div className="flex items-center justify-center mb-6">
                          <div className="w-32 h-32 bg-gradient-to-br from-purple-400 to-pink-400 rounded-full flex items-center justify-center">
                            <BarChart3 className="w-16 h-16 text-white" />
                          </div>
                        </div>
                        
                        <div className="text-center mb-6">
                          <h3 className="text-xl font-semibold">{composition.title}</h3>
                          <p className="text-muted-foreground">{composition.genre} • {composition.key}</p>
                        </div>

                        <div className="flex items-center justify-center gap-4 mb-6">
                          <Button
                            variant="outline"
                            size="lg"
                            onClick={togglePlayback}
                            className="rounded-full w-16 h-16"
                          >
                            {isPlaying ? (
                              <Pause className="w-8 h-8" />
                            ) : (
                              <Play className="w-8 h-8 ml-1" />
                            )}
                          </Button>
                        </div>

                        <div className="space-y-2 mb-6">
                          <div className="bg-gray-200 h-2 rounded-full">
                            <div className="bg-purple-500 h-2 rounded-full w-1/3"></div>
                          </div>
                          <div className="flex justify-between text-xs text-muted-foreground">
                            <span>0:00</span>
                            <span>{Math.floor(duration[0] / 60)}:{(duration[0] % 60).toString().padStart(2, '0')}</span>
                          </div>
                        </div>

                        <div className="flex items-center justify-center gap-4">
                          <Button variant="outline" size="sm">
                            <Volume2 className="w-4 h-4 mr-2" />
                            Volume
                          </Button>
                          <Button variant="outline" size="sm" onClick={downloadComposition}>
                            <Download className="w-4 h-4 mr-2" />
                            Download
                          </Button>
                          <Button variant="outline" size="sm">
                            <Share className="w-4 h-4 mr-2" />
                            Share
                          </Button>
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="score" className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold">Musical Score</h3>
                      <div className="flex gap-2">
                        <Badge variant="outline">{composition.key}</Badge>
                        <Badge variant="outline">{composition.timeSignature}</Badge>
                      </div>
                    </div>
                    
                    <Card>
                      <CardContent className="pt-6">
                        <div className="bg-white border rounded-lg p-6">
                          <pre className="font-mono text-sm whitespace-pre-wrap">
{composition.generatedScore}
                          </pre>
                        </div>
                      </CardContent>
                    </Card>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Melody Notes</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex flex-wrap gap-1">
                            {composition.melody.notes.slice(0, 12).map((note, index) => (
                              <Badge key={index} variant="secondary" className="font-mono">
                                {note}
                              </Badge>
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Chord Progression</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex flex-wrap gap-1">
                            {composition.melody.chords.map((chord, index) => (
                              <Badge key={index} variant="outline" className="font-mono">
                                {chord}
                              </Badge>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="analysis" className="space-y-4">
                    <h3 className="font-semibold">Audio Analysis</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Harmonic Complexity</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-purple-600">
                              {composition.audioAnalysis.harmonicComplexity}%
                            </div>
                            <Progress value={composition.audioAnalysis.harmonicComplexity} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Melodic Movement</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-blue-600">
                              {composition.audioAnalysis.melodicMovement}%
                            </div>
                            <Progress value={composition.audioAnalysis.melodicMovement} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Rhythmic Variation</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-green-600">
                              {composition.audioAnalysis.rhythmicVariation}%
                            </div>
                            <Progress value={composition.audioAnalysis.rhythmicVariation} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Composition Characteristics</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="font-medium">Tempo:</span> {composition.tempo} BPM
                          </div>
                          <div>
                            <span className="font-medium">Time Signature:</span> {composition.timeSignature}
                          </div>
                          <div>
                            <span className="font-medium">Key:</span> {composition.key}
                          </div>
                          <div>
                            <span className="font-medium">Genre:</span> {composition.genre}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="structure" className="space-y-4">
                    <h3 className="font-semibold">Song Structure</h3>
                    
                    <div className="space-y-3">
                      {composition.structure.map((section, index) => (
                        <Card key={index}>
                          <CardContent className="pt-4">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center gap-3">
                                <Badge variant="outline">{index + 1}</Badge>
                                <span className="font-medium">{section}</span>
                              </div>
                              <div className="text-sm text-muted-foreground">
                                {Math.floor((duration[0] / composition.structure.length) * (index + 1) / 60)}:
                                {Math.floor(((duration[0] / composition.structure.length) * (index + 1)) % 60).toString().padStart(2, '0')}
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          )}

          {!composition && (
            <Card>
              <CardContent className="py-12 text-center">
                <Music className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Composition Generated</h3>
                <p className="text-muted-foreground">
                  Select a music genre and configure your settings to generate an original AI composition.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
