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
import { Input } from '@/src/ui/components/ui/input'
import { PenTool, Download, Copy, RefreshCw, AlertTriangle, BookOpen, Lightbulb, Target } from 'lucide-react'

interface CreativeWriting {
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
}

const WRITING_GENRES = [
  'Fiction',
  'Poetry',
  'Essay',
  'Blog Post',
  'Short Story',
  'Script',
  'Song Lyrics',
  'Marketing Copy',
  'Technical Writing',
  'Creative Non-fiction',
  'Children\'s Story',
  'Horror'
]

const WRITING_TONES = [
  'Professional',
  'Casual',
  'Humorous',
  'Dramatic',
  'Inspirational',
  'Mysterious',
  'Romantic',
  'Dark',
  'Playful',
  'Serious',
  'Optimistic',
  'Melancholic'
]

const TARGET_AUDIENCES = [
  'General',
  'Children',
  'Teenagers',
  'Adults',
  'Professionals',
  'Academics',
  'Creative Writers',
  'Business'
]

export default function CreativeWritingAIPage() {
  const [prompt, setPrompt] = useState('')
  const [genre, setGenre] = useState('')
  const [tone, setTone] = useState('')
  const [targetAudience, setTargetAudience] = useState('')
  const [targetWordCount, setTargetWordCount] = useState([500])
  const [creativity, setCreativity] = useState([70])
  const [theme, setTheme] = useState('')
  const [isGenerating, setIsGenerating] = useState(false)
  const [progress, setProgress] = useState(0)
  const [writing, setWriting] = useState<CreativeWriting | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleGenerate = async () => {
    if (!prompt.trim() || !genre) {
      setError('Please provide a writing prompt and select a genre')
      return
    }

    setIsGenerating(true)
    setError(null)
    setProgress(0)

    // Simulate generation progress
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval)
          return 90
        }
        return prev + 10
      })
    }, 300)

    try {
      const response = await fetch('/api/tools/creative-writing-ai', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'generate',
          prompt: prompt.trim(),
          genre: genre.toLowerCase(),
          tone: tone || 'neutral',
          targetAudience: targetAudience || 'general',
          targetWordCount: targetWordCount[0],
          creativity: creativity[0],
          theme: theme.trim() || undefined
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Writing generation failed')
      }

      setWriting(data)
      setProgress(100)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Writing generation failed')
    } finally {
      clearInterval(progressInterval)
      setIsGenerating(false)
      setTimeout(() => setProgress(0), 1000)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const downloadWriting = () => {
    if (!writing) return

    const content = `${writing.title}

Genre: ${writing.genre}
Tone: ${writing.tone}
Word Count: ${writing.wordCount}
Reading Time: ${writing.metadata.estimatedReadingTime} minutes
Target Audience: ${writing.metadata.targetAudience}
Generated: ${new Date(writing.timestamp).toLocaleString()}

${writing.content}

---

LITERARY ANALYSIS:
- Readability Score: ${writing.literaryAnalysis.readabilityScore}%
- Sentiment Score: ${writing.literaryAnalysis.sentimentScore}%
- Creativity Index: ${writing.literaryAnalysis.creativityIndex}%
- Coherence Rating: ${writing.literaryAnalysis.coherenceRating}%

IMPROVEMENT SUGGESTIONS:
${writing.suggestions.improvements.map(s => `- ${s}`).join('\n')}

ALTERNATIVE APPROACHES:
${writing.suggestions.alternatives.map(s => `- ${s}`).join('\n')}

STYLE ENHANCEMENTS:
${writing.suggestions.styleEnhancements.map(s => `- ${s}`).join('\n')}`

    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${writing.title.replace(/\s+/g, '_')}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const getGenreColor = (genre: string): string => {
    const colors: { [key: string]: string } = {
      fiction: 'bg-blue-100 text-blue-800',
      poetry: 'bg-purple-100 text-purple-800',
      essay: 'bg-green-100 text-green-800',
      'blog post': 'bg-orange-100 text-orange-800',
      'short story': 'bg-pink-100 text-pink-800',
      script: 'bg-red-100 text-red-800',
      'song lyrics': 'bg-yellow-100 text-yellow-800',
      'marketing copy': 'bg-cyan-100 text-cyan-800'
    }
    return colors[genre.toLowerCase()] || 'bg-gray-100 text-gray-800'
  }

  const getDifficultyColor = (difficulty: string): string => {
    const colors = {
      'beginner': 'bg-green-100 text-green-800',
      'intermediate': 'bg-yellow-100 text-yellow-800',
      'advanced': 'bg-red-100 text-red-800'
    }
    return colors[difficulty.toLowerCase() as keyof typeof colors] || 'bg-gray-100 text-gray-800'
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
          Creative Writing AI Assistant
        </h1>
        <p className="text-lg text-muted-foreground">
          Generate compelling creative content with AI-powered writing assistance across multiple genres and styles
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Writing Settings */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <PenTool className="w-5 h-5" />
                Writing Parameters
              </CardTitle>
              <CardDescription>
                Configure your creative writing preferences
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="prompt">Writing Prompt *</Label>
                <Textarea
                  id="prompt"
                  placeholder="e.g., Write a story about a time traveler who accidentally changes history"
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  rows={4}
                  disabled={isGenerating}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="genre">Genre *</Label>
                  <Select value={genre} onValueChange={setGenre} disabled={isGenerating}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select genre" />
                    </SelectTrigger>
                    <SelectContent>
                      {WRITING_GENRES.map((g) => (
                        <SelectItem key={g} value={g}>
                          {g}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="tone">Tone</Label>
                  <Select value={tone} onValueChange={setTone} disabled={isGenerating}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select tone" />
                    </SelectTrigger>
                    <SelectContent>
                      {WRITING_TONES.map((t) => (
                        <SelectItem key={t} value={t}>
                          {t}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="targetAudience">Target Audience</Label>
                <Select value={targetAudience} onValueChange={setTargetAudience} disabled={isGenerating}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select audience" />
                  </SelectTrigger>
                  <SelectContent>
                    {TARGET_AUDIENCES.map((audience) => (
                      <SelectItem key={audience} value={audience}>
                        {audience}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="theme">Theme/Topic (Optional)</Label>
                <Input
                  id="theme"
                  placeholder="e.g., friendship, redemption, technology"
                  value={theme}
                  onChange={(e) => setTheme(e.target.value)}
                  disabled={isGenerating}
                />
              </div>

              <div className="space-y-3">
                <Label>Target Word Count: {targetWordCount[0]} words</Label>
                <Slider
                  value={targetWordCount}
                  onValueChange={setTargetWordCount}
                  min={100}
                  max={2000}
                  step={50}
                  disabled={isGenerating}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>100</span>
                  <span>1000</span>
                  <span>2000</span>
                </div>
              </div>

              <div className="space-y-3">
                <Label>Creativity Level: {creativity[0]}%</Label>
                <Slider
                  value={creativity}
                  onValueChange={setCreativity}
                  min={20}
                  max={100}
                  step={10}
                  disabled={isGenerating}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Conservative</span>
                  <span>Balanced</span>
                  <span>Experimental</span>
                </div>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              {isGenerating && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Generating content...</span>
                    <span className="text-sm font-medium">{progress}%</span>
                  </div>
                  <Progress value={progress} />
                </div>
              )}

              <Button 
                onClick={handleGenerate} 
                disabled={isGenerating || !prompt.trim() || !genre}
                className="w-full"
              >
                <PenTool className="w-4 h-4 mr-2" />
                {isGenerating ? 'Generating...' : 'Generate Writing'}
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Results */}
        <div className="lg:col-span-2">
          {writing && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <BookOpen className="w-5 h-5" />
                      {writing.title}
                    </CardTitle>
                    <CardDescription>
                      {writing.genre} • {writing.tone} tone • {writing.wordCount} words
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={getGenreColor(writing.genre)}>
                      {writing.genre}
                    </Badge>
                    <Badge variant="outline">
                      {writing.metadata.estimatedReadingTime}min read
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="content" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="content">Content</TabsTrigger>
                    <TabsTrigger value="analysis">Analysis</TabsTrigger>
                    <TabsTrigger value="suggestions">Suggestions</TabsTrigger>
                    <TabsTrigger value="metadata">Metadata</TabsTrigger>
                  </TabsList>

                  <TabsContent value="content" className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold">Generated Content</h3>
                      <div className="flex gap-2">
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => copyToClipboard(writing.content)}
                        >
                          <Copy className="w-4 h-4 mr-2" />
                          Copy
                        </Button>
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={downloadWriting}
                        >
                          <Download className="w-4 h-4 mr-2" />
                          Download
                        </Button>
                      </div>
                    </div>
                    
                    <Card>
                      <CardContent className="pt-6">
                        <div className="prose max-w-none">
                          <div className="whitespace-pre-wrap leading-relaxed">
                            {writing.content}
                          </div>
                        </div>
                      </CardContent>
                    </Card>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Word Count</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-2xl font-bold">{writing.wordCount}</span>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Reading Time</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-2xl font-bold">{writing.metadata.estimatedReadingTime}</span>
                          <span className="text-sm text-muted-foreground ml-1">min</span>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Difficulty</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <Badge className={getDifficultyColor(writing.metadata.difficulty)}>
                            {writing.metadata.difficulty}
                          </Badge>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="analysis" className="space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <Target className="w-5 h-5" />
                      <h3 className="font-semibold">Literary Analysis</h3>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Readability Score</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-blue-600">
                              {writing.literaryAnalysis.readabilityScore}%
                            </div>
                            <Progress value={writing.literaryAnalysis.readabilityScore} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Sentiment Score</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-green-600">
                              {writing.literaryAnalysis.sentimentScore}%
                            </div>
                            <Progress value={writing.literaryAnalysis.sentimentScore} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Creativity Index</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-purple-600">
                              {writing.literaryAnalysis.creativityIndex}%
                            </div>
                            <Progress value={writing.literaryAnalysis.creativityIndex} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Coherence Rating</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-orange-600">
                              {writing.literaryAnalysis.coherenceRating}%
                            </div>
                            <Progress value={writing.literaryAnalysis.coherenceRating} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Content Structure</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-3">
                        <div>
                          <h4 className="font-medium text-sm mb-1">Introduction</h4>
                          <p className="text-sm text-muted-foreground">{writing.structure.introduction}</p>
                        </div>
                        <div>
                          <h4 className="font-medium text-sm mb-1">Body Sections ({writing.structure.body.length})</h4>
                          <ul className="text-sm text-muted-foreground space-y-1">
                            {writing.structure.body.map((section, index) => (
                              <li key={index}>• {section}</li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <h4 className="font-medium text-sm mb-1">Conclusion</h4>
                          <p className="text-sm text-muted-foreground">{writing.structure.conclusion}</p>
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="suggestions" className="space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <Lightbulb className="w-5 h-5" />
                      <h3 className="font-semibold">AI Suggestions</h3>
                    </div>
                    
                    <div className="space-y-6">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm text-green-600">Improvements</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {writing.suggestions.improvements.map((improvement, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{improvement}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm text-blue-600">Alternative Approaches</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {writing.suggestions.alternatives.map((alternative, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{alternative}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm text-purple-600">Style Enhancements</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {writing.suggestions.styleEnhancements.map((enhancement, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-purple-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{enhancement}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="metadata" className="space-y-4">
                    <h3 className="font-semibold">Content Metadata</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Target Audience</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <Badge variant="secondary">{writing.metadata.targetAudience}</Badge>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Reading Difficulty</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <Badge className={getDifficultyColor(writing.metadata.difficulty)}>
                            {writing.metadata.difficulty}
                          </Badge>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Word Frequency Analysis</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex flex-wrap gap-2">
                          {Object.entries(writing.metadata.wordFrequency)
                            .slice(0, 10)
                            .map(([word, freq]) => (
                              <Badge key={word} variant="outline" className="text-xs">
                                {word} ({freq})
                              </Badge>
                            ))}
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          )}

          {!writing && (
            <Card>
              <CardContent className="py-12 text-center">
                <PenTool className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Content Generated</h3>
                <p className="text-muted-foreground">
                  Enter a writing prompt and select a genre to generate creative content with AI assistance.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
