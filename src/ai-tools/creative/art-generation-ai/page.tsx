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
import { Palette, Download, Share, Wand2, AlertTriangle, Image, Sparkles, Eye } from 'lucide-react'

interface ArtGeneration {
  prompt: string
  style: string
  mood: string
  colorPalette: string[]
  dimensions: string
  quality: string
  technique: string
  composition: {
    elements: string[]
    balance: number
    contrast: number
    harmony: number
  }
  styleAnalysis: {
    brushstrokes: string
    texture: string
    lighting: string
    perspective: string
  }
  imageData: string
  metadata: {
    aiModel: string
    processingTime: number
    iterations: number
    confidence: number
  }
  timestamp: string
}

const ART_STYLES = [
  'Realistic',
  'Impressionist',
  'Abstract',
  'Surreal',
  'Minimalist',
  'Expressionist',
  'Pop Art',
  'Digital Art',
  'Oil Painting',
  'Watercolor',
  'Pencil Sketch',
  'Photography'
]

const ART_MOODS = [
  'Peaceful',
  'Energetic',
  'Mysterious',
  'Romantic',
  'Dramatic',
  'Playful',
  'Melancholic',
  'Optimistic',
  'Dark',
  'Bright',
  'Ethereal',
  'Bold'
]

const COLOR_PALETTES = [
  { name: 'Warm', colors: ['#FF6B6B', '#FFE66D', '#FF8E53', '#D63031'] },
  { name: 'Cool', colors: ['#74B9FF', '#0984E3', '#6C5CE7', '#A29BFE'] },
  { name: 'Earth', colors: ['#8B4513', '#D2B48C', '#DEB887', '#F4A460'] },
  { name: 'Pastel', colors: ['#FFB3BA', '#BAFFC9', '#BAE1FF', '#FFFFBA'] },
  { name: 'Monochrome', colors: ['#000000', '#404040', '#808080', '#FFFFFF'] },
  { name: 'Vibrant', colors: ['#FF0080', '#00FF80', '#8000FF', '#FF8000'] }
]

const DIMENSIONS = [
  '512x512',
  '768x768',
  '1024x1024',
  '512x768',
  '768x512',
  '1920x1080'
]

export default function ArtGenerationAIPage() {
  const [prompt, setPrompt] = useState('')
  const [style, setStyle] = useState('')
  const [mood, setMood] = useState('')
  const [colorPalette, setColorPalette] = useState('')
  const [dimensions, setDimensions] = useState('')
  const [quality, setQuality] = useState([75])
  const [creativity, setCreativity] = useState([50])
  const [isGenerating, setIsGenerating] = useState(false)
  const [progress, setProgress] = useState(0)
  const [artwork, setArtwork] = useState<ArtGeneration | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleGenerate = async () => {
    if (!prompt.trim() || !style) {
      setError('Please provide an art prompt and select a style')
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
        return prev + 12
      })
    }, 400)

    try {
      const response = await fetch('/api/tools/art-generation-ai', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'generate',
          prompt: prompt.trim(),
          style: style.toLowerCase(),
          mood: mood || 'neutral',
          colorPalette: colorPalette || 'vibrant',
          dimensions: dimensions || '1024x1024',
          quality: quality[0],
          creativity: creativity[0]
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Art generation failed')
      }

      setArtwork(data)
      setProgress(100)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Art generation failed')
    } finally {
      clearInterval(progressInterval)
      setIsGenerating(false)
      setTimeout(() => setProgress(0), 1000)
    }
  }

  const downloadArtwork = () => {
    if (!artwork) return

    const content = `AI Generated Artwork: ${artwork.prompt}
Style: ${artwork.style}
Mood: ${artwork.mood}
Dimensions: ${artwork.dimensions}
Generated: ${new Date(artwork.timestamp).toLocaleString()}

COMPOSITION ANALYSIS:
- Balance: ${artwork.composition.balance}%
- Contrast: ${artwork.composition.contrast}%
- Harmony: ${artwork.composition.harmony}%

STYLE ANALYSIS:
- Brushstrokes: ${artwork.styleAnalysis.brushstrokes}
- Texture: ${artwork.styleAnalysis.texture}
- Lighting: ${artwork.styleAnalysis.lighting}
- Perspective: ${artwork.styleAnalysis.perspective}

TECHNICAL DETAILS:
- AI Model: ${artwork.metadata.aiModel}
- Processing Time: ${artwork.metadata.processingTime}ms
- Iterations: ${artwork.metadata.iterations}
- Confidence: ${artwork.metadata.confidence}%

ELEMENTS:
${artwork.composition.elements.map(element => `- ${element}`).join('\n')}

COLOR PALETTE:
${artwork.colorPalette.map(color => `- ${color}`).join('\n')}`

    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `artwork_${Date.now()}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const getStyleColor = (style: string): string => {
    const colors: { [key: string]: string } = {
      realistic: 'bg-blue-100 text-blue-800',
      impressionist: 'bg-purple-100 text-purple-800',
      abstract: 'bg-green-100 text-green-800',
      surreal: 'bg-pink-100 text-pink-800',
      minimalist: 'bg-gray-100 text-gray-800',
      'pop art': 'bg-red-100 text-red-800',
      'digital art': 'bg-cyan-100 text-cyan-800',
      'oil painting': 'bg-amber-100 text-amber-800'
    }
    return colors[style.toLowerCase()] || 'bg-gray-100 text-gray-800'
  }

  const selectedPalette = COLOR_PALETTES.find(p => p.name.toLowerCase() === colorPalette.toLowerCase())

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-purple-600 to-pink-600 bg-clip-text text-transparent">
          AI Art Generation
        </h1>
        <p className="text-lg text-muted-foreground">
          Create stunning visual art with AI-powered generation across multiple styles and techniques
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Art Settings */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Palette className="w-5 h-5" />
                Art Generation
              </CardTitle>
              <CardDescription>
                Describe your vision and configure artistic parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="prompt">Art Prompt *</Label>
                <Textarea
                  id="prompt"
                  placeholder="e.g., A serene mountain landscape at sunset with vibrant colors"
                  value={prompt}
                  onChange={(e) => setPrompt(e.target.value)}
                  rows={4}
                  disabled={isGenerating}
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="style">Art Style *</Label>
                  <Select value={style} onValueChange={setStyle} disabled={isGenerating}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select style" />
                    </SelectTrigger>
                    <SelectContent>
                      {ART_STYLES.map((s) => (
                        <SelectItem key={s} value={s}>
                          {s}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="mood">Mood</Label>
                  <Select value={mood} onValueChange={setMood} disabled={isGenerating}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select mood" />
                    </SelectTrigger>
                    <SelectContent>
                      {ART_MOODS.map((m) => (
                        <SelectItem key={m} value={m}>
                          {m}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="colorPalette">Color Palette</Label>
                <Select value={colorPalette} onValueChange={setColorPalette} disabled={isGenerating}>
                  <SelectTrigger>
                    <SelectValue placeholder="Select palette" />
                  </SelectTrigger>
                  <SelectContent>
                    {COLOR_PALETTES.map((palette) => (
                      <SelectItem key={palette.name} value={palette.name}>
                        <div className="flex items-center gap-2">
                          <div className="flex gap-1">
                            {palette.colors.map((color, i) => (
                              <div
                                key={i}
                                className="w-3 h-3 rounded-full"
                                style={{ backgroundColor: color }}
                              />
                            ))}
                          </div>
                          {palette.name}
                        </div>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="dimensions">Dimensions</Label>
                <Select value={dimensions} onValueChange={setDimensions} disabled={isGenerating}>
                  <SelectTrigger>
                    <SelectValue placeholder="1024x1024" />
                  </SelectTrigger>
                  <SelectContent>
                    {DIMENSIONS.map((dim) => (
                      <SelectItem key={dim} value={dim}>
                        {dim}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-3">
                <Label>Quality: {quality[0]}%</Label>
                <Slider
                  value={quality}
                  onValueChange={setQuality}
                  min={25}
                  max={100}
                  step={5}
                  disabled={isGenerating}
                  className="w-full"
                />
                <div className="flex justify-between text-xs text-muted-foreground">
                  <span>Draft</span>
                  <span>Standard</span>
                  <span>High Quality</span>
                </div>
              </div>

              <div className="space-y-3">
                <Label>Creativity: {creativity[0]}%</Label>
                <Slider
                  value={creativity}
                  onValueChange={setCreativity}
                  min={10}
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

              {selectedPalette && (
                <div className="space-y-2">
                  <Label>Selected Color Palette</Label>
                  <div className="flex items-center gap-2">
                    {selectedPalette.colors.map((color, i) => (
                      <div
                        key={i}
                        className="w-8 h-8 rounded-full border-2 border-gray-200"
                        style={{ backgroundColor: color }}
                        title={color}
                      />
                    ))}
                  </div>
                </div>
              )}

              {error && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              {isGenerating && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Generating artwork...</span>
                    <span className="text-sm font-medium">{progress}%</span>
                  </div>
                  <Progress value={progress} />
                </div>
              )}

              <Button 
                onClick={handleGenerate} 
                disabled={isGenerating || !prompt.trim() || !style}
                className="w-full"
              >
                <Wand2 className="w-4 h-4 mr-2" />
                {isGenerating ? 'Generating...' : 'Generate Artwork'}
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Results */}
        <div className="lg:col-span-2">
          {artwork && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Image className="w-5 h-5" />
                      Generated Artwork
                    </CardTitle>
                    <CardDescription>
                      AI-generated {artwork.style} artwork with {artwork.mood} mood
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={getStyleColor(artwork.style)}>
                      {artwork.style}
                    </Badge>
                    <Badge variant="outline">
                      {artwork.dimensions}
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="artwork" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="artwork">Artwork</TabsTrigger>
                    <TabsTrigger value="composition">Composition</TabsTrigger>
                    <TabsTrigger value="style">Style Analysis</TabsTrigger>
                    <TabsTrigger value="metadata">Metadata</TabsTrigger>
                  </TabsList>

                  <TabsContent value="artwork" className="space-y-6">
                    {/* Generated Image Display */}
                    <Card>
                      <CardContent className="pt-6">
                        <div className="relative bg-gradient-to-br from-gray-100 to-gray-200 rounded-lg aspect-square flex items-center justify-center">
                          {artwork.imageData ? (
                            <img
                              src={artwork.imageData}
                              alt={artwork.prompt}
                              className="w-full h-full object-cover rounded-lg"
                            />
                          ) : (
                            <div className="text-center">
                              <Eye className="w-16 h-16 mx-auto text-gray-400 mb-4" />
                              <h3 className="text-lg font-semibold text-gray-600 mb-2">
                                Generated Artwork Preview
                              </h3>
                              <p className="text-sm text-gray-500 max-w-md">
                                {artwork.prompt}
                              </p>
                            </div>
                          )}
                        </div>
                        
                        <div className="mt-6 flex items-center justify-center gap-4">
                          <Button variant="outline" onClick={downloadArtwork}>
                            <Download className="w-4 h-4 mr-2" />
                            Download
                          </Button>
                          <Button variant="outline">
                            <Share className="w-4 h-4 mr-2" />
                            Share
                          </Button>
                        </div>
                      </CardContent>
                    </Card>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Color Palette</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex gap-2">
                            {artwork.colorPalette.map((color, index) => (
                              <div
                                key={index}
                                className="w-8 h-8 rounded-full border-2 border-gray-200"
                                style={{ backgroundColor: color }}
                                title={color}
                              />
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Technique</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <Badge variant="secondary" className="text-lg">
                            {artwork.technique}
                          </Badge>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="composition" className="space-y-4">
                    <h3 className="font-semibold">Composition Analysis</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Balance</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-blue-600">
                              {artwork.composition.balance}%
                            </div>
                            <Progress value={artwork.composition.balance} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Contrast</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-green-600">
                              {artwork.composition.contrast}%
                            </div>
                            <Progress value={artwork.composition.contrast} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Harmony</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-2xl font-bold text-purple-600">
                              {artwork.composition.harmony}%
                            </div>
                            <Progress value={artwork.composition.harmony} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Visual Elements</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex flex-wrap gap-2">
                          {artwork.composition.elements.map((element, index) => (
                            <Badge key={index} variant="outline">
                              {element}
                            </Badge>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="style" className="space-y-4">
                    <h3 className="font-semibold">Style Analysis</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Brushstrokes</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="text-sm">{artwork.styleAnalysis.brushstrokes}</p>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Texture</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="text-sm">{artwork.styleAnalysis.texture}</p>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Lighting</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="text-sm">{artwork.styleAnalysis.lighting}</p>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Perspective</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="text-sm">{artwork.styleAnalysis.perspective}</p>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="metadata" className="space-y-4">
                    <h3 className="font-semibold">Technical Metadata</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">AI Model</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <Badge variant="secondary">{artwork.metadata.aiModel}</Badge>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Processing Time</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-lg font-medium">{artwork.metadata.processingTime}ms</span>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Iterations</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-lg font-medium">{artwork.metadata.iterations}</span>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Confidence</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center gap-2">
                            <span className="text-lg font-medium">{artwork.metadata.confidence}%</span>
                            <Progress value={artwork.metadata.confidence} className="flex-1" />
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          )}

          {!artwork && (
            <Card>
              <CardContent className="py-12 text-center">
                <Sparkles className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Artwork Generated</h3>
                <p className="text-muted-foreground">
                  Enter an art prompt and select a style to generate stunning AI artwork.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
