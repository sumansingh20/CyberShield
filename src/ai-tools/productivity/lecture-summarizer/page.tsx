'use client'

import { useState } from 'react'
import { Button } from '@/src/ui/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Input } from '@/src/ui/components/ui/input'
import { Label } from '@/src/ui/components/ui/label'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Badge } from '@/src/ui/components/ui/badge'
import { Progress } from '@/src/ui/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'

interface LectureSummaryRequest {
  content: string
  content_type: 'text' | 'audio_url' | 'video_url'
  summary_length: 'brief' | 'moderate' | 'detailed'
  focus_areas: string[]
  include_timestamps: boolean
  language: string
}

interface LectureSummary {
  title: string
  main_summary: string
  key_points: string[]
  topics_covered: Array<{
    topic: string
    importance: number
    timestamp?: string
    summary: string
  }>
  action_items: string[]
  questions_for_review: string[]
  difficulty_level: string
  estimated_reading_time: number
  confidence_score: number
  word_count: number
  processing_time: number
}

export default function LectureSummarizer() {
  const [request, setRequest] = useState<LectureSummaryRequest>({
    content: '',
    content_type: 'text',
    summary_length: 'moderate',
    focus_areas: [],
    include_timestamps: false,
    language: 'en'
  })
  
  const [result, setResult] = useState<LectureSummary | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [focusArea, setFocusArea] = useState('')

  const handleSummarize = async () => {
    if (!request.content.trim()) {
      setError('Please provide lecture content to summarize')
      return
    }

    setLoading(true)
    setError('')
    
    try {
      const response = await fetch('/api/tools/lecture-summarizer', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      })

      if (!response.ok) {
        throw new Error('Failed to generate lecture summary')
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const addFocusArea = () => {
    if (focusArea.trim() && !request.focus_areas.includes(focusArea.trim())) {
      setRequest({
        ...request,
        focus_areas: [...request.focus_areas, focusArea.trim()]
      })
      setFocusArea('')
    }
  }

  const removeFocusArea = (area: string) => {
    setRequest({
      ...request,
      focus_areas: request.focus_areas.filter(a => a !== area)
    })
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty.toLowerCase()) {
      case 'beginner': return 'bg-green-100 text-green-800'
      case 'intermediate': return 'bg-yellow-100 text-yellow-800'
      case 'advanced': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-2 mb-2">
          📚 AI Lecture Summarizer
        </h1>
        <p className="text-gray-600">
          Transform lengthy lecture content into concise, actionable summaries with AI
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              📝 Input Configuration
            </CardTitle>
            <CardDescription>
              Provide lecture content and customization options
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <Label htmlFor="content-type">Content Type</Label>
              <select
                id="content-type"
                title="Select content type"
                className="w-full p-2 border rounded-md"
                value={request.content_type}
                onChange={(e) => setRequest({...request, content_type: e.target.value as any})}
              >
                <option value="text">Text Content</option>
                <option value="audio_url">Audio URL</option>
                <option value="video_url">Video URL</option>
              </select>
            </div>

            <div>
              <Label htmlFor="content">
                {request.content_type === 'text' ? 'Lecture Content' : 'Media URL'}
              </Label>
              {request.content_type === 'text' ? (
                <Textarea
                  id="content"
                  value={request.content}
                  onChange={(e) => setRequest({...request, content: e.target.value})}
                  placeholder="Paste your lecture transcript, notes, or content here..."
                  rows={8}
                />
              ) : (
                <Input
                  id="content"
                  value={request.content}
                  onChange={(e) => setRequest({...request, content: e.target.value})}
                  placeholder="Enter URL to audio or video file..."
                />
              )}
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label htmlFor="summary-length">Summary Length</Label>
                <select
                  id="summary-length"
                  title="Select summary length"
                  className="w-full p-2 border rounded-md"
                  value={request.summary_length}
                  onChange={(e) => setRequest({...request, summary_length: e.target.value as any})}
                >
                  <option value="brief">Brief (1-2 paragraphs)</option>
                  <option value="moderate">Moderate (3-5 paragraphs)</option>
                  <option value="detailed">Detailed (6+ paragraphs)</option>
                </select>
              </div>
              <div>
                <Label htmlFor="language">Language</Label>
                <select
                  id="language"
                  title="Select language"
                  className="w-full p-2 border rounded-md"
                  value={request.language}
                  onChange={(e) => setRequest({...request, language: e.target.value})}
                >
                  <option value="en">English</option>
                  <option value="es">Spanish</option>
                  <option value="fr">French</option>
                  <option value="de">German</option>
                  <option value="zh">Chinese</option>
                </select>
              </div>
            </div>

            <div>
              <Label>Focus Areas (Optional)</Label>
              <div className="flex gap-2 mt-1">
                <Input
                  value={focusArea}
                  onChange={(e) => setFocusArea(e.target.value)}
                  placeholder="e.g., key concepts, formulas, dates..."
                  onKeyPress={(e) => e.key === 'Enter' && addFocusArea()}
                />
                <Button type="button" onClick={addFocusArea}>Add</Button>
              </div>
              {request.focus_areas.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {request.focus_areas.map((area, index) => (
                    <Badge key={index} className="cursor-pointer" onClick={() => removeFocusArea(area)}>
                      {area} ×
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="timestamps"
                checked={request.include_timestamps}
                onChange={(e) => setRequest({...request, include_timestamps: e.target.checked})}
              />
              <Label htmlFor="timestamps">Include timestamps (for video/audio)</Label>
            </div>

            {error && (
              <Alert>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button 
              onClick={handleSummarize} 
              disabled={loading}
              className="w-full"
            >
              {loading ? 'Generating Summary...' : 'Generate Lecture Summary'}
            </Button>
          </CardContent>
        </Card>

        {result && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                🎯 Lecture Summary
              </CardTitle>
              <CardDescription>
                AI-generated comprehensive summary and analysis
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="summary" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="summary">Summary</TabsTrigger>
                  <TabsTrigger value="topics">Topics</TabsTrigger>
                  <TabsTrigger value="actions">Actions</TabsTrigger>
                  <TabsTrigger value="review">Review</TabsTrigger>
                </TabsList>

                <TabsContent value="summary" className="space-y-4">
                  <div className="space-y-4">
                    <div className="p-4 border rounded-lg">
                      <h3 className="font-semibold text-lg mb-2">{result.title}</h3>
                      <div className="flex gap-2 mb-3">
                        <Badge className={getDifficultyColor(result.difficulty_level)}>
                          {result.difficulty_level}
                        </Badge>
                        <Badge>
                          {result.estimated_reading_time} min read
                        </Badge>
                        <Badge>
                          {result.word_count} words
                        </Badge>
                      </div>
                      <p className="text-gray-700 leading-relaxed">{result.main_summary}</p>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-3">Key Points</h4>
                      <div className="space-y-2">
                        {result.key_points.map((point, index) => (
                          <div key={index} className="flex items-start gap-2 p-2 border rounded">
                            <span className="text-blue-500 font-bold">{index + 1}.</span>
                            <span>{point}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="topics" className="space-y-4">
                  <div className="space-y-3">
                    <h3 className="font-semibold">Topics Covered</h3>
                    {result.topics_covered.map((topic, index) => (
                      <div key={index} className="p-3 border rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium">{topic.topic}</h4>
                          <div className="flex items-center gap-2">
                            {topic.timestamp && (
                              <Badge>⏱️ {topic.timestamp}</Badge>
                            )}
                            <div className="flex items-center gap-1">
                              <span className="text-sm">Importance:</span>
                              <Progress value={topic.importance * 10} className="w-16" />
                            </div>
                          </div>
                        </div>
                        <p className="text-sm text-gray-600">{topic.summary}</p>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="actions" className="space-y-4">
                  <div className="space-y-3">
                    <h3 className="font-semibold">Action Items</h3>
                    {result.action_items.map((item, index) => (
                      <div key={index} className="flex items-center gap-2 p-2 border rounded">
                        <input type="checkbox" className="rounded" />
                        <span>{item}</span>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="review" className="space-y-4">
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-semibold mb-3">Questions for Review</h3>
                      <div className="space-y-2">
                        {result.questions_for_review.map((question, index) => (
                          <div key={index} className="p-3 border rounded-lg">
                            <p className="font-medium">Q{index + 1}: {question}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                    
                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-3 border rounded text-center">
                        <p className="text-sm text-gray-600">Confidence Score</p>
                        <p className="font-semibold text-lg">{result.confidence_score}%</p>
                      </div>
                      <div className="p-3 border rounded text-center">
                        <p className="text-sm text-gray-600">Processing Time</p>
                        <p className="font-semibold text-lg">{result.processing_time}ms</p>
                      </div>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        )}
      </div>

      <div className="mt-8">
        <Alert>
          <AlertDescription>
            💡 <strong>Tip:</strong> For best results, provide clear, well-structured content. 
            The AI works better with organized lecture materials and proper formatting.
          </AlertDescription>
        </Alert>
      </div>
    </div>
  )
}
