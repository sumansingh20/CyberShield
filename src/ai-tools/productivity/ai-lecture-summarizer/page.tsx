'use client'

import { useState, useRef } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Label } from '@/src/ui/components/ui/label'
import { Input } from '@/src/ui/components/ui/input'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select'
import { Badge } from '@/src/ui/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Progress } from '@/src/ui/components/ui/progress'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Separator } from '@/src/ui/components/ui/separator'
import { BookOpen, FileText, Brain, Download, Upload, Play, Pause, Volume2, Clock, Target, Lightbulb, Bookmark, CheckCircle } from 'lucide-react'

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

const SUBJECT_OPTIONS = [
  'Computer Science', 'Mathematics', 'Physics', 'Chemistry', 'Biology',
  'History', 'Literature', 'Psychology', 'Economics', 'Philosophy',
  'Engineering', 'Medicine', 'Law', 'Business', 'Art', 'Other'
]

const LECTURE_TYPES = [
  'Traditional Lecture', 'Seminar', 'Workshop', 'Tutorial', 'Conference Talk',
  'Online Course', 'Webinar', 'Panel Discussion', 'Case Study', 'Laboratory'
]

export default function LectureSummarizerPage() {
  const [lectureTitle, setLectureTitle] = useState('')
  const [lectureSubject, setLectureSubject] = useState('')
  const [lectureType, setLectureType] = useState('')
  const [lecturer, setLecturer] = useState('')
  const [lectureContent, setLectureContent] = useState('')
  const [audioFile, setAudioFile] = useState<File | null>(null)
  const [isProcessing, setIsProcessing] = useState(false)
  const [summary, setSummary] = useState<LectureSummary | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [activeTab, setActiveTab] = useState('input')
  const [isPlaying, setIsPlaying] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const audioRef = useRef<HTMLAudioElement>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileUpload = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      if (file.type.startsWith('audio/') || file.type.startsWith('video/')) {
        setAudioFile(file)
        setError(null)
      } else {
        setError('Please upload an audio or video file')
        setAudioFile(null)
      }
    }
  }

  const handleAudioControl = () => {
    if (audioRef.current) {
      if (isPlaying) {
        audioRef.current.pause()
      } else {
        audioRef.current.play()
      }
      setIsPlaying(!isPlaying)
    }
  }

  const formatTime = (seconds: number): string => {
    const mins = Math.floor(seconds / 60)
    const secs = Math.floor(seconds % 60)
    return `${mins}:${secs.toString().padStart(2, '0')}`
  }

  const handleSubmit = async () => {
    if (!lectureTitle.trim() && !audioFile) {
      setError('Please provide either lecture content or upload an audio file')
      return
    }

    setIsProcessing(true)
    setError(null)

    try {
      const formData = new FormData()
      
      if (audioFile) {
        formData.append('audioFile', audioFile)
      }
      
      formData.append('title', lectureTitle)
      formData.append('subject', lectureSubject)
      formData.append('type', lectureType)
      formData.append('lecturer', lecturer)
      formData.append('content', lectureContent)

      const response = await fetch('/api/tools/lecture-summarizer', {
        method: 'POST',
        body: formData,
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Processing failed')
      }

      setSummary(data)
      setActiveTab('summary')

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Processing failed')
    } finally {
      setIsProcessing(false)
    }
  }

  const handleDownloadNotes = () => {
    if (!summary) return

    const notesContent = `
# ${summary.title}
**Subject:** ${summary.subject}
**Lecturer:** ${summary.lecturer}
**Duration:** ${summary.duration}

## Summary
${summary.mainSummary}

## Key Topics
${summary.keyTopics.map(topic => `- ${topic}`).join('\n')}

## Detailed Notes
${summary.detailedNotes.map(note => `
### ${note.section}
${note.timestamp ? `**Time:** ${note.timestamp}` : ''}
**Importance:** ${note.importance}

${note.content}

**Key Concepts:** ${note.concepts.join(', ')}
`).join('\n')}

## Key Insights
${summary.keyInsights.map(insight => `
### ${insight.title} (${insight.type})
${insight.timestamp ? `**Time:** ${insight.timestamp}` : ''}

${insight.content}
`).join('\n')}

## Study Guide

### Learning Objectives
${summary.studyGuide.learningObjectives.map(obj => `- ${obj}`).join('\n')}

### Key Terms
${summary.studyGuide.keyTerms.map(term => `**${term.term}:** ${term.definition}`).join('\n\n')}

### Practice Questions
${summary.studyGuide.practiceQuestions.map((q, i) => `
${i + 1}. **${q.type} (${q.difficulty})**
${q.question}
${q.hint ? `*Hint: ${q.hint}*` : ''}
`).join('\n')}

### Additional Resources
${summary.studyGuide.additionalResources.map(resource => `
**${resource.title}** (${resource.type})
${resource.description}
${resource.url ? `Link: ${resource.url}` : ''}
`).join('\n')}
    `.trim()

    const blob = new Blob([notesContent], { type: 'text/markdown' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${summary.title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}_notes.md`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const getImportanceColor = (importance: string): string => {
    const colors = {
      high: 'bg-red-100 text-red-800',
      medium: 'bg-yellow-100 text-yellow-800',
      low: 'bg-green-100 text-green-800'
    }
    return colors[importance as keyof typeof colors] || 'bg-gray-100 text-gray-800'
  }

  const getTypeIcon = (type: string) => {
    const icons = {
      definition: '📖',
      formula: '🧮',
      principle: '⚖️',
      example: '💡',
      question: '❓'
    }
    return icons[type as keyof typeof icons] || '📝'
  }

  const getDifficultyColor = (difficulty: string): string => {
    const colors = {
      easy: 'text-green-600',
      medium: 'text-yellow-600',
      hard: 'text-red-600'
    }
    return colors[difficulty as keyof typeof colors] || 'text-gray-600'
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
          AI Lecture Summarizer
        </h1>
        <p className="text-lg text-muted-foreground">
          Transform lectures into smart notes with AI-powered summarization and study guide generation
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Input Panel */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Upload className="w-5 h-5" />
                Lecture Input
              </CardTitle>
              <CardDescription>
                Upload audio/video or paste lecture content
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="lectureTitle">Lecture Title</Label>
                <Input
                  id="lectureTitle"
                  value={lectureTitle}
                  onChange={(e) => setLectureTitle(e.target.value)}
                  placeholder="Introduction to Machine Learning"
                />
              </div>

              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Subject</Label>
                  <Select value={lectureSubject} onValueChange={setLectureSubject}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select subject" />
                    </SelectTrigger>
                    <SelectContent>
                      {SUBJECT_OPTIONS.map(subject => (
                        <SelectItem key={subject} value={subject}>
                          {subject}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label>Type</Label>
                  <Select value={lectureType} onValueChange={setLectureType}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select type" />
                    </SelectTrigger>
                    <SelectContent>
                      {LECTURE_TYPES.map(type => (
                        <SelectItem key={type} value={type}>
                          {type}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="lecturer">Lecturer/Instructor</Label>
                <Input
                  id="lecturer"
                  value={lecturer}
                  onChange={(e) => setLecturer(e.target.value)}
                  placeholder="Dr. Smith"
                />
              </div>

              <Separator />

              <div className="space-y-4">
                <div className="space-y-2">
                  <Label>Upload Audio/Video File</Label>
                  <div className="border-2 border-dashed border-gray-300 rounded-lg p-4 text-center">
                    <input
                      ref={fileInputRef}
                      type="file"
                      accept="audio/*,video/*"
                      onChange={handleFileUpload}
                      className="hidden"
                      aria-label="Upload audio or video file"
                    />
                    <Button
                      variant="outline"
                      onClick={() => fileInputRef.current?.click()}
                      className="mb-2"
                    >
                      <Upload className="w-4 h-4 mr-2" />
                      Choose File
                    </Button>
                    {audioFile && (
                      <div className="mt-2">
                        <p className="text-sm font-medium">{audioFile.name}</p>
                        <p className="text-xs text-muted-foreground">
                          {(audioFile.size / (1024 * 1024)).toFixed(2)} MB
                        </p>
                      </div>
                    )}
                  </div>
                </div>

                {audioFile && (
                  <div className="space-y-2">
                    <audio
                      ref={audioRef}
                      src={URL.createObjectURL(audioFile)}
                      onTimeUpdate={(e) => setCurrentTime((e.target as HTMLAudioElement).currentTime)}
                      onEnded={() => setIsPlaying(false)}
                      className="hidden"
                    />
                    <div className="flex items-center gap-2">
                      <Button size="sm" variant="outline" onClick={handleAudioControl}>
                        {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                      </Button>
                      <span className="text-sm font-mono">
                        {formatTime(currentTime)}
                      </span>
                      <Volume2 className="w-4 h-4 text-muted-foreground" />
                    </div>
                  </div>
                )}

                <div className="space-y-2">
                  <Label htmlFor="lectureContent">Or Paste Lecture Content</Label>
                  <Textarea
                    id="lectureContent"
                    value={lectureContent}
                    onChange={(e) => setLectureContent(e.target.value)}
                    placeholder="Paste lecture transcript, notes, or content here..."
                    rows={8}
                  />
                </div>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <Button 
                onClick={handleSubmit} 
                disabled={isProcessing || (!lectureContent.trim() && !audioFile)}
                className="w-full"
              >
                <Brain className="w-4 h-4 mr-2" />
                {isProcessing ? 'Processing...' : 'Generate Smart Notes'}
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Results Panel */}
        <div className="lg:col-span-2">
          {summary ? (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <FileText className="w-5 h-5" />
                      {summary.title}
                    </CardTitle>
                    <CardDescription>
                      AI-generated lecture summary and study materials
                    </CardDescription>
                  </div>
                  <Button onClick={handleDownloadNotes} variant="outline">
                    <Download className="w-4 h-4 mr-2" />
                    Download Notes
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                  <TabsList className="grid w-full grid-cols-5">
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="notes">Notes</TabsTrigger>
                    <TabsTrigger value="insights">Insights</TabsTrigger>
                    <TabsTrigger value="study">Study Guide</TabsTrigger>
                    <TabsTrigger value="analysis">Analysis</TabsTrigger>
                  </TabsList>

                  <TabsContent value="summary" className="space-y-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="text-center">
                        <div className="text-2xl font-bold text-blue-600">{summary.duration}</div>
                        <div className="text-sm text-muted-foreground">Duration</div>
                      </div>
                      <div className="text-center">
                        <div className="text-2xl font-bold text-green-600">{summary.keyTopics.length}</div>
                        <div className="text-sm text-muted-foreground">Key Topics</div>
                      </div>
                      <div className="text-center">
                        <div className="text-2xl font-bold text-purple-600">{summary.metadata.wordCount}</div>
                        <div className="text-sm text-muted-foreground">Words</div>
                      </div>
                      <div className="text-center">
                        <div className="text-2xl font-bold text-orange-600 capitalize">{summary.metadata.complexity}</div>
                        <div className="text-sm text-muted-foreground">Level</div>
                      </div>
                    </div>

                    <Separator />

                    <div>
                      <h3 className="font-semibold mb-2">Lecture Overview</h3>
                      <p className="text-muted-foreground leading-relaxed">{summary.mainSummary}</p>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-3">Key Topics Covered</h3>
                      <div className="flex flex-wrap gap-2">
                        {summary.keyTopics.map((topic, index) => (
                          <Badge key={index} variant="secondary">
                            {topic}
                          </Badge>
                        ))}
                      </div>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Instructor</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="font-medium">{summary.lecturer}</p>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Subject Area</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="font-medium">{summary.subject}</p>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Processing Time</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <p className="font-medium">{summary.metadata.processingTime}s</p>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="notes" className="space-y-4">
                    <h3 className="font-semibold">Detailed Lecture Notes</h3>
                    
                    <div className="space-y-4">
                      {summary.detailedNotes.map((note, index) => (
                        <Card key={index}>
                          <CardContent className="pt-4">
                            <div className="flex items-start justify-between mb-2">
                              <h4 className="font-medium flex-1">{note.section}</h4>
                              <div className="flex items-center gap-2">
                                {note.timestamp && (
                                  <Badge variant="outline" className="text-xs">
                                    <Clock className="w-3 h-3 mr-1" />
                                    {note.timestamp}
                                  </Badge>
                                )}
                                <Badge className={getImportanceColor(note.importance)}>
                                  {note.importance}
                                </Badge>
                              </div>
                            </div>
                            
                            <p className="text-muted-foreground mb-3 leading-relaxed">
                              {note.content}
                            </p>
                            
                            {note.concepts.length > 0 && (
                              <div>
                                <div className="text-sm font-medium mb-1">Key Concepts:</div>
                                <div className="flex flex-wrap gap-1">
                                  {note.concepts.map((concept, i) => (
                                    <Badge key={i} variant="outline" className="text-xs">
                                      {concept}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="insights" className="space-y-4">
                    <h3 className="font-semibold">Key Insights & Highlights</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {summary.keyInsights.map((insight, index) => (
                        <Card key={index}>
                          <CardContent className="pt-4">
                            <div className="flex items-center gap-2 mb-2">
                              <span className="text-lg">{getTypeIcon(insight.type)}</span>
                              <div className="flex-1">
                                <h4 className="font-medium">{insight.title}</h4>
                                <div className="flex items-center gap-2 mt-1">
                                  <Badge variant="outline" className="text-xs">
                                    {insight.type}
                                  </Badge>
                                  {insight.timestamp && (
                                    <Badge variant="outline" className="text-xs">
                                      {insight.timestamp}
                                    </Badge>
                                  )}
                                </div>
                              </div>
                            </div>
                            <p className="text-sm text-muted-foreground leading-relaxed">
                              {insight.content}
                            </p>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="study" className="space-y-6">
                    <div>
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Target className="w-4 h-4" />
                        Learning Objectives
                      </h3>
                      <div className="space-y-2">
                        {summary.studyGuide.learningObjectives.map((objective, index) => (
                          <div key={index} className="flex items-start gap-2">
                            <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                            <span className="text-sm">{objective}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <Separator />

                    <div>
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <BookOpen className="w-4 h-4" />
                        Key Terms & Definitions
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {summary.studyGuide.keyTerms.map((term, index) => (
                          <Card key={index}>
                            <CardContent className="pt-3">
                              <h4 className="font-medium text-blue-600 mb-1">{term.term}</h4>
                              <p className="text-sm text-muted-foreground">{term.definition}</p>
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </div>

                    <Separator />

                    <div>
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Lightbulb className="w-4 h-4" />
                        Practice Questions
                      </h3>
                      <div className="space-y-3">
                        {summary.studyGuide.practiceQuestions.map((question, index) => (
                          <Card key={index}>
                            <CardContent className="pt-4">
                              <div className="flex items-center justify-between mb-2">
                                <Badge variant="outline" className="text-xs">
                                  {question.type.replace('_', ' ')}
                                </Badge>
                                <Badge className={`text-xs ${getDifficultyColor(question.difficulty)}`}>
                                  {question.difficulty}
                                </Badge>
                              </div>
                              <p className="font-medium mb-2">{question.question}</p>
                              {question.hint && (
                                <p className="text-sm text-muted-foreground italic">
                                  💡 Hint: {question.hint}
                                </p>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </div>

                    <Separator />

                    <div>
                      <h3 className="font-semibold mb-3 flex items-center gap-2">
                        <Bookmark className="w-4 h-4" />
                        Additional Resources
                      </h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {summary.studyGuide.additionalResources.map((resource, index) => (
                          <Card key={index}>
                            <CardContent className="pt-3">
                              <div className="flex items-center justify-between mb-1">
                                <h4 className="font-medium">{resource.title}</h4>
                                <Badge variant="outline" className="text-xs">
                                  {resource.type}
                                </Badge>
                              </div>
                              <p className="text-sm text-muted-foreground mb-2">{resource.description}</p>
                              {resource.url && (
                                <Button size="sm" variant="outline">
                                  Open Resource
                                </Button>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="analysis" className="space-y-4">
                    <div>
                      <h3 className="font-semibold mb-3">Comprehension Analysis</h3>
                      
                      <Card className="mb-4">
                        <CardContent className="pt-4">
                          <div className="text-center mb-4">
                            <div className="text-3xl font-bold text-blue-600">
                              {summary.comprehensionScore.overall}%
                            </div>
                            <div className="text-sm text-muted-foreground">Overall Comprehension Score</div>
                            <Progress value={summary.comprehensionScore.overall} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>

                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                        {Object.entries(summary.comprehensionScore.categories).map(([category, score]) => (
                          <Card key={category}>
                            <CardContent className="pt-4 text-center">
                              <div className="text-xl font-bold text-green-600">{score}%</div>
                              <div className="text-sm font-medium capitalize mb-2">{category}</div>
                              <Progress value={score} className="h-2" />
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    </div>

                    <Separator />

                    <div>
                      <h3 className="font-semibold mb-3">Content Metadata</h3>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                        <div>
                          <div className="text-sm text-muted-foreground">Word Count</div>
                          <div className="font-semibold">{summary.metadata.wordCount.toLocaleString()}</div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground">Complexity Level</div>
                          <div className="font-semibold capitalize">{summary.metadata.complexity}</div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground">Processing Time</div>
                          <div className="font-semibold">{summary.metadata.processingTime} seconds</div>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-3">Content Tags</h3>
                      <div className="flex flex-wrap gap-2">
                        {summary.metadata.tags.map((tag, index) => (
                          <Badge key={index} variant="secondary">
                            {tag}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          ) : (
            <Card>
              <CardContent className="py-12 text-center">
                <BookOpen className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">Ready to Process Your Lecture</h3>
                <p className="text-muted-foreground">
                  Upload an audio/video file or paste lecture content to generate AI-powered smart notes, 
                  summaries, and study guides.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
