'use client'

import { useState, useRef, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Label } from '@/src/ui/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select'
import { Badge } from '@/src/ui/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Progress } from '@/src/ui/components/ui/progress'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Input } from '@/src/ui/components/ui/input'
import { Mic, MicOff, Play, Pause, Square, Upload, Download, Users, CheckCircle, Clock, FileText } from 'lucide-react'

interface TranscriptionSession {
  id: string
  title: string
  duration: number
  participantCount: number
  transcript: Array<{
    id: string
    timestamp: number
    speaker: string
    content: string
    confidence: number
  }>
  speakers: Array<{
    id: string
    name: string
    totalSpeakTime: number
    segments: number
  }>
  actionItems: Array<{
    id: string
    item: string
    assignee?: string
    priority: 'high' | 'medium' | 'low'
    deadline?: string
    mentioned_at: number
  }>
  keyTopics: Array<{
    topic: string
    mentions: number
    relevance: number
    timestamps: number[]
  }>
  summary: {
    overview: string
    keyDecisions: string[]
    nextSteps: string[]
    attendees: string[]
  }
  sentiment: {
    overall: 'positive' | 'neutral' | 'negative'
    score: number
    bySegment: Array<{
      timestamp: number
      sentiment: string
      score: number
    }>
  }
  metadata: {
    language: string
    quality: number
    processingTime: number
    createdAt: string
  }
}

const MEETING_TYPES = [
  'General Meeting',
  'Standup/Daily',
  'Project Review',
  'Client Call',
  'Team Sync',
  'Planning Session',
  'Brainstorming',
  'Performance Review',
  'Interview',
  'Presentation'
]

const AUDIO_QUALITY = [
  'Auto',
  'High Quality (Low Noise)',
  'Standard Quality',
  'Low Quality (High Noise)',
  'Phone Call Quality'
]

export default function MeetingTranscriptionPage() {
  const [isRecording, setIsRecording] = useState(false)
  const [isPaused, setIsPaused] = useState(false)
  const [recordingTime, setRecordingTime] = useState(0)
  const [meetingTitle, setMeetingTitle] = useState('')
  const [meetingType, setMeetingType] = useState('')
  const [audioQuality, setAudioQuality] = useState('')
  const [isTranscribing, setIsTranscribing] = useState(false)
  const [progress, setProgress] = useState(0)
  const [session, setSession] = useState<TranscriptionSession | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [liveTranscript, setLiveTranscript] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)
  const intervalRef = useRef<NodeJS.Timeout | null>(null)

  useEffect(() => {
    if (isRecording && !isPaused) {
      intervalRef.current = setInterval(() => {
        setRecordingTime(prev => prev + 1)
      }, 1000)
    } else {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
        intervalRef.current = null
      }
    }

    return () => {
      if (intervalRef.current) {
        clearInterval(intervalRef.current)
      }
    }
  }, [isRecording, isPaused])

  const formatTime = (seconds: number): string => {
    const hours = Math.floor(seconds / 3600)
    const minutes = Math.floor((seconds % 3600) / 60)
    const secs = seconds % 60
    return `${hours.toString().padStart(2, '0')}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`
  }

  const handleStartRecording = async () => {
    if (!meetingTitle.trim()) {
      setError('Please enter a meeting title')
      return
    }

    setError(null)
    setIsRecording(true)
    setIsPaused(false)
    setRecordingTime(0)
    setLiveTranscript('')
    
    // Simulate live transcription
    const transcriptInterval = setInterval(() => {
      const samplePhrases = [
        'Welcome everyone to today\'s meeting.',
        'Let\'s start by reviewing the agenda.',
        'The quarterly results show positive growth.',
        'We need to address the client feedback.',
        'Action item: Follow up with the development team.',
        'The deadline for this project is next Friday.',
        'Any questions or concerns about this?',
        'Let\'s move on to the next topic.',
        'Thank you for bringing this up.',
        'We should schedule a follow-up meeting.'
      ]
      
      if (Math.random() > 0.7) { // 30% chance to add new text
        const phrase = samplePhrases[Math.floor(Math.random() * samplePhrases.length)]
        setLiveTranscript(prev => prev + (prev ? ' ' : '') + phrase)
      }
    }, 3000)

    // Store interval reference for cleanup
    ;(window as any).transcriptInterval = transcriptInterval
  }

  const handlePauseRecording = () => {
    setIsPaused(!isPaused)
  }

  const handleStopRecording = async () => {
    setIsRecording(false)
    setIsPaused(false)
    
    // Clear live transcription interval
    if ((window as any).transcriptInterval) {
      clearInterval((window as any).transcriptInterval)
    }

    if (recordingTime < 5) {
      setError('Recording too short. Please record for at least 5 seconds.')
      return
    }

    await processTranscription('live_recording')
  }

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      // Check file type and size
      const allowedTypes = ['audio/mp3', 'audio/wav', 'audio/m4a', 'audio/ogg', 'video/mp4']
      if (!allowedTypes.includes(file.type) && !file.name.match(/\.(mp3|wav|m4a|ogg|mp4)$/i)) {
        setError('Please select a valid audio/video file (MP3, WAV, M4A, OGG, MP4)')
        return
      }
      
      if (file.size > 100 * 1024 * 1024) { // 100MB limit
        setError('File size must be less than 100MB')
        return
      }
      
      setSelectedFile(file)
      setError(null)
    }
  }

  const handleFileUpload = async () => {
    if (!selectedFile) {
      setError('Please select an audio file to transcribe')
      return
    }

    if (!meetingTitle.trim()) {
      setError('Please enter a meeting title')
      return
    }

    await processTranscription('file_upload')
  }

  const processTranscription = async (source: 'live_recording' | 'file_upload') => {
    setIsTranscribing(true)
    setError(null)
    setProgress(0)

    // Simulate transcription progress
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval)
          return 90
        }
        return prev + 10
      })
    }, 800)

    try {
      const requestData = {
        type: 'transcribe',
        meetingTitle: meetingTitle.trim(),
        meetingType: meetingType || 'General Meeting',
        audioQuality: audioQuality || 'Auto',
        source,
        duration: source === 'live_recording' ? recordingTime : 0,
        fileName: source === 'file_upload' ? selectedFile?.name : undefined,
        fileSize: source === 'file_upload' ? selectedFile?.size : undefined,
        liveTranscript: source === 'live_recording' ? liveTranscript : undefined
      }

      const response = await fetch('/api/tools/meeting-transcription-ai', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Transcription failed')
      }

      setSession(data)
      setProgress(100)
      
      // Reset form
      setMeetingTitle('')
      setSelectedFile(null)
      setLiveTranscript('')
      setRecordingTime(0)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Transcription failed')
    } finally {
      clearInterval(progressInterval)
      setIsTranscribing(false)
      setTimeout(() => setProgress(0), 1000)
    }
  }

  const downloadTranscript = () => {
    if (!session) return

    const transcript = `Meeting Transcription Report
Generated: ${new Date(session.metadata.createdAt).toLocaleString()}

MEETING INFORMATION:
- Title: ${session.title}
- Duration: ${formatTime(session.duration)}
- Participants: ${session.participantCount}
- Language: ${session.metadata.language}
- Quality Score: ${session.metadata.quality}%

ATTENDEES:
${session.summary.attendees.map(attendee => `• ${attendee}`).join('\n')}

FULL TRANSCRIPT:
${session.transcript.map(segment => 
  `[${formatTime(Math.floor(segment.timestamp / 1000))}] ${segment.speaker}: ${segment.content}`
).join('\n\n')}

SPEAKER ANALYTICS:
${session.speakers.map(speaker => 
  `• ${speaker.name}: ${formatTime(speaker.totalSpeakTime)} (${speaker.segments} segments)`
).join('\n')}

KEY TOPICS:
${session.keyTopics.map(topic => 
  `• ${topic.topic} (${topic.mentions} mentions, ${topic.relevance}% relevance)`
).join('\n')}

ACTION ITEMS:
${session.actionItems.map(item => 
  `• [${item.priority.toUpperCase()}] ${item.item}${item.assignee ? ` (Assigned: ${item.assignee})` : ''}${item.deadline ? ` (Due: ${item.deadline})` : ''} - Mentioned at ${formatTime(Math.floor(item.mentioned_at / 1000))}`
).join('\n')}

MEETING SUMMARY:
${session.summary.overview}

KEY DECISIONS:
${session.summary.keyDecisions.map(decision => `• ${decision}`).join('\n')}

NEXT STEPS:
${session.summary.nextSteps.map(step => `• ${step}`).join('\n')}

SENTIMENT ANALYSIS:
- Overall Sentiment: ${session.sentiment.overall} (${session.sentiment.score}%)
- Sentiment varied throughout the meeting based on topics discussed`

    const blob = new Blob([transcript], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `transcript_${session.title.replace(/[^a-z0-9]/gi, '_').toLowerCase()}_${Date.now()}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const getPriorityColor = (priority: string): string => {
    const colors = {
      high: 'bg-red-100 text-red-800',
      medium: 'bg-yellow-100 text-yellow-800',
      low: 'bg-green-100 text-green-800'
    }
    return colors[priority as keyof typeof colors] || 'bg-gray-100 text-gray-800'
  }

  const getSentimentColor = (sentiment: string): string => {
    const colors = {
      positive: 'bg-green-100 text-green-800',
      negative: 'bg-red-100 text-red-800',
      neutral: 'bg-gray-100 text-gray-800'
    }
    return colors[sentiment.toLowerCase() as keyof typeof colors] || 'bg-gray-100 text-gray-800'
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-purple-600 to-blue-600 bg-clip-text text-transparent">
          Meeting Transcription AI
        </h1>
        <p className="text-lg text-muted-foreground">
          Real-time transcription with speaker identification, action item extraction, and intelligent summaries
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Recording & Upload Controls */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Mic className="w-5 h-5" />
                Meeting Transcription
              </CardTitle>
              <CardDescription>
                Record live or upload audio/video files
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="meetingTitle">Meeting Title *</Label>
                  <Input
                    id="meetingTitle"
                    value={meetingTitle}
                    onChange={(e) => setMeetingTitle(e.target.value)}
                    placeholder="Enter meeting title..."
                    disabled={isTranscribing || isRecording}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="meetingType">Meeting Type</Label>
                  <Select value={meetingType} onValueChange={setMeetingType} disabled={isTranscribing || isRecording}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select meeting type" />
                    </SelectTrigger>
                    <SelectContent>
                      {MEETING_TYPES.map((type) => (
                        <SelectItem key={type} value={type}>
                          {type}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="audioQuality">Audio Quality</Label>
                  <Select value={audioQuality} onValueChange={setAudioQuality} disabled={isTranscribing || isRecording}>
                    <SelectTrigger>
                      <SelectValue placeholder="Auto detect" />
                    </SelectTrigger>
                    <SelectContent>
                      {AUDIO_QUALITY.map((quality) => (
                        <SelectItem key={quality} value={quality}>
                          {quality}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* Live Recording Section */}
              <div className="space-y-4 border-t pt-4">
                <h3 className="font-semibold flex items-center gap-2">
                  <Mic className="w-4 h-4" />
                  Live Recording
                </h3>
                
                {isRecording && (
                  <div className="bg-red-50 p-4 rounded-lg">
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <div className="w-3 h-3 bg-red-500 rounded-full animate-pulse" />
                        <span className="font-medium text-red-700">
                          {isPaused ? 'PAUSED' : 'RECORDING'}
                        </span>
                      </div>
                      <span className="text-lg font-mono">{formatTime(recordingTime)}</span>
                    </div>
                    
                    {liveTranscript && (
                      <div className="mt-3 p-3 bg-white rounded border">
                        <Label className="text-sm text-muted-foreground">Live Transcript:</Label>
                        <p className="text-sm mt-1 max-h-20 overflow-y-auto">{liveTranscript}</p>
                      </div>
                    )}
                  </div>
                )}

                <div className="flex gap-2">
                  {!isRecording ? (
                    <Button 
                      onClick={handleStartRecording} 
                      disabled={isTranscribing || !meetingTitle.trim()}
                      className="flex-1"
                    >
                      <Mic className="w-4 h-4 mr-2" />
                      Start Recording
                    </Button>
                  ) : (
                    <>
                      <Button 
                        onClick={handlePauseRecording}
                        variant="outline"
                        className="flex-1"
                      >
                        {isPaused ? <Play className="w-4 h-4 mr-2" /> : <Pause className="w-4 h-4 mr-2" />}
                        {isPaused ? 'Resume' : 'Pause'}
                      </Button>
                      <Button 
                        onClick={handleStopRecording}
                        variant="destructive"
                        className="flex-1"
                      >
                        <Square className="w-4 h-4 mr-2" />
                        Stop
                      </Button>
                    </>
                  )}
                </div>
              </div>

              {/* File Upload Section */}
              <div className="space-y-4 border-t pt-4">
                <h3 className="font-semibold flex items-center gap-2">
                  <Upload className="w-4 h-4" />
                  File Upload
                </h3>

                <div 
                  className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center cursor-pointer hover:border-gray-400 transition-colors"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Upload className="w-8 h-8 mx-auto mb-2 text-gray-400" />
                  <p className="text-sm text-gray-600">
                    {selectedFile ? selectedFile.name : 'Click to upload audio/video file'}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">
                    MP3, WAV, M4A, OGG, MP4 (max 100MB)
                  </p>
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".mp3,.wav,.m4a,.ogg,.mp4"
                  onChange={handleFileSelect}
                  className="hidden"
                  disabled={isTranscribing || isRecording}
                  aria-label="Upload audio or video file"
                  title="Upload audio or video file for transcription"
                />

                {selectedFile && (
                  <div className="flex items-center gap-2 p-3 bg-gray-50 rounded-lg">
                    <FileText className="w-4 h-4 text-gray-500" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{selectedFile.name}</p>
                      <p className="text-xs text-gray-500">
                        {(selectedFile.size / (1024 * 1024)).toFixed(2)} MB
                      </p>
                    </div>
                  </div>
                )}

                <Button 
                  onClick={handleFileUpload} 
                  disabled={isTranscribing || isRecording || !selectedFile || !meetingTitle.trim()}
                  className="w-full"
                >
                  <Upload className="w-4 h-4 mr-2" />
                  Upload & Transcribe
                </Button>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              {isTranscribing && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Processing audio...</span>
                    <span className="text-sm font-medium">{progress}%</span>
                  </div>
                  <Progress value={progress} />
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Transcription Results */}
        <div className="lg:col-span-2">
          {session && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Users className="w-5 h-5" />
                      {session.title}
                    </CardTitle>
                    <CardDescription>
                      {formatTime(session.duration)} • {session.participantCount} participants • {session.metadata.language}
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">
                      {session.metadata.quality}% quality
                    </Badge>
                    <Button variant="outline" size="sm" onClick={downloadTranscript}>
                      <Download className="w-4 h-4 mr-2" />
                      Download
                    </Button>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="transcript" className="w-full">
                  <TabsList className="grid w-full grid-cols-5">
                    <TabsTrigger value="transcript">Transcript</TabsTrigger>
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="actions">Actions</TabsTrigger>
                    <TabsTrigger value="analytics">Analytics</TabsTrigger>
                    <TabsTrigger value="speakers">Speakers</TabsTrigger>
                  </TabsList>

                  <TabsContent value="transcript" className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold">Full Transcript</h3>
                      <Badge className={getSentimentColor(session.sentiment.overall)}>
                        {session.sentiment.overall} ({session.sentiment.score}%)
                      </Badge>
                    </div>
                    
                    <div className="max-h-96 overflow-y-auto space-y-3 border rounded-lg p-4">
                      {session.transcript.map((segment) => (
                        <div key={segment.id} className="flex gap-3 hover:bg-gray-50 rounded p-2">
                          <div className="text-xs text-muted-foreground w-16 flex-shrink-0 pt-1">
                            {formatTime(Math.floor(segment.timestamp / 1000))}
                          </div>
                          <div className="flex-1">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-medium text-sm">{segment.speaker}</span>
                              <Badge variant="outline" className="text-xs">
                                {segment.confidence}%
                              </Badge>
                            </div>
                            <p className="text-sm leading-relaxed">{segment.content}</p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="summary" className="space-y-4">
                    <h3 className="font-semibold">Meeting Summary</h3>
                    
                    <Card>
                      <CardHeader className="pb-3">
                        <CardTitle className="text-sm">Overview</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <p className="leading-relaxed">{session.summary.overview}</p>
                      </CardContent>
                    </Card>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Key Decisions</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {session.summary.keyDecisions.map((decision, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{decision}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Next Steps</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {session.summary.nextSteps.map((step, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{step}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader className="pb-3">
                        <CardTitle className="text-sm">Key Topics Discussed</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {session.keyTopics.map((topic, index) => (
                            <div key={index} className="space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="font-medium">{topic.topic}</span>
                                <div className="flex items-center gap-2">
                                  <span className="text-sm text-muted-foreground">{topic.mentions} mentions</span>
                                  <span className="text-sm text-muted-foreground">{topic.relevance}%</span>
                                </div>
                              </div>
                              <Progress value={topic.relevance} />
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="actions" className="space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <CheckCircle className="w-5 h-5" />
                      <h3 className="font-semibold">Action Items</h3>
                    </div>
                    
                    <div className="space-y-3">
                      {session.actionItems.map((item) => (
                        <Card key={item.id}>
                          <CardContent className="pt-4">
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-2">
                                  <Badge className={getPriorityColor(item.priority)}>
                                    {item.priority}
                                  </Badge>
                                  {item.assignee && (
                                    <Badge variant="outline" className="text-xs">
                                      {item.assignee}
                                    </Badge>
                                  )}
                                  {item.deadline && (
                                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                      <Clock className="w-3 h-3" />
                                      {item.deadline}
                                    </div>
                                  )}
                                  <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                    <span>@</span>
                                    {formatTime(Math.floor(item.mentioned_at / 1000))}
                                  </div>
                                </div>
                                <p className="text-sm">{item.item}</p>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="analytics" className="space-y-4">
                    <h3 className="font-semibold">Meeting Analytics</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Duration</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-2xl font-bold">{formatTime(session.duration)}</span>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Participants</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-2xl font-bold">{session.participantCount}</span>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Action Items</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-2xl font-bold">{session.actionItems.length}</span>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Sentiment Throughout Meeting</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {session.sentiment.bySegment.map((segment, index) => (
                            <div key={index} className="flex items-center justify-between">
                              <span className="text-xs text-muted-foreground">
                                {formatTime(Math.floor(segment.timestamp / 1000))}
                              </span>
                              <Badge className={getSentimentColor(segment.sentiment)}>
                                {segment.sentiment} ({segment.score}%)
                              </Badge>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="speakers" className="space-y-4">
                    <h3 className="font-semibold">Speaker Analysis</h3>
                    
                    <div className="space-y-4">
                      {session.speakers.map((speaker) => (
                        <Card key={speaker.id}>
                          <CardContent className="pt-4">
                            <div className="flex items-center justify-between mb-3">
                              <h4 className="font-medium">{speaker.name}</h4>
                              <div className="flex items-center gap-4 text-sm text-muted-foreground">
                                <span>{formatTime(speaker.totalSpeakTime)} speaking time</span>
                                <span>{speaker.segments} segments</span>
                              </div>
                            </div>
                            <div className="space-y-2">
                              <div className="flex items-center justify-between text-sm">
                                <span>Speaking time</span>
                                <span>{Math.round((speaker.totalSpeakTime / session.duration) * 100)}%</span>
                              </div>
                              <Progress value={(speaker.totalSpeakTime / session.duration) * 100} />
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

          {!session && (
            <Card>
              <CardContent className="py-12 text-center">
                <Mic className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Transcription Available</h3>
                <p className="text-muted-foreground">
                  Start recording or upload an audio file to begin transcription with AI-powered analysis.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
