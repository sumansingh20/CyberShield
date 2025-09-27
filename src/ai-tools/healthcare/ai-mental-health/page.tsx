'use client'

import { useState, useEffect } from 'react'
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
import { Slider } from '@/src/ui/components/ui/slider'
import { Heart, Brain, Smile, Frown, Meh, TrendingUp, Calendar, Clock, MessageCircle, Activity, Shield, Sparkles } from 'lucide-react'

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

const MOOD_OPTIONS = [
  { value: 'very_sad', label: 'Very Sad', icon: '😢', color: 'text-red-600' },
  { value: 'sad', label: 'Sad', icon: '😔', color: 'text-orange-600' },
  { value: 'neutral', label: 'Neutral', icon: '😐', color: 'text-gray-600' },
  { value: 'happy', label: 'Happy', icon: '😊', color: 'text-green-600' },
  { value: 'very_happy', label: 'Very Happy', icon: '😄', color: 'text-blue-600' }
]

const MOOD_FACTORS = [
  'Work/School', 'Relationships', 'Health', 'Family', 'Money', 'Weather', 
  'Sleep', 'Exercise', 'Social Media', 'News', 'Food', 'Hobbies'
]

export default function MentalHealthCompanionPage() {
  const [currentMood, setCurrentMood] = useState<'very_sad' | 'sad' | 'neutral' | 'happy' | 'very_happy'>('neutral')
  const [moodIntensity, setMoodIntensity] = useState([5])
  const [selectedFactors, setSelectedFactors] = useState<string[]>([])
  const [moodNotes, setMoodNotes] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysis, setAnalysis] = useState<MentalHealthAnalysis | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [moodHistory, setMoodHistory] = useState<MoodEntry[]>([])
  const [chatMessage, setChatMessage] = useState('')
  const [chatHistory, setChatHistory] = useState<Array<{ role: 'user' | 'assistant'; content: string; timestamp: string }>>([])

  useEffect(() => {
    // Load sample mood history
    loadSampleMoodHistory()
  }, [])

  const loadSampleMoodHistory = () => {
    const sampleHistory: MoodEntry[] = [
      {
        id: 'mood_1',
        mood: 'happy',
        intensity: 7,
        factors: ['Exercise', 'Weather'],
        notes: 'Had a great workout and the weather was beautiful today',
        timestamp: new Date(Date.now() - 86400000).toISOString()
      },
      {
        id: 'mood_2',
        mood: 'neutral',
        intensity: 5,
        factors: ['Work/School'],
        notes: 'Regular day at work, nothing special',
        timestamp: new Date(Date.now() - 172800000).toISOString()
      },
      {
        id: 'mood_3',
        mood: 'sad',
        intensity: 3,
        factors: ['Relationships', 'Money'],
        notes: 'Had an argument with a friend and worried about expenses',
        timestamp: new Date(Date.now() - 259200000).toISOString()
      }
    ]
    setMoodHistory(sampleHistory)
  }

  const handleFactorToggle = (factor: string) => {
    setSelectedFactors(prev => 
      prev.includes(factor) 
        ? prev.filter(f => f !== factor)
        : [...prev, factor]
    )
  }

  const handleMoodSubmit = async () => {
    const newMoodEntry: MoodEntry = {
      id: `mood_${Date.now()}`,
      mood: currentMood,
      intensity: moodIntensity[0],
      factors: selectedFactors,
      notes: moodNotes,
      timestamp: new Date().toISOString()
    }

    setMoodHistory(prev => [newMoodEntry, ...prev])
    
    // Reset form
    setCurrentMood('neutral')
    setMoodIntensity([5])
    setSelectedFactors([])
    setMoodNotes('')

    // Analyze mood patterns
    await analyzeMentalHealth([newMoodEntry, ...moodHistory])
  }

  const analyzeMentalHealth = async (moodData: MoodEntry[]) => {
    setIsAnalyzing(true)
    setError(null)

    try {
      const response = await fetch('/api/tools/mental-health-ai', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'analyze',
          moodHistory: moodData,
          currentEntry: moodData[0]
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Analysis failed')
      }

      setAnalysis(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const handleChatSubmit = async () => {
    if (!chatMessage.trim()) return

    const userMessage = {
      role: 'user' as const,
      content: chatMessage.trim(),
      timestamp: new Date().toISOString()
    }

    setChatHistory(prev => [...prev, userMessage])
    setChatMessage('')

    try {
      const response = await fetch('/api/tools/mental-health-ai', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'chat',
          message: userMessage.content,
          context: analysis ? {
            currentMood: analysis.currentMood,
            wellnessScore: analysis.wellnessScore
          } : null
        }),
      })

      const data = await response.json()

      if (response.ok) {
        const assistantMessage = {
          role: 'assistant' as const,
          content: data.response,
          timestamp: new Date().toISOString()
        }
        setChatHistory(prev => [...prev, assistantMessage])
      }
    } catch (err) {
      console.error('Chat error:', err)
    }
  }

  const getMoodIcon = (mood: string): string => {
    const moodData = MOOD_OPTIONS.find(m => m.value === mood)
    return moodData?.icon || '😐'
  }

  const getMoodColor = (mood: string): string => {
    const moodData = MOOD_OPTIONS.find(m => m.value === mood)
    return moodData?.color || 'text-gray-600'
  }

  const getPriorityColor = (priority: string): string => {
    const colors = {
      low: 'bg-green-100 text-green-800',
      medium: 'bg-yellow-100 text-yellow-800',
      high: 'bg-red-100 text-red-800'
    }
    return colors[priority as keyof typeof colors] || 'bg-gray-100 text-gray-800'
  }

  const getRiskColor = (level: string): string => {
    const colors = {
      low: 'bg-green-100 text-green-800',
      moderate: 'bg-yellow-100 text-yellow-800',
      high: 'bg-red-100 text-red-800'
    }
    return colors[level as keyof typeof colors] || 'bg-gray-100 text-gray-800'
  }

  const formatDate = (dateString: string): string => {
    return new Date(dateString).toLocaleDateString()
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-7xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-pink-600 to-purple-600 bg-clip-text text-transparent">
          AI Mental Health Companion
        </h1>
        <p className="text-lg text-muted-foreground">
          Your personal AI-powered mental wellness companion with mood tracking, insights, and support
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Mood Tracking Panel */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Heart className="w-5 h-5" />
                Mood Check-in
              </CardTitle>
              <CardDescription>
                Track your daily mood and emotions
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <div className="space-y-3">
                  <Label>How are you feeling today?</Label>
                  <div className="grid grid-cols-5 gap-2">
                    {MOOD_OPTIONS.map((mood) => (
                      <Button
                        key={mood.value}
                        variant={currentMood === mood.value ? "default" : "outline"}
                        className="h-16 flex flex-col gap-1"
                        onClick={() => setCurrentMood(mood.value as any)}
                      >
                        <span className="text-2xl">{mood.icon}</span>
                        <span className="text-xs">{mood.label}</span>
                      </Button>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <Label>Intensity Level: {moodIntensity[0]}/10</Label>
                  <Slider
                    value={moodIntensity}
                    onValueChange={setMoodIntensity}
                    min={1}
                    max={10}
                    step={1}
                    className="w-full"
                  />
                </div>

                <div className="space-y-2">
                  <Label>What's affecting your mood?</Label>
                  <div className="flex flex-wrap gap-2">
                    {MOOD_FACTORS.map((factor) => (
                      <Button
                        key={factor}
                        variant={selectedFactors.includes(factor) ? "default" : "outline"}
                        size="sm"
                        onClick={() => handleFactorToggle(factor)}
                      >
                        {factor}
                      </Button>
                    ))}
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="moodNotes">Additional Notes</Label>
                  <Textarea
                    id="moodNotes"
                    value={moodNotes}
                    onChange={(e) => setMoodNotes(e.target.value)}
                    placeholder="How was your day? Any specific thoughts or feelings..."
                    rows={3}
                  />
                </div>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              <Button 
                onClick={handleMoodSubmit} 
                disabled={isAnalyzing}
                className="w-full"
              >
                <Brain className="w-4 h-4 mr-2" />
                {isAnalyzing ? 'Analyzing...' : 'Submit & Analyze'}
              </Button>

              {/* Recent Mood History */}
              <div className="space-y-2">
                <Label className="text-sm font-medium">Recent Moods</Label>
                <div className="space-y-2 max-h-40 overflow-y-auto">
                  {moodHistory.slice(0, 5).map((entry) => (
                    <div key={entry.id} className="flex items-center justify-between p-2 bg-gray-50 rounded">
                      <div className="flex items-center gap-2">
                        <span className="text-lg">{getMoodIcon(entry.mood)}</span>
                        <div>
                          <div className="text-sm font-medium">{entry.intensity}/10</div>
                          <div className="text-xs text-muted-foreground">{formatDate(entry.timestamp)}</div>
                        </div>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </CardContent>
          </Card>

          {/* AI Chat Companion */}
          <Card className="mt-6">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <MessageCircle className="w-5 h-5" />
                AI Companion Chat
              </CardTitle>
              <CardDescription>
                Talk to your AI mental health companion
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="space-y-3 max-h-64 overflow-y-auto">
                {chatHistory.length === 0 && (
                  <div className="text-center text-muted-foreground py-4">
                    <MessageCircle className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">Start a conversation with your AI companion</p>
                  </div>
                )}
                {chatHistory.map((message, index) => (
                  <div
                    key={index}
                    className={`flex ${message.role === 'user' ? 'justify-end' : 'justify-start'}`}
                  >
                    <div
                      className={`max-w-[80%] p-3 rounded-lg text-sm ${
                        message.role === 'user'
                          ? 'bg-blue-500 text-white'
                          : 'bg-gray-100 text-gray-800'
                      }`}
                    >
                      {message.content}
                    </div>
                  </div>
                ))}
              </div>
              
              <div className="flex gap-2">
                <Input
                  value={chatMessage}
                  onChange={(e) => setChatMessage(e.target.value)}
                  placeholder="Share your thoughts..."
                  onKeyPress={(e) => e.key === 'Enter' && handleChatSubmit()}
                />
                <Button onClick={handleChatSubmit} disabled={!chatMessage.trim()}>
                  Send
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Analysis Results */}
        <div className="lg:col-span-2">
          {analysis && (
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="w-5 h-5" />
                  Mental Health Analysis
                </CardTitle>
                <CardDescription>
                  AI-powered insights and personalized recommendations
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="overview" className="w-full">
                  <TabsList className="grid w-full grid-cols-5">
                    <TabsTrigger value="overview">Overview</TabsTrigger>
                    <TabsTrigger value="trends">Trends</TabsTrigger>
                    <TabsTrigger value="insights">Insights</TabsTrigger>
                    <TabsTrigger value="recommendations">Help</TabsTrigger>
                    <TabsTrigger value="resources">Resources</TabsTrigger>
                  </TabsList>

                  <TabsContent value="overview" className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Current Mood</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center gap-3">
                            <span className="text-4xl">{getMoodIcon(analysis.currentMood.mood)}</span>
                            <div>
                              <div className="font-semibold">{analysis.currentMood.description}</div>
                              <div className="text-sm text-muted-foreground">
                                Intensity: {analysis.currentMood.intensity}/10
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Wellness Score</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-center">
                            <div className="text-3xl font-bold text-blue-600">
                              {analysis.wellnessScore.overall}%
                            </div>
                            <Progress value={analysis.wellnessScore.overall} className="mt-2" />
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Wellness Categories</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                          {Object.entries(analysis.wellnessScore.categories).map(([category, score]) => (
                            <div key={category} className="text-center">
                              <div className="text-lg font-semibold capitalize">{category}</div>
                              <div className="text-2xl font-bold text-green-600">{score}%</div>
                              <Progress value={score} className="mt-1" />
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm flex items-center gap-2">
                          <Shield className="w-4 h-4" />
                          Risk Assessment
                        </CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="flex items-center justify-between mb-3">
                          <span>Risk Level:</span>
                          <Badge className={getRiskColor(analysis.riskAssessment.level)}>
                            {analysis.riskAssessment.level.toUpperCase()}
                          </Badge>
                        </div>
                        
                        {analysis.riskAssessment.level !== 'low' && (
                          <div className="space-y-2">
                            <div className="text-sm font-medium">Emergency Contacts:</div>
                            {analysis.riskAssessment.emergencyContacts.map((contact, index) => (
                              <div key={index} className="p-2 bg-red-50 rounded border-l-2 border-red-200">
                                <div className="font-medium">{contact.name}</div>
                                <div className="text-sm text-muted-foreground">{contact.number}</div>
                                <div className="text-xs text-muted-foreground">{contact.available}</div>
                              </div>
                            ))}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="trends" className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Weekly Average</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold">{analysis.moodTrends.weeklyAverage}/10</div>
                          <div className="flex items-center gap-1 mt-1">
                            <TrendingUp className={`w-4 h-4 ${
                              analysis.moodTrends.trend === 'improving' ? 'text-green-500' :
                              analysis.moodTrends.trend === 'declining' ? 'text-red-500' : 'text-gray-500'
                            }`} />
                            <span className="text-sm capitalize">{analysis.moodTrends.trend}</span>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Monthly Average</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="text-2xl font-bold">{analysis.moodTrends.monthlyAverage}/10</div>
                          <Progress value={analysis.moodTrends.monthlyAverage * 10} className="mt-2" />
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Streaks</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            <div>
                              <span className="text-sm text-muted-foreground">Current:</span>
                              <span className="ml-2 font-semibold">{analysis.moodTrends.streaks.current} days</span>
                            </div>
                            <div>
                              <span className="text-sm text-muted-foreground">Longest:</span>
                              <span className="ml-2 font-semibold">{analysis.moodTrends.streaks.longest} days</span>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="insights" className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm text-blue-600">Patterns</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {analysis.insights.patterns.map((pattern, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{pattern}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm text-green-600">Strengths</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {analysis.insights.strengths.map((strength, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{strength}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm text-orange-600">Triggers</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {analysis.insights.triggers.map((trigger, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-orange-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{trigger}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm text-red-600">Concerns</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {analysis.insights.concerns.map((concern, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-red-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{concern}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="recommendations" className="space-y-4">
                    <h3 className="font-semibold">Personalized Recommendations</h3>
                    
                    <div className="space-y-3">
                      {analysis.recommendations.map((rec, index) => (
                        <Card key={index}>
                          <CardContent className="pt-4">
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-2">
                                  <Badge className={getPriorityColor(rec.priority)}>
                                    {rec.priority}
                                  </Badge>
                                  <Badge variant="outline" className="text-xs">
                                    {rec.category}
                                  </Badge>
                                  <Badge variant="outline" className="text-xs">
                                    {rec.duration}
                                  </Badge>
                                </div>
                                <h4 className="font-medium mb-1">{rec.title}</h4>
                                <p className="text-sm text-muted-foreground">{rec.description}</p>
                              </div>
                              <Button size="sm" variant="outline">
                                <Sparkles className="w-4 h-4 mr-1" />
                                Try It
                              </Button>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="resources" className="space-y-4">
                    <h3 className="font-semibold">Mental Health Resources</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      {analysis.resources.map((resource, index) => (
                        <Card key={index}>
                          <CardContent className="pt-4">
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-2">
                                  <Badge variant="outline" className="text-xs">
                                    {resource.type}
                                  </Badge>
                                  {resource.duration && (
                                    <Badge variant="outline" className="text-xs">
                                      {resource.duration}
                                    </Badge>
                                  )}
                                </div>
                                <h4 className="font-medium mb-1">{resource.title}</h4>
                                <p className="text-sm text-muted-foreground">{resource.description}</p>
                              </div>
                              {resource.url && (
                                <Button size="sm" variant="outline">
                                  Open
                                </Button>
                              )}
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

          {!analysis && (
            <Card>
              <CardContent className="py-12 text-center">
                <Heart className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">Ready to Support You</h3>
                <p className="text-muted-foreground">
                  Complete your mood check-in to receive personalized AI-powered mental health insights and recommendations.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
