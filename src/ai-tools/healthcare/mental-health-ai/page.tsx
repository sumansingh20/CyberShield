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

interface MentalHealthRequest {
  mood_description: string
  stress_level: number
  anxiety_level: number
  sleep_quality: number
  recent_events: string
  support_needed: string[]
  assessment_type: 'mood' | 'stress' | 'anxiety' | 'wellness' | 'comprehensive'
}

interface MentalHealthAssessment {
  overall_assessment: {
    score: number
    level: string
    description: string
  }
  mood_analysis: {
    primary_emotion: string
    secondary_emotions: string[]
    emotional_stability: number
    insights: string[]
  }
  stress_indicators: {
    level: string
    triggers: string[]
    physical_symptoms: string[]
    coping_mechanisms: string[]
  }
  recommendations: {
    immediate_actions: string[]
    long_term_strategies: string[]
    professional_resources: string[]
    self_care_activities: string[]
  }
  risk_assessment: {
    level: string
    warning_signs: string[]
    crisis_resources: string[]
  }
  tracking_metrics: {
    mood_trend: string
    improvement_areas: string[]
    strengths: string[]
  }
  confidence_score: number
  processing_time: number
}

export default function MentalHealthAI() {
  const [request, setRequest] = useState<MentalHealthRequest>({
    mood_description: '',
    stress_level: 5,
    anxiety_level: 5,
    sleep_quality: 5,
    recent_events: '',
    support_needed: [],
    assessment_type: 'comprehensive'
  })
  
  const [result, setResult] = useState<MentalHealthAssessment | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [supportType, setSupportType] = useState('')

  const handleAssess = async () => {
    if (!request.mood_description.trim()) {
      setError('Please describe your current mood or feelings')
      return
    }

    setLoading(true)
    setError('')
    
    try {
      const response = await fetch('/api/tools/mental-health-ai', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      })

      if (!response.ok) {
        throw new Error('Failed to generate mental health assessment')
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const addSupportType = () => {
    if (supportType.trim() && !request.support_needed.includes(supportType.trim())) {
      setRequest({
        ...request,
        support_needed: [...request.support_needed, supportType.trim()]
      })
      setSupportType('')
    }
  }

  const removeSupportType = (type: string) => {
    setRequest({
      ...request,
      support_needed: request.support_needed.filter(t => t !== type)
    })
  }

  const getLevelColor = (level: string) => {
    switch (level.toLowerCase()) {
      case 'low': case 'good': case 'positive': return 'bg-green-100 text-green-800'
      case 'moderate': case 'fair': case 'neutral': return 'bg-yellow-100 text-yellow-800'
      case 'high': case 'poor': case 'negative': return 'bg-red-100 text-red-800'
      case 'critical': case 'severe': return 'bg-red-200 text-red-900'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const supportOptions = [
    'Professional Counseling', 'Peer Support', 'Family Support', 'Online Resources',
    'Meditation', 'Exercise', 'Therapy', 'Medication Guidance', 'Crisis Support'
  ]

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-2 mb-2">
          🧠 AI Mental Health Assistant
        </h1>
        <p className="text-gray-600">
          Personalized mental health assessment and wellness recommendations
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              📋 Assessment Input
            </CardTitle>
            <CardDescription>
              Share your current state and receive personalized insights
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <Label htmlFor="assessment-type">Assessment Type</Label>
              <select
                id="assessment-type"
                title="Select assessment type"
                className="w-full p-2 border rounded-md"
                value={request.assessment_type}
                onChange={(e) => setRequest({...request, assessment_type: e.target.value as any})}
              >
                <option value="comprehensive">Comprehensive Assessment</option>
                <option value="mood">Mood Analysis</option>
                <option value="stress">Stress Evaluation</option>
                <option value="anxiety">Anxiety Assessment</option>
                <option value="wellness">Wellness Check</option>
              </select>
            </div>

            <div>
              <Label htmlFor="mood">Current Mood & Feelings</Label>
              <Textarea
                id="mood"
                value={request.mood_description}
                onChange={(e) => setRequest({...request, mood_description: e.target.value})}
                placeholder="Describe how you're feeling today, your emotions, thoughts, or any concerns..."
                rows={4}
              />
            </div>

            <div>
              <Label htmlFor="recent-events">Recent Life Events (Optional)</Label>
              <Textarea
                id="recent-events"
                value={request.recent_events}
                onChange={(e) => setRequest({...request, recent_events: e.target.value})}
                placeholder="Any significant events, changes, or stressors in your life recently..."
                rows={3}
              />
            </div>

            <div className="space-y-4">
              <div>
                <Label>Stress Level (1-10)</Label>
                <div className="flex items-center gap-4 mt-2">
                  <span className="text-sm">Low</span>
                  <input
                    type="range"
                    min="1"
                    max="10"
                    value={request.stress_level}
                    onChange={(e) => setRequest({...request, stress_level: parseInt(e.target.value)})}
                    className="flex-1"
                  />
                  <span className="text-sm">High</span>
                  <Badge>{request.stress_level}</Badge>
                </div>
              </div>

              <div>
                <Label>Anxiety Level (1-10)</Label>
                <div className="flex items-center gap-4 mt-2">
                  <span className="text-sm">Low</span>
                  <input
                    type="range"
                    min="1"
                    max="10"
                    value={request.anxiety_level}
                    onChange={(e) => setRequest({...request, anxiety_level: parseInt(e.target.value)})}
                    className="flex-1"
                  />
                  <span className="text-sm">High</span>
                  <Badge>{request.anxiety_level}</Badge>
                </div>
              </div>

              <div>
                <Label>Sleep Quality (1-10)</Label>
                <div className="flex items-center gap-4 mt-2">
                  <span className="text-sm">Poor</span>
                  <input
                    type="range"
                    min="1"
                    max="10"
                    value={request.sleep_quality}
                    onChange={(e) => setRequest({...request, sleep_quality: parseInt(e.target.value)})}
                    className="flex-1"
                  />
                  <span className="text-sm">Excellent</span>
                  <Badge>{request.sleep_quality}</Badge>
                </div>
              </div>
            </div>

            <div>
              <Label>Support Types Needed</Label>
              <div className="flex gap-2 mt-1">
                <select
                  value={supportType}
                  onChange={(e) => setSupportType(e.target.value)}
                  className="flex-1 p-2 border rounded-md"
                >
                  <option value="">Select support type...</option>
                  {supportOptions.map(option => (
                    <option key={option} value={option}>{option}</option>
                  ))}
                </select>
                <Button type="button" onClick={addSupportType}>Add</Button>
              </div>
              {request.support_needed.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {request.support_needed.map((type, index) => (
                    <Badge key={index} className="cursor-pointer" onClick={() => removeSupportType(type)}>
                      {type} ×
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            {error && (
              <Alert>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button 
              onClick={handleAssess} 
              disabled={loading}
              className="w-full"
            >
              {loading ? 'Analyzing...' : 'Generate Mental Health Assessment'}
            </Button>
          </CardContent>
        </Card>

        {result && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                🎯 Assessment Results
              </CardTitle>
              <CardDescription>
                Personalized mental health insights and recommendations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="analysis">Analysis</TabsTrigger>
                  <TabsTrigger value="recommendations">Actions</TabsTrigger>
                  <TabsTrigger value="resources">Resources</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <div className="space-y-4">
                    <div className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="font-semibold">Overall Assessment</h3>
                        <Badge className={getLevelColor(result.overall_assessment.level)}>
                          {result.overall_assessment.level}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-sm">Wellness Score:</span>
                        <Progress value={result.overall_assessment.score} className="flex-1" />
                        <span className="font-medium">{result.overall_assessment.score}%</span>
                      </div>
                      <p className="text-gray-700">{result.overall_assessment.description}</p>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3 border rounded">
                        <h4 className="font-medium mb-2">Primary Emotion</h4>
                        <Badge className="mb-2">{result.mood_analysis.primary_emotion}</Badge>
                        <div className="flex items-center gap-2">
                          <span className="text-sm">Stability:</span>
                          <Progress value={result.mood_analysis.emotional_stability * 10} className="flex-1" />
                        </div>
                      </div>
                      <div className="p-3 border rounded">
                        <h4 className="font-medium mb-2">Risk Level</h4>
                        <Badge className={getLevelColor(result.risk_assessment.level)}>
                          {result.risk_assessment.level}
                        </Badge>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Secondary Emotions</h4>
                      <div className="flex flex-wrap gap-2">
                        {result.mood_analysis.secondary_emotions.map((emotion, index) => (
                          <Badge key={index}>{emotion}</Badge>
                        ))}
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="analysis" className="space-y-4">
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-semibold mb-2">Mood Insights</h3>
                      <div className="space-y-2">
                        {result.mood_analysis.insights.map((insight, index) => (
                          <div key={index} className="p-2 border rounded bg-blue-50">
                            <p className="text-sm">{insight}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Stress Analysis</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <h4 className="font-medium mb-2">Stress Triggers</h4>
                          <ul className="space-y-1">
                            {result.stress_indicators.triggers.map((trigger, index) => (
                              <li key={index} className="text-sm">• {trigger}</li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <h4 className="font-medium mb-2">Physical Symptoms</h4>
                          <ul className="space-y-1">
                            {result.stress_indicators.physical_symptoms.map((symptom, index) => (
                              <li key={index} className="text-sm">• {symptom}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Strengths & Improvement Areas</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <h4 className="font-medium mb-2 text-green-700">Strengths</h4>
                          <ul className="space-y-1">
                            {result.tracking_metrics.strengths.map((strength, index) => (
                              <li key={index} className="text-sm text-green-600">✓ {strength}</li>
                            ))}
                          </ul>
                        </div>
                        <div>
                          <h4 className="font-medium mb-2 text-orange-700">Areas to Focus</h4>
                          <ul className="space-y-1">
                            {result.tracking_metrics.improvement_areas.map((area, index) => (
                              <li key={index} className="text-sm text-orange-600">→ {area}</li>
                            ))}
                          </ul>
                        </div>
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="recommendations" className="space-y-4">
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-semibold mb-2">Immediate Actions</h3>
                      <div className="space-y-2">
                        {result.recommendations.immediate_actions.map((action, index) => (
                          <div key={index} className="flex items-center gap-2 p-2 border rounded">
                            <input type="checkbox" title="Mark as completed" />
                            <span className="text-sm">{action}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Long-term Strategies</h3>
                      <div className="space-y-2">
                        {result.recommendations.long_term_strategies.map((strategy, index) => (
                          <div key={index} className="p-2 border rounded bg-green-50">
                            <p className="text-sm">{strategy}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div>
                      <h3 className="font-semibold mb-2">Self-Care Activities</h3>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                        {result.recommendations.self_care_activities.map((activity, index) => (
                          <div key={index} className="flex items-center gap-2 p-2 border rounded">
                            <span className="text-blue-500">🌟</span>
                            <span className="text-sm">{activity}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="resources" className="space-y-4">
                  <div className="space-y-4">
                    <div>
                      <h3 className="font-semibold mb-2">Professional Resources</h3>
                      <div className="space-y-2">
                        {result.recommendations.professional_resources.map((resource, index) => (
                          <div key={index} className="p-3 border rounded">
                            <p className="text-sm">{resource}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {result.risk_assessment.warning_signs.length > 0 && (
                      <Alert>
                        <AlertDescription>
                          <strong>Warning Signs to Monitor:</strong>
                          <ul className="list-disc list-inside mt-1">
                            {result.risk_assessment.warning_signs.map((sign, index) => (
                              <li key={index}>{sign}</li>
                            ))}
                          </ul>
                        </AlertDescription>
                      </Alert>
                    )}

                    <div>
                      <h3 className="font-semibold mb-2">Crisis Resources</h3>
                      <div className="space-y-2">
                        {result.risk_assessment.crisis_resources.map((resource, index) => (
                          <div key={index} className="p-3 border rounded bg-red-50">
                            <p className="text-sm font-medium text-red-800">{resource}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="grid grid-cols-2 gap-4">
                      <div className="p-3 border rounded text-center">
                        <p className="text-sm text-gray-600">Confidence Score</p>
                        <p className="font-semibold">{result.confidence_score}%</p>
                      </div>
                      <div className="p-3 border rounded text-center">
                        <p className="text-sm text-gray-600">Processing Time</p>
                        <p className="font-semibold">{result.processing_time}ms</p>
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
            🏥 <strong>Important:</strong> This AI tool provides general wellness insights and is not a substitute for professional mental health care. 
            If you're experiencing a mental health crisis, please contact emergency services or a mental health professional immediately. 
            For immediate help: National Suicide Prevention Lifeline: 988
          </AlertDescription>
        </Alert>
      </div>
    </div>
  )
}
