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
import { 
  Heart, 
  Brain, 
  Activity, 
  AlertTriangle, 
  CheckCircle, 
  Info,
  Stethoscope,
  FileText,
  Clock,
  TrendingUp
} from 'lucide-react'

interface DiagnosticRequest {
  symptoms: string
  medical_history: string
  age: number
  gender: string
  vital_signs: {
    temperature: number
    blood_pressure: string
    heart_rate: number
    respiratory_rate: number
  }
  severity: 'mild' | 'moderate' | 'severe'
}

interface DiagnosticResult {
  primary_diagnosis: {
    condition: string
    confidence: number
    icd_code: string
    description: string
  }
  differential_diagnoses: Array<{
    condition: string
    confidence: number
    reasoning: string
  }>
  recommended_tests: string[]
  treatment_suggestions: string[]
  urgency_level: string
  red_flags: string[]
  follow_up_recommendations: string
  confidence_score: number
  analysis_time: number
}

export default function HealthcareDiagnostic() {
  const [request, setRequest] = useState<DiagnosticRequest>({
    symptoms: '',
    medical_history: '',
    age: 0,
    gender: 'other',
    vital_signs: {
      temperature: 98.6,
      blood_pressure: '120/80',
      heart_rate: 70,
      respiratory_rate: 16
    },
    severity: 'mild'
  })
  
  const [result, setResult] = useState<DiagnosticResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleDiagnose = async () => {
    if (!request.symptoms.trim()) {
      setError('Please describe the symptoms')
      return
    }

    setLoading(true)
    setError('')
    
    try {
      const response = await fetch('/api/tools/healthcare-diagnostic', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      })

      if (!response.ok) {
        throw new Error('Diagnostic analysis failed')
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'low': return 'bg-green-100 text-green-800'
      case 'moderate': return 'bg-yellow-100 text-yellow-800'
      case 'high': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getUrgencyIcon = (urgency: string) => {
    switch (urgency.toLowerCase()) {
      case 'emergency': return <AlertTriangle className="h-4 w-4 text-red-500" />
      case 'urgent': return <Clock className="h-4 w-4 text-orange-500" />
      case 'routine': return <CheckCircle className="h-4 w-4 text-green-500" />
      default: return <Info className="h-4 w-4 text-blue-500" />
    }
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-2 mb-2">
          <Stethoscope className="h-8 w-8 text-blue-600" />
          AI Healthcare Diagnostic Assistant
        </h1>
        <p className="text-gray-600">
          Advanced AI-powered diagnostic tool for healthcare professionals and educational purposes
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <FileText className="h-5 w-5" />
              Patient Information
            </CardTitle>
            <CardDescription>
              Enter patient details and symptoms for AI analysis
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label htmlFor="age">Age</Label>
                <Input
                  id="age"
                  type="number"
                  value={request.age || ''}
                  onChange={(e) => setRequest({...request, age: parseInt(e.target.value) || 0})}
                  placeholder="Patient age"
                />
              </div>
              <div>
                <Label htmlFor="gender">Gender</Label>
                <select
                  id="gender"
                  className="w-full p-2 border rounded-md"
                  value={request.gender}
                  onChange={(e) => setRequest({...request, gender: e.target.value})}
                >
                  <option value="male">Male</option>
                  <option value="female">Female</option>
                  <option value="other">Other</option>
                </select>
              </div>
            </div>

            <div>
              <Label htmlFor="symptoms">Symptoms Description</Label>
              <Textarea
                id="symptoms"
                value={request.symptoms}
                onChange={(e) => setRequest({...request, symptoms: e.target.value})}
                placeholder="Describe the patient's symptoms in detail..."
                rows={4}
              />
            </div>

            <div>
              <Label htmlFor="history">Medical History</Label>
              <Textarea
                id="history"
                value={request.medical_history}
                onChange={(e) => setRequest({...request, medical_history: e.target.value})}
                placeholder="Previous medical conditions, medications, allergies..."
                rows={3}
              />
            </div>

            <div>
              <Label>Vital Signs</Label>
              <div className="grid grid-cols-2 gap-4 mt-2">
                <div>
                  <Label htmlFor="temp" className="text-sm">Temperature (°F)</Label>
                  <Input
                    id="temp"
                    type="number"
                    step="0.1"
                    value={request.vital_signs.temperature}
                    onChange={(e) => setRequest({
                      ...request,
                      vital_signs: {...request.vital_signs, temperature: parseFloat(e.target.value)}
                    })}
                  />
                </div>
                <div>
                  <Label htmlFor="bp" className="text-sm">Blood Pressure</Label>
                  <Input
                    id="bp"
                    value={request.vital_signs.blood_pressure}
                    onChange={(e) => setRequest({
                      ...request,
                      vital_signs: {...request.vital_signs, blood_pressure: e.target.value}
                    })}
                    placeholder="120/80"
                  />
                </div>
                <div>
                  <Label htmlFor="hr" className="text-sm">Heart Rate (BPM)</Label>
                  <Input
                    id="hr"
                    type="number"
                    value={request.vital_signs.heart_rate}
                    onChange={(e) => setRequest({
                      ...request,
                      vital_signs: {...request.vital_signs, heart_rate: parseInt(e.target.value)}
                    })}
                  />
                </div>
                <div>
                  <Label htmlFor="rr" className="text-sm">Respiratory Rate</Label>
                  <Input
                    id="rr"
                    type="number"
                    value={request.vital_signs.respiratory_rate}
                    onChange={(e) => setRequest({
                      ...request,
                      vital_signs: {...request.vital_signs, respiratory_rate: parseInt(e.target.value)}
                    })}
                  />
                </div>
              </div>
            </div>

            <div>
              <Label>Symptom Severity</Label>
              <select
                className="w-full p-2 border rounded-md mt-1"
                value={request.severity}
                onChange={(e) => setRequest({...request, severity: e.target.value as any})}
              >
                <option value="mild">Mild</option>
                <option value="moderate">Moderate</option>
                <option value="severe">Severe</option>
              </select>
            </div>

            {error && (
              <Alert>
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button 
              onClick={handleDiagnose} 
              disabled={loading}
              className="w-full"
            >
              {loading ? 'Analyzing...' : 'Generate Diagnostic Analysis'}
            </Button>
          </CardContent>
        </Card>

        {result && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Brain className="h-5 w-5" />
                Diagnostic Analysis Results
              </CardTitle>
              <CardDescription>
                AI-generated diagnostic suggestions and recommendations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="diagnosis" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="diagnosis">Diagnosis</TabsTrigger>
                  <TabsTrigger value="tests">Tests</TabsTrigger>
                  <TabsTrigger value="treatment">Treatment</TabsTrigger>
                  <TabsTrigger value="followup">Follow-up</TabsTrigger>
                </TabsList>

                <TabsContent value="diagnosis" className="space-y-4">
                  <div className="space-y-4">
                    <div className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="font-semibold">Primary Diagnosis</h3>
                        <Badge className={getSeverityColor(result.urgency_level)}>
                          {getUrgencyIcon(result.urgency_level)}
                          {result.urgency_level}
                        </Badge>
                      </div>
                      <p className="font-medium text-lg">{result.primary_diagnosis.condition}</p>
                      <p className="text-sm text-gray-600 mb-2">ICD Code: {result.primary_diagnosis.icd_code}</p>
                      <p className="text-sm mb-2">{result.primary_diagnosis.description}</p>
                      <div className="flex items-center gap-2">
                        <span className="text-sm">Confidence:</span>
                        <Progress value={result.primary_diagnosis.confidence} className="flex-1" />
                        <span className="text-sm font-medium">{result.primary_diagnosis.confidence}%</span>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Differential Diagnoses</h4>
                      <div className="space-y-2">
                        {result.differential_diagnoses.map((diagnosis, index) => (
                          <div key={index} className="p-3 border rounded">
                            <div className="flex items-center justify-between mb-1">
                              <span className="font-medium">{diagnosis.condition}</span>
                              <Badge variant="outline">{diagnosis.confidence}%</Badge>
                            </div>
                            <p className="text-sm text-gray-600">{diagnosis.reasoning}</p>
                          </div>
                        ))}
                      </div>
                    </div>

                    {result.red_flags.length > 0 && (
                      <Alert>
                        <AlertTriangle className="h-4 w-4" />
                        <AlertDescription>
                          <strong>Red Flags:</strong>
                          <ul className="list-disc list-inside mt-1">
                            {result.red_flags.map((flag, index) => (
                              <li key={index}>{flag}</li>
                            ))}
                          </ul>
                        </AlertDescription>
                      </Alert>
                    )}
                  </div>
                </TabsContent>

                <TabsContent value="tests" className="space-y-4">
                  <div className="space-y-3">
                    <h3 className="font-semibold">Recommended Diagnostic Tests</h3>
                    {result.recommended_tests.map((test, index) => (
                      <div key={index} className="flex items-center gap-2 p-2 border rounded">
                        <Activity className="h-4 w-4 text-blue-500" />
                        <span>{test}</span>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="treatment" className="space-y-4">
                  <div className="space-y-3">
                    <h3 className="font-semibold">Treatment Suggestions</h3>
                    {result.treatment_suggestions.map((treatment, index) => (
                      <div key={index} className="flex items-center gap-2 p-2 border rounded">
                        <Heart className="h-4 w-4 text-red-500" />
                        <span>{treatment}</span>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="followup" className="space-y-4">
                  <div className="p-4 border rounded-lg">
                    <h3 className="font-semibold mb-2">Follow-up Recommendations</h3>
                    <p>{result.follow_up_recommendations}</p>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-4">
                    <div className="p-3 border rounded text-center">
                      <TrendingUp className="h-6 w-6 mx-auto mb-1 text-blue-500" />
                      <p className="text-sm text-gray-600">Confidence Score</p>
                      <p className="font-semibold">{result.confidence_score}%</p>
                    </div>
                    <div className="p-3 border rounded text-center">
                      <Clock className="h-6 w-6 mx-auto mb-1 text-green-500" />
                      <p className="text-sm text-gray-600">Analysis Time</p>
                      <p className="font-semibold">{result.analysis_time}ms</p>
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
          <Info className="h-4 w-4" />
          <AlertDescription>
            <strong>Medical Disclaimer:</strong> This AI diagnostic tool is for educational and research purposes only. 
            It should not be used as a substitute for professional medical advice, diagnosis, or treatment. 
            Always consult with qualified healthcare professionals for medical decisions.
          </AlertDescription>
        </Alert>
      </div>
    </div>
  )
}
