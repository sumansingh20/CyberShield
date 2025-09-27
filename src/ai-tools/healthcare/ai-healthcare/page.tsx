'use client'

import { useState } from 'react'
import { Button } from '@/src/ui/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Label } from '@/src/ui/components/ui/label'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Upload, Heart, Brain, Eye, Stethoscope, AlertTriangle, CheckCircle, Activity, FileText } from 'lucide-react'
import { Badge } from '@/src/ui/components/ui/badge'
import { Progress } from '@/src/ui/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select'

interface HealthDiagnosisResult {
  condition: string
  confidence: number
  severity: 'LOW' | 'MODERATE' | 'HIGH' | 'CRITICAL'
  findings: {
    primary: string[]
    secondary: string[]
    differential: string[]
  }
  aiAnalysis: {
    imageFeatures: string[]
    patternRecognition: string[]
    anatomicalAssessment: string[]
    comparisonToNormal: string[]
  }
  recommendations: {
    immediate: string[]
    followUp: string[]
    lifestyle: string[]
    monitoring: string[]
  }
  riskFactors: {
    identified: string[]
    modifiable: string[]
    nonModifiable: string[]
  }
  disclaimer: string
  timestamp: string
}

interface VitalSigns {
  heartRate?: number
  bloodPressure?: string
  temperature?: number
  respiratoryRate?: number
  oxygenSaturation?: number
  bloodSugar?: number
}

interface SymptomAnalysis {
  symptoms: string[]
  duration: string
  severity: number
  associatedFactors: string[]
}

export default function HealthcareDiagnosticPage() {
  const [selectedTab, setSelectedTab] = useState<'imaging' | 'symptoms' | 'vitals'>('imaging')
  const [file, setFile] = useState<File | null>(null)
  const [scanType, setScanType] = useState<string>('')
  const [symptoms, setSymptoms] = useState<string>('')
  const [duration, setDuration] = useState<string>('')
  const [severity, setSeverity] = useState<number>(5)
  const [vitalSigns, setVitalSigns] = useState<VitalSigns>({})
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<HealthDiagnosisResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [analysisProgress, setAnalysisProgress] = useState(0)

  const scanTypes = [
    { value: 'xray', label: 'X-Ray Imaging' },
    { value: 'ct', label: 'CT Scan' },
    { value: 'mri', label: 'MRI Scan' },
    { value: 'ultrasound', label: 'Ultrasound' },
    { value: 'mammogram', label: 'Mammogram' },
    { value: 'dermatology', label: 'Skin Lesion' },
    { value: 'retinal', label: 'Retinal Imaging' },
    { value: 'ecg', label: 'ECG/EKG' }
  ]

  const handleFileSelect = (selectedFile: File) => {
    const maxSize = 50 * 1024 * 1024 // 50MB
    if (selectedFile.size > maxSize) {
      setError('File size must be less than 50MB')
      return
    }

    const allowedTypes = ['image/jpeg', 'image/png', 'image/dicom', 'image/tiff']
    if (!allowedTypes.includes(selectedFile.type)) {
      setError('Please select a valid medical image file (JPEG, PNG, DICOM, TIFF)')
      return
    }

    setFile(selectedFile)
    setError(null)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const droppedFile = e.dataTransfer.files[0]
    if (droppedFile) {
      handleFileSelect(droppedFile)
    }
  }

  const simulateProgress = () => {
    const intervals = [
      { delay: 500, progress: 15, message: 'Preprocessing medical data...' },
      { delay: 1000, progress: 30, message: 'Running AI diagnostic models...' },
      { delay: 1500, progress: 45, message: 'Analyzing anatomical structures...' },
      { delay: 2000, progress: 60, message: 'Pattern recognition analysis...' },
      { delay: 2500, progress: 75, message: 'Generating clinical insights...' },
      { delay: 3000, progress: 90, message: 'Preparing recommendations...' },
      { delay: 3500, progress: 100, message: 'Analysis complete!' }
    ]

    intervals.forEach(({ delay, progress }) => {
      setTimeout(() => setAnalysisProgress(progress), delay)
    })
  }

  const analyzeHealthData = async () => {
    if (selectedTab === 'imaging' && (!file || !scanType)) {
      setError('Please upload an image and select scan type')
      return
    }
    if (selectedTab === 'symptoms' && !symptoms) {
      setError('Please describe your symptoms')
      return
    }
    if (selectedTab === 'vitals' && Object.keys(vitalSigns).length === 0) {
      setError('Please enter at least one vital sign')
      return
    }

    setIsAnalyzing(true)
    setError(null)
    setResult(null)
    setAnalysisProgress(0)

    simulateProgress()

    try {
      let endpoint = '/api/tools/healthcare-diagnostic'
      let payload: any = { type: selectedTab }

      if (selectedTab === 'imaging') {
        const formData = new FormData()
        formData.append('file', file!)
        formData.append('scanType', scanType)
        formData.append('type', 'imaging')
        
        const response = await fetch(endpoint, {
          method: 'POST',
          body: formData
        })

        if (!response.ok) {
          throw new Error(`Analysis failed: ${response.statusText}`)
        }

        const result = await response.json()
        setResult(result)
        return
      } else if (selectedTab === 'symptoms') {
        payload.symptoms = symptoms
        payload.duration = duration
        payload.severity = severity
      } else {
        payload.vitalSigns = vitalSigns
      }

      const response = await fetch(endpoint, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify(payload)
      })

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.statusText}`)
      }

      const result = await response.json()
      setResult(result)

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed')
    } finally {
      setIsAnalyzing(false)
      setAnalysisProgress(0)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'LOW': return 'text-green-600 bg-green-50 border-green-200'
      case 'MODERATE': return 'text-yellow-600 bg-yellow-50 border-yellow-200'
      case 'HIGH': return 'text-orange-600 bg-orange-50 border-orange-200'
      case 'CRITICAL': return 'text-red-600 bg-red-50 border-red-200'
      default: return 'text-gray-600 bg-gray-50 border-gray-200'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity) {
      case 'LOW': return <CheckCircle className="h-4 w-4" />
      case 'MODERATE': return <Eye className="h-4 w-4" />
      case 'HIGH': return <AlertTriangle className="h-4 w-4" />
      case 'CRITICAL': return <Activity className="h-4 w-4" />
      default: return <Eye className="h-4 w-4" />
    }
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <Heart className="h-6 w-6 text-red-600" />
        <h1 className="text-3xl font-bold">AI Healthcare Diagnostic Assistant</h1>
      </div>

      <Alert className="border-blue-200 bg-blue-50">
        <Stethoscope className="h-4 w-4 text-blue-600" />
        <AlertDescription className="text-blue-800">
          <strong>Medical Disclaimer:</strong> This AI diagnostic tool is for educational and informational purposes only. 
          It does not replace professional medical advice, diagnosis, or treatment. Always consult with qualified healthcare providers.
        </AlertDescription>
      </Alert>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Brain className="h-5 w-5" />
              Medical Data Input
            </CardTitle>
            <CardDescription>
              Upload medical images, describe symptoms, or enter vital signs for AI analysis
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Tabs value={selectedTab} onValueChange={(value) => setSelectedTab(value as any)}>
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="imaging" className="flex items-center gap-2">
                  <Eye className="h-4 w-4" />
                  Imaging
                </TabsTrigger>
                <TabsTrigger value="symptoms" className="flex items-center gap-2">
                  <FileText className="h-4 w-4" />
                  Symptoms
                </TabsTrigger>
                <TabsTrigger value="vitals" className="flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Vitals
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="imaging" className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="scan-type">Medical Scan Type</Label>
                  <Select value={scanType} onValueChange={setScanType}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select scan type" />
                    </SelectTrigger>
                    <SelectContent>
                      {scanTypes.map((type) => (
                        <SelectItem key={type.value} value={type.value}>
                          {type.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div
                  className={`border-2 border-dashed rounded-lg p-8 text-center transition-colors ${
                    dragOver ? 'border-blue-500 bg-blue-50' : 'border-gray-300'
                  }`}
                  onDrop={handleDrop}
                  onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
                  onDragLeave={() => setDragOver(false)}
                >
                  <Upload className="h-12 w-12 mx-auto mb-4 text-gray-400" />
                  <p className="text-lg font-semibold mb-2">Upload Medical Image</p>
                  <p className="text-gray-600 mb-4">
                    Drag and drop a medical image or click to browse
                  </p>
                  <input
                    type="file"
                    accept="image/*,.dcm"
                    onChange={(e) => e.target.files && handleFileSelect(e.target.files[0])}
                    className="hidden"
                    id="image-upload"
                    title="Upload medical image file"
                    aria-label="Upload medical image file"
                  />
                  <Label htmlFor="image-upload">
                    <Button variant="outline" className="cursor-pointer">
                      Select Medical Image
                    </Button>
                  </Label>
                  {file && (
                    <div className="mt-4 p-3 bg-gray-50 rounded-lg">
                      <p className="font-medium text-sm">{file.name}</p>
                      <p className="text-xs text-gray-600">
                        {(file.size / 1024 / 1024).toFixed(2)} MB
                      </p>
                    </div>
                  )}
                </div>
              </TabsContent>

              <TabsContent value="symptoms" className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="symptoms">Describe Your Symptoms</Label>
                  <textarea
                    id="symptoms"
                    value={symptoms}
                    onChange={(e) => setSymptoms(e.target.value)}
                    placeholder="Describe your symptoms in detail... (e.g., headache, nausea, chest pain, difficulty breathing)"
                    className="w-full h-32 p-3 border rounded-lg resize-none focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                  />
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="duration">Duration</Label>
                    <Select value={duration} onValueChange={setDuration}>
                      <SelectTrigger>
                        <SelectValue placeholder="How long?" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="minutes">Minutes</SelectItem>
                        <SelectItem value="hours">Hours</SelectItem>
                        <SelectItem value="days">Days</SelectItem>
                        <SelectItem value="weeks">Weeks</SelectItem>
                        <SelectItem value="months">Months</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label>Severity (1-10)</Label>
                    <div className="flex items-center space-x-2">
                      <span>1</span>
                      <input
                        type="range"
                        min="1"
                        max="10"
                        value={severity}
                        onChange={(e) => setSeverity(Number(e.target.value))}
                        className="flex-1"
                        title="Symptom severity scale from 1 to 10"
                        aria-label="Symptom severity scale from 1 to 10"
                      />
                      <span>10</span>
                      <Badge variant="outline">{severity}</Badge>
                    </div>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="vitals" className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="heart-rate">Heart Rate (BPM)</Label>
                    <input
                      id="heart-rate"
                      type="number"
                      placeholder="72"
                      value={vitalSigns.heartRate || ''}
                      onChange={(e) => setVitalSigns(prev => ({ ...prev, heartRate: Number(e.target.value) }))}
                      className="w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="blood-pressure">Blood Pressure</Label>
                    <input
                      id="blood-pressure"
                      type="text"
                      placeholder="120/80"
                      value={vitalSigns.bloodPressure || ''}
                      onChange={(e) => setVitalSigns(prev => ({ ...prev, bloodPressure: e.target.value }))}
                      className="w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="temperature">Temperature (°F)</Label>
                    <input
                      id="temperature"
                      type="number"
                      step="0.1"
                      placeholder="98.6"
                      value={vitalSigns.temperature || ''}
                      onChange={(e) => setVitalSigns(prev => ({ ...prev, temperature: Number(e.target.value) }))}
                      className="w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="oxygen-sat">Oxygen Saturation (%)</Label>
                    <input
                      id="oxygen-sat"
                      type="number"
                      placeholder="98"
                      value={vitalSigns.oxygenSaturation || ''}
                      onChange={(e) => setVitalSigns(prev => ({ ...prev, oxygenSaturation: Number(e.target.value) }))}
                      className="w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="respiratory-rate">Respiratory Rate</Label>
                    <input
                      id="respiratory-rate"
                      type="number"
                      placeholder="16"
                      value={vitalSigns.respiratoryRate || ''}
                      onChange={(e) => setVitalSigns(prev => ({ ...prev, respiratoryRate: Number(e.target.value) }))}
                      className="w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="blood-sugar">Blood Sugar (mg/dL)</Label>
                    <input
                      id="blood-sugar"
                      type="number"
                      placeholder="100"
                      value={vitalSigns.bloodSugar || ''}
                      onChange={(e) => setVitalSigns(prev => ({ ...prev, bloodSugar: Number(e.target.value) }))}
                      className="w-full p-2 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
                    />
                  </div>
                </div>
              </TabsContent>
            </Tabs>

            {error && (
              <Alert className="border-red-200 bg-red-50">
                <AlertTriangle className="h-4 w-4 text-red-600" />
                <AlertDescription className="text-red-800">
                  {error}
                </AlertDescription>
              </Alert>
            )}

            {isAnalyzing && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span>Analyzing medical data...</span>
                  <span>{analysisProgress}%</span>
                </div>
                <Progress value={analysisProgress} className="w-full" />
              </div>
            )}

            <Button 
              onClick={analyzeHealthData} 
              disabled={isAnalyzing}
              className="w-full"
            >
              {isAnalyzing ? 'Analyzing...' : 'Analyze Medical Data'}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Brain className="h-5 w-5" />
              AI Diagnostic Results
            </CardTitle>
            <CardDescription>
              AI-powered medical analysis and recommendations
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!result && (
              <div className="text-center py-8 text-gray-500">
                <Stethoscope className="h-16 w-16 mx-auto mb-4 opacity-50" />
                <p>Upload medical data and run analysis to see results</p>
              </div>
            )}

            {result && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Badge className={`${getSeverityColor(result.severity)} px-3 py-1`}>
                      {getSeverityIcon(result.severity)}
                      {result.severity}
                    </Badge>
                    <span className="text-sm text-gray-600">
                      {result.confidence}% confidence
                    </span>
                  </div>
                  <div className="text-right">
                    <p className="font-semibold text-lg">{result.condition}</p>
                  </div>
                </div>

                <div className="space-y-4">
                  <div>
                    <h4 className="font-semibold text-sm mb-2">Key Findings</h4>
                    <div className="space-y-2">
                      <div>
                        <span className="text-xs font-medium text-green-600">Primary:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {result.findings.primary.map((finding, index) => (
                            <Badge key={index} variant="outline" className="text-xs">
                              {finding}
                            </Badge>
                          ))}
                        </div>
                      </div>
                      {result.findings.secondary.length > 0 && (
                        <div>
                          <span className="text-xs font-medium text-yellow-600">Secondary:</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {result.findings.secondary.map((finding, index) => (
                              <Badge key={index} variant="outline" className="text-xs">
                                {finding}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>

                  <div>
                    <h4 className="font-semibold text-sm mb-2">AI Analysis</h4>
                    <div className="grid gap-2 text-xs">
                      {result.aiAnalysis.imageFeatures.length > 0 && (
                        <div>
                          <span className="font-medium">Image Features:</span>
                          <span className="ml-2">{result.aiAnalysis.imageFeatures.join(', ')}</span>
                        </div>
                      )}
                      {result.aiAnalysis.patternRecognition.length > 0 && (
                        <div>
                          <span className="font-medium">Pattern Recognition:</span>
                          <span className="ml-2">{result.aiAnalysis.patternRecognition.join(', ')}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div>
                    <h4 className="font-semibold text-sm mb-2">Recommendations</h4>
                    <div className="space-y-2">
                      {result.recommendations.immediate.length > 0 && (
                        <div>
                          <span className="text-xs font-medium text-red-600">Immediate:</span>
                          <ul className="text-xs space-y-1 mt-1">
                            {result.recommendations.immediate.map((rec, index) => (
                              <li key={index} className="flex items-start gap-2">
                                <CheckCircle className="h-3 w-3 mt-0.5 text-red-600 flex-shrink-0" />
                                {rec}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                      {result.recommendations.followUp.length > 0 && (
                        <div>
                          <span className="text-xs font-medium text-blue-600">Follow-up:</span>
                          <ul className="text-xs space-y-1 mt-1">
                            {result.recommendations.followUp.map((rec, index) => (
                              <li key={index} className="flex items-start gap-2">
                                <CheckCircle className="h-3 w-3 mt-0.5 text-blue-600 flex-shrink-0" />
                                {rec}
                              </li>
                            ))}
                          </ul>
                        </div>
                      )}
                    </div>
                  </div>

                  {result.riskFactors.identified.length > 0 && (
                    <div>
                      <h4 className="font-semibold text-sm mb-2">Risk Factors</h4>
                      <div className="space-y-1">
                        {result.riskFactors.identified.map((factor, index) => (
                          <Badge key={index} variant="outline" className="text-xs mr-1 mb-1">
                            {factor}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <Alert className="border-yellow-200 bg-yellow-50">
                  <AlertTriangle className="h-4 w-4 text-yellow-600" />
                  <AlertDescription className="text-yellow-800 text-xs">
                    {result.disclaimer}
                  </AlertDescription>
                </Alert>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
