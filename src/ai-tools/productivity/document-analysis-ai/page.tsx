'use client'

import { useState, useRef } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Label } from '@/src/ui/components/ui/label'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select'
import { Badge } from '@/src/ui/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Progress } from '@/src/ui/components/ui/progress'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { FileText, Upload, Download, Eye, Brain, AlertTriangle, BarChart3, CheckCircle, Clock } from 'lucide-react'

interface DocumentAnalysis {
  fileName: string
  fileSize: string
  documentType: string
  content: string
  summary: {
    executiveSummary: string
    keyPoints: string[]
    mainTopics: string[]
    wordCount: number
    pageCount: number
  }
  insights: {
    sentiment: {
      score: number
      label: string
      confidence: number
    }
    readability: {
      score: number
      grade: string
      difficulty: string
    }
    topics: Array<{
      topic: string
      relevance: number
      keywords: string[]
    }>
    entities: Array<{
      text: string
      type: string
      confidence: number
    }>
  }
  actionItems: Array<{
    item: string
    priority: 'high' | 'medium' | 'low'
    category: string
    deadline?: string
  }>
  compliance: {
    issues: string[]
    recommendations: string[]
    riskLevel: 'low' | 'medium' | 'high'
  }
  metadata: {
    processingTime: number
    confidence: number
    language: string
    lastModified?: string
  }
  timestamp: string
}

const DOCUMENT_TYPES = [
  'Auto-detect',
  'Business Report',
  'Legal Document',
  'Academic Paper',
  'Financial Statement',
  'Technical Manual',
  'Email',
  'Contract',
  'Resume/CV',
  'Meeting Notes'
]

const ANALYSIS_FOCUS = [
  'Comprehensive',
  'Summary Only',
  'Action Items',
  'Compliance Check',
  'Sentiment Analysis',
  'Entity Extraction',
  'Readability Assessment'
]

export default function SmartDocumentAnalysisPage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [documentType, setDocumentType] = useState('')
  const [analysisFocus, setAnalysisFocus] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [progress, setProgress] = useState(0)
  const [analysis, setAnalysis] = useState<DocumentAnalysis | null>(null)
  const [error, setError] = useState<string | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      // Check file type and size
      const allowedTypes = ['application/pdf', 'text/plain', 'application/msword', 'application/vnd.openxmlformats-officedocument.wordprocessingml.document']
      if (!allowedTypes.includes(file.type) && !file.name.match(/\.(txt|pdf|doc|docx)$/i)) {
        setError('Please select a valid document file (PDF, DOC, DOCX, or TXT)')
        return
      }
      
      if (file.size > 10 * 1024 * 1024) { // 10MB limit
        setError('File size must be less than 10MB')
        return
      }
      
      setSelectedFile(file)
      setError(null)
    }
  }

  const handleAnalyze = async () => {
    if (!selectedFile) {
      setError('Please select a document to analyze')
      return
    }

    setIsAnalyzing(true)
    setError(null)
    setProgress(0)

    // Simulate analysis progress
    const progressInterval = setInterval(() => {
      setProgress(prev => {
        if (prev >= 90) {
          clearInterval(progressInterval)
          return 90
        }
        return prev + 15
      })
    }, 500)

    try {
      // Convert file to base64 for API
      const fileContent = await fileToBase64(selectedFile)
      
      const response = await fetch('/api/tools/document-analysis-ai', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: 'analyze',
          fileName: selectedFile.name,
          fileSize: formatFileSize(selectedFile.size),
          fileContent: fileContent,
          documentType: documentType || 'auto-detect',
          analysisFocus: analysisFocus || 'comprehensive'
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Document analysis failed')
      }

      setAnalysis(data)
      setProgress(100)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Document analysis failed')
    } finally {
      clearInterval(progressInterval)
      setIsAnalyzing(false)
      setTimeout(() => setProgress(0), 1000)
    }
  }

  const fileToBase64 = (file: File): Promise<string> => {
    return new Promise((resolve, reject) => {
      const reader = new FileReader()
      reader.readAsDataURL(file)
      reader.onload = () => {
        const result = reader.result as string
        resolve(result.split(',')[1]) // Remove data URL prefix
      }
      reader.onerror = reject
    })
  }

  const formatFileSize = (bytes: number): string => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  const downloadReport = () => {
    if (!analysis) return

    const report = `Document Analysis Report
Generated: ${new Date(analysis.timestamp).toLocaleString()}

DOCUMENT INFORMATION:
- File Name: ${analysis.fileName}
- File Size: ${analysis.fileSize}
- Document Type: ${analysis.documentType}
- Language: ${analysis.metadata.language}
- Processing Time: ${analysis.metadata.processingTime}ms

EXECUTIVE SUMMARY:
${analysis.summary.executiveSummary}

KEY POINTS:
${analysis.summary.keyPoints.map(point => `• ${point}`).join('\n')}

MAIN TOPICS:
${analysis.summary.mainTopics.map(topic => `• ${topic}`).join('\n')}

SENTIMENT ANALYSIS:
- Score: ${analysis.insights.sentiment.score}%
- Label: ${analysis.insights.sentiment.label}
- Confidence: ${analysis.insights.sentiment.confidence}%

READABILITY ASSESSMENT:
- Score: ${analysis.insights.readability.score}%
- Grade Level: ${analysis.insights.readability.grade}
- Difficulty: ${analysis.insights.readability.difficulty}

TOPICS DETECTED:
${analysis.insights.topics.map(topic => 
  `• ${topic.topic} (${topic.relevance}% relevance): ${topic.keywords.join(', ')}`
).join('\n')}

ENTITIES IDENTIFIED:
${analysis.insights.entities.map(entity => 
  `• ${entity.text} (${entity.type}) - ${entity.confidence}% confidence`
).join('\n')}

ACTION ITEMS:
${analysis.actionItems.map(item => 
  `• [${item.priority.toUpperCase()}] ${item.item} (${item.category})`
).join('\n')}

COMPLIANCE ANALYSIS:
- Risk Level: ${analysis.compliance.riskLevel}
- Issues Found: ${analysis.compliance.issues.length}
${analysis.compliance.issues.map(issue => `  • ${issue}`).join('\n')}
- Recommendations: ${analysis.compliance.recommendations.length}
${analysis.compliance.recommendations.map(rec => `  • ${rec}`).join('\n')}

DOCUMENT STATISTICS:
- Word Count: ${analysis.summary.wordCount}
- Page Count: ${analysis.summary.pageCount}
- Analysis Confidence: ${analysis.metadata.confidence}%`

    const blob = new Blob([report], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `analysis_${analysis.fileName}_${Date.now()}.txt`
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

  const getRiskColor = (risk: string): string => {
    const colors = {
      high: 'bg-red-100 text-red-800',
      medium: 'bg-yellow-100 text-yellow-800',
      low: 'bg-green-100 text-green-800'
    }
    return colors[risk as keyof typeof colors] || 'bg-gray-100 text-gray-800'
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
        <h1 className="text-4xl font-bold mb-4 bg-gradient-to-r from-blue-600 to-green-600 bg-clip-text text-transparent">
          Smart Document Analysis AI
        </h1>
        <p className="text-lg text-muted-foreground">
          Extract insights, generate summaries, and analyze documents with advanced AI-powered processing
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Document Upload & Settings */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <FileText className="w-5 h-5" />
                Document Analysis
              </CardTitle>
              <CardDescription>
                Upload and configure your document analysis
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-4">
                <Label>Document File *</Label>
                <div 
                  className="border-2 border-dashed border-gray-300 rounded-lg p-6 text-center cursor-pointer hover:border-gray-400 transition-colors"
                  onClick={() => fileInputRef.current?.click()}
                >
                  <Upload className="w-8 h-8 mx-auto mb-2 text-gray-400" />
                  <p className="text-sm text-gray-600">
                    {selectedFile ? selectedFile.name : 'Click to upload or drag and drop'}
                  </p>
                  <p className="text-xs text-gray-500 mt-1">
                    PDF, DOC, DOCX, TXT (max 10MB)
                  </p>
                </div>
                <input
                  ref={fileInputRef}
                  type="file"
                  accept=".pdf,.doc,.docx,.txt"
                  onChange={handleFileSelect}
                  className="hidden"
                  disabled={isAnalyzing}
                  aria-label="Upload document file"
                  title="Upload document file for analysis"
                />
                
                {selectedFile && (
                  <div className="flex items-center gap-2 p-3 bg-gray-50 rounded-lg">
                    <FileText className="w-4 h-4 text-gray-500" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium truncate">{selectedFile.name}</p>
                      <p className="text-xs text-gray-500">{formatFileSize(selectedFile.size)}</p>
                    </div>
                  </div>
                )}
              </div>

              <div className="space-y-2">
                <Label htmlFor="documentType">Document Type</Label>
                <Select value={documentType} onValueChange={setDocumentType} disabled={isAnalyzing}>
                  <SelectTrigger>
                    <SelectValue placeholder="Auto-detect" />
                  </SelectTrigger>
                  <SelectContent>
                    {DOCUMENT_TYPES.map((type) => (
                      <SelectItem key={type} value={type}>
                        {type}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="analysisFocus">Analysis Focus</Label>
                <Select value={analysisFocus} onValueChange={setAnalysisFocus} disabled={isAnalyzing}>
                  <SelectTrigger>
                    <SelectValue placeholder="Comprehensive" />
                  </SelectTrigger>
                  <SelectContent>
                    {ANALYSIS_FOCUS.map((focus) => (
                      <SelectItem key={focus} value={focus}>
                        {focus}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>

              {error && (
                <Alert variant="destructive">
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>{error}</AlertDescription>
                </Alert>
              )}

              {isAnalyzing && (
                <div className="space-y-2">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">Analyzing document...</span>
                    <span className="text-sm font-medium">{progress}%</span>
                  </div>
                  <Progress value={progress} />
                </div>
              )}

              <Button 
                onClick={handleAnalyze} 
                disabled={isAnalyzing || !selectedFile}
                className="w-full"
              >
                <Brain className="w-4 h-4 mr-2" />
                {isAnalyzing ? 'Analyzing...' : 'Analyze Document'}
              </Button>
            </CardContent>
          </Card>
        </div>

        {/* Analysis Results */}
        <div className="lg:col-span-2">
          {analysis && (
            <Card>
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Eye className="w-5 h-5" />
                      Analysis Results
                    </CardTitle>
                    <CardDescription>
                      {analysis.fileName} • {analysis.documentType} • {analysis.fileSize}
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge variant="outline">
                      {analysis.summary.wordCount} words
                    </Badge>
                    <Badge variant="outline">
                      {analysis.metadata.confidence}% confidence
                    </Badge>
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="summary" className="w-full">
                  <TabsList className="grid w-full grid-cols-5">
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="insights">Insights</TabsTrigger>
                    <TabsTrigger value="actions">Actions</TabsTrigger>
                    <TabsTrigger value="compliance">Compliance</TabsTrigger>
                    <TabsTrigger value="metadata">Details</TabsTrigger>
                  </TabsList>

                  <TabsContent value="summary" className="space-y-4">
                    <div className="flex items-center justify-between">
                      <h3 className="font-semibold">Executive Summary</h3>
                      <Button variant="outline" size="sm" onClick={downloadReport}>
                        <Download className="w-4 h-4 mr-2" />
                        Download Report
                      </Button>
                    </div>
                    
                    <Card>
                      <CardContent className="pt-6">
                        <p className="leading-relaxed">{analysis.summary.executiveSummary}</p>
                      </CardContent>
                    </Card>

                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Word Count</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-2xl font-bold">{analysis.summary.wordCount.toLocaleString()}</span>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Page Count</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-2xl font-bold">{analysis.summary.pageCount}</span>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Processing Time</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-2xl font-bold">{analysis.metadata.processingTime}</span>
                          <span className="text-sm text-muted-foreground ml-1">ms</span>
                        </CardContent>
                      </Card>
                    </div>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">Key Points</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {analysis.summary.keyPoints.map((point, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-blue-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{point}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm">Main Topics</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex flex-wrap gap-2">
                            {analysis.summary.mainTopics.map((topic, index) => (
                              <Badge key={index} variant="outline">
                                {topic}
                              </Badge>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="insights" className="space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <BarChart3 className="w-5 h-5" />
                      <h3 className="font-semibold">AI Insights</h3>
                    </div>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Sentiment Analysis</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <Badge className={getSentimentColor(analysis.insights.sentiment.label)}>
                                {analysis.insights.sentiment.label}
                              </Badge>
                              <span className="text-sm font-medium">{analysis.insights.sentiment.score}%</span>
                            </div>
                            <Progress value={Math.abs(analysis.insights.sentiment.score)} />
                            <p className="text-xs text-muted-foreground">
                              Confidence: {analysis.insights.sentiment.confidence}%
                            </p>
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Readability</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            <div className="flex items-center justify-between">
                              <span className="text-lg font-bold">{analysis.insights.readability.score}%</span>
                              <Badge variant="outline">{analysis.insights.readability.grade}</Badge>
                            </div>
                            <Progress value={analysis.insights.readability.score} />
                            <p className="text-xs text-muted-foreground">
                              {analysis.insights.readability.difficulty} difficulty
                            </p>
                          </div>
                        </CardContent>
                      </Card>
                    </div>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Topic Analysis</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          {analysis.insights.topics.map((topic, index) => (
                            <div key={index} className="space-y-2">
                              <div className="flex items-center justify-between">
                                <span className="font-medium">{topic.topic}</span>
                                <span className="text-sm text-muted-foreground">{topic.relevance}%</span>
                              </div>
                              <Progress value={topic.relevance} />
                              <div className="flex flex-wrap gap-1">
                                {topic.keywords.map((keyword, i) => (
                                  <Badge key={i} variant="secondary" className="text-xs">
                                    {keyword}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>

                    <Card>
                      <CardHeader>
                        <CardTitle className="text-sm">Named Entities</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          {analysis.insights.entities.map((entity, index) => (
                            <div key={index} className="flex items-center justify-between">
                              <div className="flex items-center gap-2">
                                <span className="font-medium">{entity.text}</span>
                                <Badge variant="outline" className="text-xs">
                                  {entity.type}
                                </Badge>
                              </div>
                              <span className="text-sm text-muted-foreground">
                                {entity.confidence}%
                              </span>
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
                      {analysis.actionItems.map((item, index) => (
                        <Card key={index}>
                          <CardContent className="pt-4">
                            <div className="flex items-start justify-between">
                              <div className="flex-1">
                                <div className="flex items-center gap-2 mb-2">
                                  <Badge className={getPriorityColor(item.priority)}>
                                    {item.priority}
                                  </Badge>
                                  <Badge variant="outline" className="text-xs">
                                    {item.category}
                                  </Badge>
                                  {item.deadline && (
                                    <div className="flex items-center gap-1 text-xs text-muted-foreground">
                                      <Clock className="w-3 h-3" />
                                      {item.deadline}
                                    </div>
                                  )}
                                </div>
                                <p className="text-sm">{item.item}</p>
                              </div>
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="compliance" className="space-y-4">
                    <div className="flex items-center gap-2 mb-4">
                      <AlertTriangle className="w-5 h-5" />
                      <h3 className="font-semibold">Compliance Analysis</h3>
                    </div>
                    
                    <Card>
                      <CardHeader>
                        <div className="flex items-center justify-between">
                          <CardTitle className="text-sm">Risk Assessment</CardTitle>
                          <Badge className={getRiskColor(analysis.compliance.riskLevel)}>
                            {analysis.compliance.riskLevel} risk
                          </Badge>
                        </div>
                      </CardHeader>
                      <CardContent>
                        <p className="text-sm text-muted-foreground">
                          Based on document analysis, compliance risk level has been assessed
                        </p>
                      </CardContent>
                    </Card>

                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm text-red-600">Issues Found</CardTitle>
                        </CardHeader>
                        <CardContent>
                          {analysis.compliance.issues.length > 0 ? (
                            <div className="space-y-2">
                              {analysis.compliance.issues.map((issue, index) => (
                                <div key={index} className="flex items-start gap-2">
                                  <div className="w-2 h-2 bg-red-500 rounded-full mt-2 flex-shrink-0" />
                                  <span className="text-sm">{issue}</span>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <p className="text-sm text-muted-foreground">No compliance issues detected</p>
                          )}
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader>
                          <CardTitle className="text-sm text-green-600">Recommendations</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-2">
                            {analysis.compliance.recommendations.map((recommendation, index) => (
                              <div key={index} className="flex items-start gap-2">
                                <div className="w-2 h-2 bg-green-500 rounded-full mt-2 flex-shrink-0" />
                                <span className="text-sm">{recommendation}</span>
                              </div>
                            ))}
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="metadata" className="space-y-4">
                    <h3 className="font-semibold">Document Metadata</h3>
                    
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Language</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <Badge variant="secondary">{analysis.metadata.language}</Badge>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Analysis Confidence</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center gap-2">
                            <span className="text-lg font-medium">{analysis.metadata.confidence}%</span>
                            <Progress value={analysis.metadata.confidence} className="flex-1" />
                          </div>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Processing Time</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-lg font-medium">{analysis.metadata.processingTime}ms</span>
                        </CardContent>
                      </Card>

                      <Card>
                        <CardHeader className="pb-3">
                          <CardTitle className="text-sm">Analysis Date</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <span className="text-sm">{new Date(analysis.timestamp).toLocaleString()}</span>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          )}

          {!analysis && (
            <Card>
              <CardContent className="py-12 text-center">
                <FileText className="w-12 h-12 mx-auto text-muted-foreground mb-4" />
                <h3 className="text-lg font-semibold mb-2">No Document Analyzed</h3>
                <p className="text-muted-foreground">
                  Upload a document to get comprehensive AI-powered analysis and insights.
                </p>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  )
}
