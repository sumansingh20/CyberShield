"use client"

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Input } from '@/src/ui/components/ui/input'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Badge } from '@/src/ui/components/ui/badge'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Shield, Mail, Link, AlertTriangle, CheckCircle, Eye, Brain } from 'lucide-react'
import { TerminalOutput } from '@/components/TerminalOutput'

interface PhishingResult {
  isPhishing: boolean
  confidence: number
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  reasons: string[]
  aiAnalysis: {
    suspiciousPatterns: string[]
    legitimateIndicators: string[]
    domainAnalysis: {
      reputation: string
      age: string
      registrar: string
    }
    contentAnalysis: {
      urgencyWords: string[]
      socialEngineering: string[]
      typos: string[]
    }
  }
}

export default function AIPhishingDetector() {
  const [inputType, setInputType] = useState<'email' | 'url'>('email')
  const [emailContent, setEmailContent] = useState('')
  const [url, setUrl] = useState('')
  const [result, setResult] = useState<PhishingResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [terminalOutput, setTerminalOutput] = useState<string[]>([])

  const handleAnalyze = async () => {
    if ((!emailContent.trim() && inputType === 'email') || (!url.trim() && inputType === 'url')) {
      setError('Please provide content to analyze')
      return
    }

    setLoading(true)
    setError('')
    setResult(null)
    setTerminalOutput([])

    const addToTerminal = (message: string) => {
      setTerminalOutput(prev => [...prev, message])
    }

    try {
      addToTerminal('🤖 Starting AI-powered phishing analysis...')
      addToTerminal(`📧 Input Type: ${inputType.toUpperCase()}`)
      
      const payload = inputType === 'email' 
        ? { type: 'email', content: emailContent }
        : { type: 'url', content: url }

      addToTerminal('🔍 Analyzing content patterns...')
      addToTerminal('🧠 Running machine learning models...')
      addToTerminal('🌐 Checking domain reputation...')
      
      const response = await fetch('/api/tools/ai-phishing-detector', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to analyze content')
      }

      addToTerminal('✅ Analysis complete!')
      addToTerminal(`🎯 Risk Level: ${data.riskLevel}`)
      addToTerminal(`📊 Confidence: ${data.confidence}%`)
      
      setResult(data)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Analysis failed'
      setError(errorMessage)
      addToTerminal(`❌ Error: ${errorMessage}`)
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'LOW': return 'bg-green-500'
      case 'MEDIUM': return 'bg-yellow-500'
      case 'HIGH': return 'bg-orange-500'
      case 'CRITICAL': return 'bg-red-500'
      default: return 'bg-gray-500'
    }
  }

  const getRiskIcon = (level: string) => {
    switch (level) {
      case 'LOW': return <CheckCircle className="h-4 w-4" />
      case 'MEDIUM': return <Eye className="h-4 w-4" />
      case 'HIGH': return <AlertTriangle className="h-4 w-4" />
      case 'CRITICAL': return <Shield className="h-4 w-4" />
      default: return <Shield className="h-4 w-4" />
    }
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <Brain className="h-8 w-8 text-primary" />
          <h1 className="text-3xl font-bold">AI Phishing Detector</h1>
        </div>
        <p className="text-muted-foreground">
          Advanced AI-powered tool to detect phishing emails and malicious URLs using machine learning models
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Section */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Content Analysis
            </CardTitle>
            <CardDescription>
              Upload email content or URL for AI-powered phishing detection
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Tabs value={inputType} onValueChange={(value) => setInputType(value as 'email' | 'url')}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="email" className="flex items-center gap-2">
                  <Mail className="h-4 w-4" />
                  Email Content
                </TabsTrigger>
                <TabsTrigger value="url" className="flex items-center gap-2">
                  <Link className="h-4 w-4" />
                  URL Analysis
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="email" className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Email Content</label>
                  <Textarea
                    placeholder="Paste the complete email content here including headers, body, and any links..."
                    value={emailContent}
                    onChange={(e) => setEmailContent(e.target.value)}
                    rows={8}
                    className="min-h-[200px]"
                  />
                </div>
              </TabsContent>
              
              <TabsContent value="url" className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">URL to Analyze</label>
                  <Input
                    placeholder="https://suspicious-website.com"
                    value={url}
                    onChange={(e) => setUrl(e.target.value)}
                    type="url"
                  />
                </div>
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Never visit suspicious URLs directly. Our AI will analyze the URL safely.
                  </AlertDescription>
                </Alert>
              </TabsContent>
            </Tabs>

            {error && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button 
              onClick={handleAnalyze} 
              disabled={loading}
              className="w-full"
              size="lg"
            >
              {loading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Analyzing...
                </>
              ) : (
                <>
                  <Brain className="h-4 w-4 mr-2" />
                  Analyze with AI
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Terminal Output */}
        <Card>
          <CardHeader>
            <CardTitle>Analysis Process</CardTitle>
            <CardDescription>Real-time AI analysis progress</CardDescription>
          </CardHeader>
          <CardContent>
            <TerminalOutput 
              output={terminalOutput.join('\n')} 
              isLoading={loading}
              title="Analysis Process"
            />
          </CardContent>
        </Card>
      </div>

      {/* Results Section */}
      {result && (
        <div className="mt-8 space-y-6">
          {/* Main Result */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {getRiskIcon(result.riskLevel)}
                Analysis Results
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold mb-2">
                    {result.isPhishing ? '🚨 PHISHING' : '✅ LEGITIMATE'}
                  </div>
                  <p className="text-sm text-muted-foreground">Classification</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold mb-2">{result.confidence}%</div>
                  <p className="text-sm text-muted-foreground">Confidence</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <Badge className={`${getRiskColor(result.riskLevel)} text-white`}>
                    {result.riskLevel} RISK
                  </Badge>
                  <p className="text-sm text-muted-foreground mt-2">Risk Level</p>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Key Findings:</h4>
                  <ul className="list-disc list-inside space-y-1">
                    {result.reasons.map((reason, index) => (
                      <li key={index} className="text-sm">{reason}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Detailed AI Analysis */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Suspicious Patterns</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {result.aiAnalysis.suspiciousPatterns.map((pattern, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 text-orange-500 mt-0.5" />
                      <span className="text-sm">{pattern}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Legitimate Indicators</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {result.aiAnalysis.legitimateIndicators.map((indicator, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <CheckCircle className="h-4 w-4 text-green-500 mt-0.5" />
                      <span className="text-sm">{indicator}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Content Analysis Details */}
          <Card>
            <CardHeader>
              <CardTitle>AI Content Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="social" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="social">Social Engineering</TabsTrigger>
                  <TabsTrigger value="urgency">Urgency Words</TabsTrigger>
                  <TabsTrigger value="typos">Typos & Errors</TabsTrigger>
                </TabsList>
                
                <TabsContent value="social" className="mt-4">
                  <div className="space-y-2">
                    {result.aiAnalysis.contentAnalysis.socialEngineering.map((item, index) => (
                      <Badge key={index} variant="outline" className="mr-2 mb-2">
                        {item}
                      </Badge>
                    ))}
                  </div>
                </TabsContent>
                
                <TabsContent value="urgency" className="mt-4">
                  <div className="space-y-2">
                    {result.aiAnalysis.contentAnalysis.urgencyWords.map((word, index) => (
                      <Badge key={index} variant="outline" className="mr-2 mb-2">
                        {word}
                      </Badge>
                    ))}
                  </div>
                </TabsContent>
                
                <TabsContent value="typos" className="mt-4">
                  <div className="space-y-2">
                    {result.aiAnalysis.contentAnalysis.typos.map((typo, index) => (
                      <Badge key={index} variant="outline" className="mr-2 mb-2">
                        {typo}
                      </Badge>
                    ))}
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        </div>
      )}
    </div>
  )
}
