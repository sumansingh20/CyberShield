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

interface MisinformationRequest {
  content: string
  content_type: 'text' | 'url' | 'social_media_post'
  source_url?: string
  check_sources: boolean
  fact_check_level: 'basic' | 'detailed' | 'comprehensive'
  language: string
}

interface MisinformationAnalysis {
  credibility_score: number
  credibility_level: string
  verdict: 'true' | 'mostly_true' | 'mixed' | 'mostly_false' | 'false' | 'unverified'
  confidence: number
  analysis: {
    factual_accuracy: number
    source_reliability: number
    emotional_manipulation: number
    bias_indicators: number
    logical_consistency: number
  }
  red_flags: Array<{
    type: string
    description: string
    severity: 'low' | 'medium' | 'high'
  }>
  fact_checks: Array<{
    claim: string
    verdict: string
    explanation: string
    sources: string[]
  }>
  source_analysis: {
    primary_sources: number
    secondary_sources: number
    unreliable_sources: number
    missing_sources: number
    source_quality: string
  }
  similar_claims: Array<{
    claim: string
    verdict: string
    source: string
    similarity: number
  }>
  recommendations: string[]
  warning_signs: string[]
  processing_time: number
}

export default function MisinformationDetector() {
  const [request, setRequest] = useState<MisinformationRequest>({
    content: '',
    content_type: 'text',
    source_url: '',
    check_sources: true,
    fact_check_level: 'detailed',
    language: 'en'
  })
  
  const [result, setResult] = useState<MisinformationAnalysis | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const handleAnalyze = async () => {
    if (!request.content.trim()) {
      setError('Please provide content to analyze')
      return
    }

    setLoading(true)
    setError('')
    
    try {
      const response = await fetch('/api/tools/misinformation-detector', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      })

      if (!response.ok) {
        throw new Error('Failed to analyze content for misinformation')
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const getVerdictColor = (verdict: string) => {
    switch (verdict.toLowerCase()) {
      case 'true': return 'bg-green-100 text-green-800'
      case 'mostly_true': return 'bg-green-50 text-green-700'
      case 'mixed': return 'bg-yellow-100 text-yellow-800'
      case 'mostly_false': return 'bg-orange-100 text-orange-800'
      case 'false': return 'bg-red-100 text-red-800'
      case 'unverified': return 'bg-gray-100 text-gray-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'low': return 'bg-yellow-100 text-yellow-800'
      case 'medium': return 'bg-orange-100 text-orange-800'
      case 'high': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getCredibilityIcon = (level: string) => {
    switch (level.toLowerCase()) {
      case 'high': return '✅'
      case 'medium': return '⚠️'
      case 'low': return '❌'
      default: return '❓'
    }
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-2 mb-2">
          🔍 AI Misinformation Detector
        </h1>
        <p className="text-gray-600">
          Advanced AI-powered tool to detect and analyze misinformation, fake news, and misleading content
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              📝 Content Analysis
            </CardTitle>
            <CardDescription>
              Enter content or URL to check for misinformation
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
                <option value="url">Article URL</option>
                <option value="social_media_post">Social Media Post</option>
              </select>
            </div>

            <div>
              <Label htmlFor="content">
                {request.content_type === 'url' ? 'Article URL' : 'Content'}
              </Label>
              {request.content_type === 'url' ? (
                <Input
                  id="content"
                  value={request.content}
                  onChange={(e) => setRequest({...request, content: e.target.value})}
                  placeholder="https://example.com/article"
                />
              ) : (
                <Textarea
                  id="content"
                  value={request.content}
                  onChange={(e) => setRequest({...request, content: e.target.value})}
                  placeholder="Paste the content, article text, or social media post here..."
                  rows={6}
                />
              )}
            </div>

            {request.content_type !== 'url' && (
              <div>
                <Label htmlFor="source-url">Source URL (Optional)</Label>
                <Input
                  id="source-url"
                  value={request.source_url || ''}
                  onChange={(e) => setRequest({...request, source_url: e.target.value})}
                  placeholder="https://example.com/source"
                />
              </div>
            )}

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label htmlFor="fact-check-level">Fact-Check Level</Label>
                <select
                  id="fact-check-level"
                  title="Select fact-check level"
                  className="w-full p-2 border rounded-md"
                  value={request.fact_check_level}
                  onChange={(e) => setRequest({...request, fact_check_level: e.target.value as any})}
                >
                  <option value="basic">Basic Check</option>
                  <option value="detailed">Detailed Analysis</option>
                  <option value="comprehensive">Comprehensive Review</option>
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

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="check-sources"
                title="Enable source checking"
                checked={request.check_sources}
                onChange={(e) => setRequest({...request, check_sources: e.target.checked})}
              />
              <Label htmlFor="check-sources">Verify sources and cross-reference claims</Label>
            </div>

            {error && (
              <Alert>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button 
              onClick={handleAnalyze} 
              disabled={loading}
              className="w-full"
            >
              {loading ? 'Analyzing Content...' : 'Detect Misinformation'}
            </Button>
          </CardContent>
        </Card>

        {result && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                🎯 Analysis Results
              </CardTitle>
              <CardDescription>
                Comprehensive misinformation analysis and fact-checking results
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="analysis">Analysis</TabsTrigger>
                  <TabsTrigger value="facts">Fact Checks</TabsTrigger>
                  <TabsTrigger value="sources">Sources</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <div className="space-y-4">
                    <div className="p-4 border rounded-lg">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="font-semibold">Overall Verdict</h3>
                        <Badge className={getVerdictColor(result.verdict)}>
                          {getCredibilityIcon(result.credibility_level)} {result.verdict.replace('_', ' ').toUpperCase()}
                        </Badge>
                      </div>
                      <div className="flex items-center gap-2 mb-2">
                        <span className="text-sm">Credibility Score:</span>
                        <Progress value={result.credibility_score} className="flex-1" />
                        <span className="font-medium">{result.credibility_score}%</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm">Confidence:</span>
                        <Progress value={result.confidence} className="flex-1" />
                        <span className="font-medium">{result.confidence}%</span>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-3">Red Flags Detected</h4>
                      {result.red_flags.length > 0 ? (
                        <div className="space-y-2">
                          {result.red_flags.map((flag, index) => (
                            <div key={index} className="p-3 border rounded">
                              <div className="flex items-center justify-between mb-1">
                                <span className="font-medium">{flag.type}</span>
                                <Badge className={getSeverityColor(flag.severity)}>
                                  {flag.severity}
                                </Badge>
                              </div>
                              <p className="text-sm text-gray-600">{flag.description}</p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-green-600">✅ No significant red flags detected</p>
                      )}
                    </div>

                    <div>
                      <h4 className="font-semibold mb-2">Warning Signs</h4>
                      {result.warning_signs.length > 0 ? (
                        <ul className="space-y-1">
                          {result.warning_signs.map((sign, index) => (
                            <li key={index} className="text-sm flex items-center gap-2">
                              <span className="text-orange-500">⚠️</span>
                              {sign}
                            </li>
                          ))}
                        </ul>
                      ) : (
                        <p className="text-green-600">✅ No warning signs detected</p>
                      )}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="analysis" className="space-y-4">
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3 border rounded">
                        <h4 className="font-medium mb-2">Factual Accuracy</h4>
                        <Progress value={result.analysis.factual_accuracy} className="mb-1" />
                        <span className="text-sm">{result.analysis.factual_accuracy}%</span>
                      </div>
                      <div className="p-3 border rounded">
                        <h4 className="font-medium mb-2">Source Reliability</h4>
                        <Progress value={result.analysis.source_reliability} className="mb-1" />
                        <span className="text-sm">{result.analysis.source_reliability}%</span>
                      </div>
                      <div className="p-3 border rounded">
                        <h4 className="font-medium mb-2">Emotional Manipulation</h4>
                        <Progress value={result.analysis.emotional_manipulation} className="mb-1" />
                        <span className="text-sm">{result.analysis.emotional_manipulation}%</span>
                      </div>
                      <div className="p-3 border rounded">
                        <h4 className="font-medium mb-2">Bias Indicators</h4>
                        <Progress value={result.analysis.bias_indicators} className="mb-1" />
                        <span className="text-sm">{result.analysis.bias_indicators}%</span>
                      </div>
                      <div className="p-3 border rounded md:col-span-2">
                        <h4 className="font-medium mb-2">Logical Consistency</h4>
                        <Progress value={result.analysis.logical_consistency} className="mb-1" />
                        <span className="text-sm">{result.analysis.logical_consistency}%</span>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-3">Similar Claims Found</h4>
                      {result.similar_claims.length > 0 ? (
                        <div className="space-y-2">
                          {result.similar_claims.map((claim, index) => (
                            <div key={index} className="p-3 border rounded">
                              <div className="flex items-center justify-between mb-2">
                                <Badge className={getVerdictColor(claim.verdict)}>
                                  {claim.verdict}
                                </Badge>
                                <span className="text-xs text-gray-500">
                                  {claim.similarity}% similar
                                </span>
                              </div>
                              <p className="text-sm mb-1">{claim.claim}</p>
                              <p className="text-xs text-gray-600">Source: {claim.source}</p>
                            </div>
                          ))}
                        </div>
                      ) : (
                        <p className="text-gray-600">No similar claims found in database</p>
                      )}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="facts" className="space-y-4">
                  <div className="space-y-3">
                    <h3 className="font-semibold">Fact-Check Results</h3>
                    {result.fact_checks.map((check, index) => (
                      <div key={index} className="p-3 border rounded">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium">Claim {index + 1}</h4>
                          <Badge className={getVerdictColor(check.verdict)}>
                            {check.verdict}
                          </Badge>
                        </div>
                        <p className="text-sm mb-2 font-medium">{check.claim}</p>
                        <p className="text-sm text-gray-600 mb-2">{check.explanation}</p>
                        {check.sources.length > 0 && (
                          <div>
                            <p className="text-xs font-medium mb-1">Sources:</p>
                            <ul className="text-xs space-y-1">
                              {check.sources.map((source, idx) => (
                                <li key={idx} className="text-blue-600">• {source}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="sources" className="space-y-4">
                  <div className="space-y-4">
                    <div className="p-4 border rounded-lg">
                      <h3 className="font-semibold mb-3">Source Quality Analysis</h3>
                      <div className="grid grid-cols-2 gap-4 mb-3">
                        <div className="text-center">
                          <p className="text-2xl font-bold text-green-600">{result.source_analysis.primary_sources}</p>
                          <p className="text-sm text-gray-600">Primary Sources</p>
                        </div>
                        <div className="text-center">
                          <p className="text-2xl font-bold text-blue-600">{result.source_analysis.secondary_sources}</p>
                          <p className="text-sm text-gray-600">Secondary Sources</p>
                        </div>
                        <div className="text-center">
                          <p className="text-2xl font-bold text-red-600">{result.source_analysis.unreliable_sources}</p>
                          <p className="text-sm text-gray-600">Unreliable Sources</p>
                        </div>
                        <div className="text-center">
                          <p className="text-2xl font-bold text-orange-600">{result.source_analysis.missing_sources}</p>
                          <p className="text-sm text-gray-600">Missing Sources</p>
                        </div>
                      </div>
                      <div className="text-center">
                        <Badge className={getLevelColor(result.source_analysis.source_quality)}>
                          Overall Quality: {result.source_analysis.source_quality}
                        </Badge>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-3">Recommendations</h4>
                      <div className="space-y-2">
                        {result.recommendations.map((rec, index) => (
                          <div key={index} className="flex items-center gap-2 p-2 border rounded">
                            <span className="text-blue-500">💡</span>
                            <span className="text-sm">{rec}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="p-3 border rounded text-center">
                      <p className="text-sm text-gray-600">Processing Time</p>
                      <p className="font-semibold">{result.processing_time}ms</p>
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
            🔍 <strong>Disclaimer:</strong> This AI tool provides analysis based on available data and patterns. 
            Always verify important information through multiple reliable sources and use critical thinking. 
            The results should be used as guidance, not absolute truth.
          </AlertDescription>
        </Alert>
      </div>
    </div>
  )

  function getLevelColor(level: string): string {
    switch (level.toLowerCase()) {
      case 'high': case 'good': case 'excellent': return 'bg-green-100 text-green-800'
      case 'medium': case 'moderate': case 'fair': return 'bg-yellow-100 text-yellow-800'
      case 'low': case 'poor': case 'bad': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }
}
