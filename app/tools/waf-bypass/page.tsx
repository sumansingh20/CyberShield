"use client"

import React, { useState } from 'react'
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Alert, AlertDescription } from "@/src/ui/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { 
  Shield, 
  Lock,
  Unlock,
  AlertTriangle, 
  Zap, 
  Eye,
  Terminal,
  FileSearch,
  ArrowLeft,
  Play,
  RefreshCw,
  CheckCircle,
  XCircle,
  Code,
  Globe,
  Target,
  Filter
} from 'lucide-react'
import Link from 'next/link'

interface WAFBypassResult {
  targetUrl: string;
  wafDetected: {
    detected: boolean;
    wafType?: string;
    confidence: number;
    fingerprints: string[];
  };
  bypassTechniques: {
    technique: string;
    payload: string;
    success: boolean;
    response: {
      status: number;
      blocked: boolean;
      evidence: string;
    };
    description: string;
  }[];
  payloadsGenerated: number;
  successfulBypasses: number;
  timeElapsed: string;
  encodingMethods: string[];
  recommendations: string[];
  summary: string;
}

export default function WAFBypassToolPage() {
  const [targetUrl, setTargetUrl] = useState('')
  const [payload, setPayload] = useState('')
  const [bypassType, setBypassType] = useState('comprehensive')
  const [encodingTypes, setEncodingTypes] = useState(['url', 'html', 'double'])
  const [customHeaders, setCustomHeaders] = useState('')
  const [testMethod, setTestMethod] = useState('GET')
  const [results, setResults] = useState<WAFBypassResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    if (!targetUrl.trim()) {
      setError('Please enter a target URL')
      return
    }
    if (!payload.trim()) {
      setError('Please enter a payload to test')
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)
    setProgress(0)

    // Simulate progress
    const progressInterval = setInterval(() => {
      setProgress(prev => Math.min(prev + Math.random() * 12, 90))
    }, 1000)

    try {
      const response = await fetch('/api/tools/waf-bypass', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetUrl: targetUrl.trim(),
          payload: payload.trim(),
          bypassType,
          wafType: 'auto-detect',
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to perform WAF bypass testing')
      }

      const data = await response.json()
      setResults(data)
      setProgress(100)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      clearInterval(progressInterval)
      setLoading(false)
    }
  }

  const handleEncodingToggle = (encoding: string) => {
    setEncodingTypes(prev => 
      prev.includes(encoding) 
        ? prev.filter(e => e !== encoding)
        : [...prev, encoding]
    )
  }

  const getBypassStatusColor = (success: boolean) => {
    return success ? 'text-green-400' : 'text-red-400'
  }

  const getBypassStatusIcon = (success: boolean) => {
    return success ? <CheckCircle className="w-4 h-4" /> : <XCircle className="w-4 h-4" />
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/tools" className="p-2 hover:bg-white/10 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-white" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">WAF Bypass Tool</h1>
            <p className="text-gray-300">
              Web Application Firewall bypass techniques and payload encoding
            </p>
          </div>
        </div>

        {/* Configuration Form */}
        <Card className="mb-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Filter className="w-5 h-5" />
              WAF Bypass Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure WAF bypass testing with various encoding techniques
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="targetUrl" className="text-gray-200">Target URL</Label>
                <Input
                  id="targetUrl"
                  placeholder="https://example.com/search"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="testMethod" className="text-gray-200">HTTP Method</Label>
                <Select value={testMethod} onValueChange={setTestMethod}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="GET">GET</SelectItem>
                    <SelectItem value="POST">POST</SelectItem>
                    <SelectItem value="PUT">PUT</SelectItem>
                    <SelectItem value="DELETE">DELETE</SelectItem>
                    <SelectItem value="PATCH">PATCH</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label htmlFor="payload" className="text-gray-200">Test Payload</Label>
              <Textarea
                id="payload"
                placeholder="<script>alert('XSS')</script>&#10;' UNION SELECT 1,2,3--&#10;../../../etc/passwd&#10;{{7*7}}"
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                rows={4}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="bypassType" className="text-gray-200">Bypass Strategy</Label>
              <Select value={bypassType} onValueChange={setBypassType}>
                <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-700 border-slate-600">
                  <SelectItem value="encoding">Encoding-based</SelectItem>
                  <SelectItem value="obfuscation">Obfuscation</SelectItem>
                  <SelectItem value="fragmentation">Fragmentation</SelectItem>
                  <SelectItem value="case-variation">Case Variation</SelectItem>
                  <SelectItem value="comprehensive">Comprehensive</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-gray-200 mb-2 block">Encoding Methods</Label>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {[
                  { id: 'url', label: 'URL Encoding' },
                  { id: 'html', label: 'HTML Entities' },
                  { id: 'double', label: 'Double Encoding' },
                  { id: 'unicode', label: 'Unicode' },
                  { id: 'hex', label: 'Hexadecimal' },
                  { id: 'base64', label: 'Base64' },
                  { id: 'mixed', label: 'Mixed Case' },
                  { id: 'null-byte', label: 'Null Bytes' }
                ].map((encoding) => (
                  <div key={encoding.id} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id={encoding.id}
                      checked={encodingTypes.includes(encoding.id)}
                      onChange={() => handleEncodingToggle(encoding.id)}
                      className="rounded"
                      aria-label={encoding.label}
                    />
                    <Label 
                      htmlFor={encoding.id} 
                      className="text-gray-300 text-sm cursor-pointer"
                    >
                      {encoding.label}
                    </Label>
                  </div>
                ))}
              </div>
            </div>

            <div>
              <Label htmlFor="customHeaders" className="text-gray-200">Custom Headers (Optional)</Label>
              <Textarea
                id="customHeaders"
                placeholder="X-Originating-IP: 127.0.0.1&#10;X-Forwarded-For: 127.0.0.1&#10;X-Remote-IP: 127.0.0.1"
                value={customHeaders}
                onChange={(e) => setCustomHeaders(e.target.value)}
                className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                rows={3}
              />
            </div>

            <Button 
              onClick={handleScan}
              disabled={loading}
              className="w-full bg-purple-600 hover:bg-purple-700"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Testing WAF Bypasses...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Start WAF Bypass Test
                </>
              )}
            </Button>

            {loading && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm text-gray-300">
                  <span>Testing bypass techniques...</span>
                  <span>{Math.round(progress)}%</span>
                </div>
                <Progress value={progress} className="bg-slate-600" />
              </div>
            )}
          </CardContent>
        </Card>

        {/* Error Display */}
        {error && (
          <Alert className="mb-6 bg-red-900/50 border-red-500 text-red-200">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Results */}
        {results && (
          <div className="space-y-6">
            {/* Summary Card */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-white">
                  <Shield className="w-5 h-5" />
                  WAF Bypass Analysis Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-green-400">
                      {results.successfulBypasses}
                    </div>
                    <div className="text-sm text-gray-300">Successful Bypasses</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-400">
                      {results.payloadsGenerated}
                    </div>
                    <div className="text-sm text-gray-300">Payloads Generated</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">
                      {results.encodingMethods.length}
                    </div>
                    <div className="text-sm text-gray-300">Encoding Methods</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-orange-400">
                      {results.timeElapsed}
                    </div>
                    <div className="text-sm text-gray-300">Time Elapsed</div>
                  </div>
                </div>

                {/* WAF Detection */}
                <div className="mb-6 p-4 bg-slate-700/30 rounded-lg">
                  <h3 className="text-lg font-semibold text-white mb-3">WAF Detection</h3>
                  {results.wafDetected.detected ? (
                    <div className="space-y-2">
                      <div className="flex items-center gap-2">
                        <Shield className="w-5 h-5 text-red-400" />
                        <span className="text-red-400 font-medium">WAF Detected</span>
                        {results.wafDetected.wafType && (
                          <Badge className="bg-red-500/20 text-red-400 border border-red-500">
                            {results.wafDetected.wafType}
                          </Badge>
                        )}
                      </div>
                      <div className="text-sm text-gray-300">
                        Confidence: {results.wafDetected.confidence}%
                      </div>
                      <div>
                        <span className="text-sm font-medium text-gray-200">Fingerprints:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {results.wafDetected.fingerprints.map((fp, index) => (
                            <Badge key={index} variant="outline" className="text-yellow-400 border-yellow-400 text-xs">
                              {fp}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    </div>
                  ) : (
                    <div className="flex items-center gap-2">
                      <Unlock className="w-5 h-5 text-green-400" />
                      <span className="text-green-400">No WAF detected</span>
                    </div>
                  )}
                </div>

                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-white mb-2">Analysis Summary</h3>
                  <p className="text-gray-300">{results.summary}</p>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Bypass Techniques Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="techniques" className="space-y-4">
                  <TabsList className="bg-slate-700">
                    <TabsTrigger value="techniques">Bypass Techniques</TabsTrigger>
                    <TabsTrigger value="encoding">Encoding Methods</TabsTrigger>
                    <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                  </TabsList>

                  <TabsContent value="techniques" className="space-y-4">
                    {results.bypassTechniques.length > 0 ? (
                      results.bypassTechniques.map((technique, index) => (
                        <Card key={index} className="bg-slate-700/30">
                          <CardHeader className="pb-3">
                            <div className="flex items-center justify-between">
                              <CardTitle className="text-lg text-white">{technique.technique}</CardTitle>
                              <div className="flex items-center gap-2">
                                <span className={getBypassStatusColor(technique.success)}>
                                  {getBypassStatusIcon(technique.success)}
                                </span>
                                <Badge className={technique.success ? 'bg-green-500 text-white' : 'bg-red-500 text-white'}>
                                  {technique.success ? 'Success' : 'Blocked'}
                                </Badge>
                              </div>
                            </div>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <div>
                              <span className="text-sm font-medium text-gray-200">Description:</span>
                              <p className="text-gray-300 text-sm mt-1">{technique.description}</p>
                            </div>
                            
                            <div>
                              <span className="text-sm font-medium text-gray-200">Encoded Payload:</span>
                              <pre className="mt-1 text-xs text-green-400 bg-slate-800 p-2 rounded overflow-x-auto">
                                {technique.payload}
                              </pre>
                            </div>
                            
                            <div className="grid md:grid-cols-2 gap-4">
                              <div>
                                <span className="text-sm font-medium text-gray-200">Response Status:</span>
                                <Badge variant="outline" className="ml-2 text-blue-400 border-blue-400">
                                  {technique.response.status}
                                </Badge>
                              </div>
                              <div>
                                <span className="text-sm font-medium text-gray-200">Blocked:</span>
                                <span className={`ml-2 text-sm ${technique.response.blocked ? 'text-red-400' : 'text-green-400'}`}>
                                  {technique.response.blocked ? 'Yes' : 'No'}
                                </span>
                              </div>
                            </div>
                            
                            {technique.response.evidence && (
                              <div>
                                <span className="text-sm font-medium text-gray-200">Evidence:</span>
                                <pre className="mt-1 text-xs text-yellow-400 bg-slate-800 p-2 rounded overflow-x-auto">
                                  {technique.response.evidence}
                                </pre>
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      ))
                    ) : (
                      <div className="text-center py-8 text-gray-400">
                        <XCircle className="w-12 h-12 mx-auto mb-4 text-red-500" />
                        <p>No bypass techniques tested</p>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="encoding" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Encoding Methods Used</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                          {results.encodingMethods.map((method, index) => (
                            <Badge key={index} variant="outline" className="text-purple-400 border-purple-400">
                              {method}
                            </Badge>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="recommendations" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Security Recommendations</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="space-y-3">
                          {results.recommendations.map((rec, index) => (
                            <li key={index} className="flex items-start gap-2">
                              <Shield className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
                              <span className="text-gray-300">{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Educational Information */}
        <Card className="mt-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Terminal className="w-5 h-5" />
              About WAF Bypass Techniques
            </CardTitle>
          </CardHeader>
          <CardContent className="text-gray-300 space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2 text-white">Common Bypass Methods:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• <strong>Encoding:</strong> URL, HTML, Unicode, Base64</li>
                  <li>• <strong>Obfuscation:</strong> String concatenation, comments</li>
                  <li>• <strong>Case Variation:</strong> Mixed upper/lowercase</li>
                  <li>• <strong>Fragmentation:</strong> Splitting payloads</li>
                  <li>• <strong>Protocol Manipulation:</strong> HTTP method override</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-white">WAF Strengthening:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Regular rule updates and tuning</li>
                  <li>• Multiple encoding detection</li>
                  <li>• Behavioral analysis integration</li>
                  <li>• Rate limiting and IP reputation</li>
                  <li>• Deep packet inspection</li>
                </ul>
              </div>
            </div>

            <Alert className="bg-amber-900/20 border-amber-500/50 text-amber-200">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Ethical Use Only:</strong> WAF bypass testing should only be performed on systems you own 
                or have explicit written permission to test. Use this knowledge to improve your own security defenses.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}