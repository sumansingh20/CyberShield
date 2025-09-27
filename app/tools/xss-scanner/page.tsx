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
  AlertTriangle, 
  Shield, 
  Zap, 
  Eye,
  Terminal,
  FileSearch,
  Lock,
  Unlock,
  ArrowLeft,
  Play,
  RefreshCw,
  CheckCircle,
  XCircle,
  Code,
  Globe,
  Target
} from 'lucide-react'
import Link from 'next/link'

interface XSSResult {
  targetUrl: string;
  vulnerabilities: {
    parameter: string;
    location: string;
    payload: string;
    type: 'Reflected' | 'Stored' | 'DOM-based';
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    context: string;
    impact: string;
    evidence: string;
    recommendation: string;
  }[];
  payloadsTested: number;
  timeElapsed: string;
  pageAnalysis: {
    forms: number;
    inputs: number;
    urls: number;
    cookies: number;
    jsFiles: number;
  };
  riskScore: number;
  summary: string;
  recommendations: string[];
}

export default function XSSVulnerabilityScannerPage() {
  const [targetUrl, setTargetUrl] = useState('')
  const [scanType, setScanType] = useState('comprehensive')
  const [payloadSet, setPayloadSet] = useState('standard')
  const [customPayloads, setCustomPayloads] = useState('')
  const [scanDepth, setScanDepth] = useState('moderate')
  const [includeHeaders, setIncludeHeaders] = useState(false)
  const [results, setResults] = useState<XSSResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    if (!targetUrl.trim()) {
      setError('Please enter a target URL')
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)
    setProgress(0)

    // Simulate progress
    const progressInterval = setInterval(() => {
      setProgress(prev => Math.min(prev + Math.random() * 8, 90))
    }, 1000)

    try {
      const response = await fetch('/api/tools/xss-scanner', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetUrl: targetUrl.trim(),
          scanType,
          payloadSet,
          customPayloads: customPayloads.trim(),
          scanDepth,
          includeHeaders,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to perform XSS vulnerability scan')
      }

      const data = await response.json()
      
      if (data.success && data.data) {
        setResults(data.data)
      } else {
        throw new Error(data.message || 'XSS vulnerability scan failed')
      }
      setProgress(100)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      clearInterval(progressInterval)
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'bg-red-500 text-white'
      case 'High': return 'bg-orange-500 text-white'
      case 'Medium': return 'bg-yellow-500 text-black'
      case 'Low': return 'bg-blue-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'Reflected': return 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200'
      case 'Stored': return 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
      case 'DOM-based': return 'bg-purple-100 text-purple-800 dark:bg-purple-900 dark:text-purple-200'
      default: return 'bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-orange-900 to-slate-900 p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/tools" className="p-2 hover:bg-white/10 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-white" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">XSS Vulnerability Scanner</h1>
            <p className="text-gray-300">
              Cross-site scripting detection with payload injection testing
            </p>
          </div>
        </div>

        {/* Configuration Form */}
        <Card className="mb-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <AlertTriangle className="w-5 h-5" />
              XSS Scan Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure your cross-site scripting vulnerability assessment
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="targetUrl" className="text-gray-200">Target URL</Label>
                <Input
                  id="targetUrl"
                  placeholder="https://example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="scanType" className="text-gray-200">Scan Type</Label>
                <Select value={scanType} onValueChange={setScanType}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="reflected">Reflected XSS Only</SelectItem>
                    <SelectItem value="stored">Stored XSS Only</SelectItem>
                    <SelectItem value="dom">DOM-based XSS Only</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="payloadSet" className="text-gray-200">Payload Set</Label>
                <Select value={payloadSet} onValueChange={setPayloadSet}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="basic">Basic Payloads</SelectItem>
                    <SelectItem value="standard">Standard Set</SelectItem>
                    <SelectItem value="advanced">Advanced Evasion</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive</SelectItem>
                    <SelectItem value="custom">Custom Payloads</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="scanDepth" className="text-gray-200">Scan Depth</Label>
                <Select value={scanDepth} onValueChange={setScanDepth}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="quick">Quick Scan</SelectItem>
                    <SelectItem value="moderate">Moderate</SelectItem>
                    <SelectItem value="deep">Deep Analysis</SelectItem>
                    <SelectItem value="exhaustive">Exhaustive</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {payloadSet === 'custom' && (
              <div>
                <Label htmlFor="customPayloads" className="text-gray-200">Custom XSS Payloads</Label>
                <Textarea
                  id="customPayloads"
                  placeholder="<script>alert('XSS')</script>&#10;<img src=x onerror=alert(1)>&#10;';alert(String.fromCharCode(88,83,83))//';alert(String.fromCharCode(88,83,83))//&quot;;alert(String.fromCharCode(88,83,83))//&quot;;alert(String.fromCharCode(88,83,83))//--&gt;&lt;/SCRIPT&gt;&quot;&gt;'&gt;&lt;SCRIPT&gt;alert(String.fromCharCode(88,83,83))&lt;/SCRIPT&gt;"
                  value={customPayloads}
                  onChange={(e) => setCustomPayloads(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                  rows={4}
                />
              </div>
            )}

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="includeHeaders"
                checked={includeHeaders}
                onChange={(e) => setIncludeHeaders(e.target.checked)}
                className="rounded"
                aria-label="Include HTTP Headers in XSS Testing"
              />
              <Label htmlFor="includeHeaders" className="text-gray-200">
                Include HTTP Headers in XSS Testing
              </Label>
            </div>

            <Button 
              onClick={handleScan}
              disabled={loading}
              className="w-full bg-orange-600 hover:bg-orange-700"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Scanning for XSS...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Start XSS Vulnerability Scan
                </>
              )}
            </Button>

            {loading && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm text-gray-300">
                  <span>Testing XSS payloads...</span>
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
                  <Target className="w-5 h-5" />
                  XSS Vulnerability Assessment Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-red-400">
                      {results.vulnerabilities.length}
                    </div>
                    <div className="text-sm text-gray-300">XSS Vulnerabilities</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-orange-400">
                      {results.payloadsTested}
                    </div>
                    <div className="text-sm text-gray-300">Payloads Tested</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">
                      {results.riskScore}/100
                    </div>
                    <div className="text-sm text-gray-300">Risk Score</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-400">
                      {results.timeElapsed}
                    </div>
                    <div className="text-sm text-gray-300">Time Elapsed</div>
                  </div>
                </div>

                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-white mb-2">Scan Summary</h3>
                  <p className="text-gray-300">{results.summary}</p>
                </div>

                {/* Page Analysis */}
                <div className="bg-slate-700/30 rounded-lg p-4">
                  <h4 className="font-medium text-white mb-3">Page Analysis</h4>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
                    <div className="text-center">
                      <div className="text-lg font-semibold text-blue-400">{results.pageAnalysis.forms}</div>
                      <div className="text-xs text-gray-400">Forms</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-green-400">{results.pageAnalysis.inputs}</div>
                      <div className="text-xs text-gray-400">Input Fields</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-yellow-400">{results.pageAnalysis.urls}</div>
                      <div className="text-xs text-gray-400">URLs</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-orange-400">{results.pageAnalysis.cookies}</div>
                      <div className="text-xs text-gray-400">Cookies</div>
                    </div>
                    <div className="text-center">
                      <div className="text-lg font-semibold text-purple-400">{results.pageAnalysis.jsFiles}</div>
                      <div className="text-xs text-gray-400">JS Files</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Detailed XSS Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="vulnerabilities" className="space-y-4">
                  <TabsList className="bg-slate-700">
                    <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                    <TabsTrigger value="payloads">Payload Analysis</TabsTrigger>
                    <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                  </TabsList>

                  <TabsContent value="vulnerabilities" className="space-y-4">
                    {results.vulnerabilities.length > 0 ? (
                      results.vulnerabilities.map((vuln, index) => (
                        <Card key={index} className="bg-slate-700/30">
                          <CardHeader className="pb-3">
                            <div className="flex items-center justify-between">
                              <CardTitle className="text-lg text-white">{vuln.type} XSS</CardTitle>
                              <div className="flex gap-2">
                                <Badge className={getTypeColor(vuln.type)}>
                                  {vuln.type}
                                </Badge>
                                <Badge className={getSeverityColor(vuln.severity)}>
                                  {vuln.severity}
                                </Badge>
                              </div>
                            </div>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <div>
                              <span className="text-sm font-medium text-gray-200">Parameter:</span>
                              <code className="ml-2 text-green-400 bg-slate-800 px-2 py-1 rounded text-sm">
                                {vuln.parameter}
                              </code>
                            </div>
                            
                            <div>
                              <span className="text-sm font-medium text-gray-200">Location:</span>
                              <code className="ml-2 text-blue-400 bg-slate-800 px-2 py-1 rounded text-sm">
                                {vuln.location}
                              </code>
                            </div>
                            
                            <div>
                              <span className="text-sm font-medium text-gray-200">Context:</span>
                              <Badge variant="outline" className="ml-2 text-purple-400 border-purple-400">
                                {vuln.context}
                              </Badge>
                            </div>
                            
                            <div>
                              <span className="text-sm font-medium text-gray-200">Payload:</span>
                              <pre className="mt-1 text-xs text-yellow-400 bg-slate-800 p-2 rounded overflow-x-auto">
                                {vuln.payload}
                              </pre>
                            </div>
                            
                            <div>
                              <span className="text-sm font-medium text-gray-200">Evidence:</span>
                              <pre className="mt-1 text-xs text-green-400 bg-slate-800 p-2 rounded overflow-x-auto">
                                {vuln.evidence}
                              </pre>
                            </div>
                            
                            <div>
                              <span className="text-sm font-medium text-gray-200">Impact:</span>
                              <p className="text-gray-300 text-sm mt-1">{vuln.impact}</p>
                            </div>
                            
                            <div>
                              <span className="text-sm font-medium text-gray-200">Recommendation:</span>
                              <p className="text-gray-300 text-sm mt-1">{vuln.recommendation}</p>
                            </div>
                          </CardContent>
                        </Card>
                      ))
                    ) : (
                      <div className="text-center py-8 text-gray-400">
                        <CheckCircle className="w-12 h-12 mx-auto mb-4 text-green-500" />
                        <p>No XSS vulnerabilities detected</p>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="payloads" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Payload Analysis</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-4">
                          <div className="text-center p-4 bg-slate-800/50 rounded-lg">
                            <div className="text-xl font-bold text-orange-400">{results.payloadsTested}</div>
                            <div className="text-sm text-gray-300">Total Payloads Tested</div>
                          </div>
                          
                          <div>
                            <h4 className="font-medium text-gray-200 mb-2">Payload Categories Tested:</h4>
                            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                              <Badge variant="outline" className="text-blue-400 border-blue-400">Script Tags</Badge>
                              <Badge variant="outline" className="text-green-400 border-green-400">Event Handlers</Badge>
                              <Badge variant="outline" className="text-yellow-400 border-yellow-400">JavaScript URIs</Badge>
                              <Badge variant="outline" className="text-purple-400 border-purple-400">HTML Entities</Badge>
                              <Badge variant="outline" className="text-orange-400 border-orange-400">CSS Injection</Badge>
                              <Badge variant="outline" className="text-red-400 border-red-400">DOM Manipulation</Badge>
                            </div>
                          </div>
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
              About XSS Vulnerabilities
            </CardTitle>
          </CardHeader>
          <CardContent className="text-gray-300 space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2 text-white">XSS Types:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• <strong>Reflected:</strong> Payload executed immediately from request</li>
                  <li>• <strong>Stored:</strong> Payload stored and executed for multiple users</li>
                  <li>• <strong>DOM-based:</strong> Client-side DOM manipulation</li>
                  <li>• <strong>Self-XSS:</strong> User executes payload on themselves</li>
                  <li>• <strong>Mutation XSS:</strong> Payload changes after parsing</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-white">Prevention Methods:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Input validation and sanitization</li>
                  <li>• Output encoding/escaping</li>
                  <li>• Content Security Policy (CSP)</li>
                  <li>• HTTP-only cookies for sensitive data</li>
                  <li>• Use secure frameworks and libraries</li>
                </ul>
              </div>
            </div>

            <Alert className="bg-amber-900/20 border-amber-500/50 text-amber-200">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Ethical Use Only:</strong> XSS testing should only be performed on systems you own 
                or have explicit written permission to test. Unauthorized testing is illegal and unethical.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}