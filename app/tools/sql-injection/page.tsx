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
  Database, 
  Shield, 
  AlertTriangle, 
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
  Clock
} from 'lucide-react'
import Link from 'next/link'

interface SQLInjectionResult {
  targetUrl: string;
  vulnerabilities: {
    parameter: string;
    method: string;
    payload: string;
    response: string;
    severity: 'Critical' | 'High' | 'Medium' | 'Low';
    type: string;
    impact: string;
    recommendation: string;
  }[];
  payloadsTested: number;
  timeElapsed: string;
  databaseInfo: {
    type?: string;
    version?: string;
    user?: string;
    database?: string;
    privileges?: string[];
  };
  extractedData: {
    tables?: string[];
    columns?: string[];
    records?: any[];
  };
  riskScore: number;
  summary: string;
  recommendations: string[];
}

export default function SQLInjectionTestingPage() {
  const [targetUrl, setTargetUrl] = useState('')
  const [testMethod, setTestMethod] = useState('GET')
  const [parameters, setParameters] = useState('')
  const [customHeaders, setCustomHeaders] = useState('')
  const [payloadType, setPayloadType] = useState('union-based')
  const [testDepth, setTestDepth] = useState('moderate')
  const [results, setResults] = useState<SQLInjectionResult | null>(null)
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
      setProgress(prev => Math.min(prev + Math.random() * 10, 90))
    }, 1000)

    try {
      const response = await fetch('/api/tools/sql-injection', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetUrl: targetUrl.trim(),
          testMethod: 'GET',
          parameters: parameters.trim(),
          payloadType,
          testDepth: 'basic',
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to perform SQL injection testing')
      }

      const data = await response.json()
      
      if (data.success && data.data) {
        setResults(data.data)
      } else {
        throw new Error(data.message || 'SQL injection testing failed')
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-purple-900 to-slate-900 p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/tools" className="p-2 hover:bg-white/10 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-white" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">SQL Injection Testing</h1>
            <p className="text-gray-300">
              Advanced SQL injection vulnerability scanner with comprehensive payload testing
            </p>
          </div>
        </div>

        {/* Configuration Form */}
        <Card className="mb-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Database className="w-5 h-5" />
              Scan Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure your SQL injection vulnerability assessment
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="targetUrl" className="text-gray-200">Target URL</Label>
                <Input
                  id="targetUrl"
                  placeholder="https://example.com/login.php"
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
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label htmlFor="parameters" className="text-gray-200">Parameters to Test</Label>
              <Textarea
                id="parameters"
                placeholder="id=1&username=admin&password=secret"
                value={parameters}
                onChange={(e) => setParameters(e.target.value)}
                className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                rows={3}
              />
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="payloadType" className="text-gray-200">Payload Type</Label>
                <Select value={payloadType} onValueChange={setPayloadType}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="union-based">UNION-based</SelectItem>
                    <SelectItem value="boolean-blind">Boolean-based blind</SelectItem>
                    <SelectItem value="time-based">Time-based blind</SelectItem>
                    <SelectItem value="error-based">Error-based</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="testDepth" className="text-gray-200">Test Depth</Label>
                <Select value={testDepth} onValueChange={setTestDepth}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="quick">Quick Scan</SelectItem>
                    <SelectItem value="moderate">Moderate</SelectItem>
                    <SelectItem value="deep">Deep Analysis</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div>
              <Label htmlFor="customHeaders" className="text-gray-200">Custom Headers (Optional)</Label>
              <Textarea
                id="customHeaders"
                placeholder="User-Agent: Custom-Agent&#10;X-Forwarded-For: 127.0.0.1"
                value={customHeaders}
                onChange={(e) => setCustomHeaders(e.target.value)}
                className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                rows={2}
              />
            </div>

            <Button 
              onClick={handleScan}
              disabled={loading}
              className="w-full bg-red-600 hover:bg-red-700"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Testing SQL Injection...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Start SQL Injection Test
                </>
              )}
            </Button>

            {loading && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm text-gray-300">
                  <span>Testing payloads...</span>
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
                  Vulnerability Assessment Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-red-400">
                      {results.vulnerabilities.length}
                    </div>
                    <div className="text-sm text-gray-300">Vulnerabilities</div>
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
                  <h3 className="text-lg font-semibold text-white mb-2">Assessment Summary</h3>
                  <p className="text-gray-300">{results.summary}</p>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Detailed Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="vulnerabilities" className="space-y-4">
                  <TabsList className="bg-slate-700">
                    <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                    <TabsTrigger value="database">Database Info</TabsTrigger>
                    <TabsTrigger value="extracted">Extracted Data</TabsTrigger>
                    <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                  </TabsList>

                  <TabsContent value="vulnerabilities" className="space-y-4">
                    {results.vulnerabilities.length > 0 ? (
                      results.vulnerabilities.map((vuln, index) => (
                        <Card key={index} className="bg-slate-700/30">
                          <CardHeader className="pb-3">
                            <div className="flex items-center justify-between">
                              <CardTitle className="text-lg text-white">{vuln.type}</CardTitle>
                              <Badge className={getSeverityColor(vuln.severity)}>
                                {vuln.severity}
                              </Badge>
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
                              <span className="text-sm font-medium text-gray-200">Method:</span>
                              <Badge variant="outline" className="ml-2 text-blue-400 border-blue-400">
                                {vuln.method}
                              </Badge>
                            </div>
                            
                            <div>
                              <span className="text-sm font-medium text-gray-200">Payload:</span>
                              <pre className="mt-1 text-xs text-yellow-400 bg-slate-800 p-2 rounded overflow-x-auto">
                                {vuln.payload}
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
                        <p>No SQL injection vulnerabilities detected</p>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="database" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Database Information</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {results.databaseInfo.type ? (
                          <div className="space-y-3">
                            {results.databaseInfo.type && (
                              <div className="flex justify-between">
                                <span className="text-gray-300">Database Type:</span>
                                <span className="text-green-400">{results.databaseInfo.type}</span>
                              </div>
                            )}
                            {results.databaseInfo.version && (
                              <div className="flex justify-between">
                                <span className="text-gray-300">Version:</span>
                                <span className="text-green-400">{results.databaseInfo.version}</span>
                              </div>
                            )}
                            {results.databaseInfo.user && (
                              <div className="flex justify-between">
                                <span className="text-gray-300">Current User:</span>
                                <span className="text-green-400">{results.databaseInfo.user}</span>
                              </div>
                            )}
                            {results.databaseInfo.database && (
                              <div className="flex justify-between">
                                <span className="text-gray-300">Current Database:</span>
                                <span className="text-green-400">{results.databaseInfo.database}</span>
                              </div>
                            )}
                            {results.databaseInfo.privileges && results.databaseInfo.privileges.length > 0 && (
                              <div>
                                <span className="text-gray-300">Privileges:</span>
                                <div className="flex flex-wrap gap-2 mt-1">
                                  {results.databaseInfo.privileges.map((priv, index) => (
                                    <Badge key={index} variant="outline" className="text-yellow-400 border-yellow-400">
                                      {priv}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ) : (
                          <p className="text-gray-400">No database information extracted</p>
                        )}
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="extracted" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Extracted Data</CardTitle>
                      </CardHeader>
                      <CardContent>
                        {results.extractedData.tables && results.extractedData.tables.length > 0 ? (
                          <div className="space-y-4">
                            <div>
                              <h4 className="font-medium text-gray-200 mb-2">Tables:</h4>
                              <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                {results.extractedData.tables.map((table, index) => (
                                  <Badge key={index} variant="outline" className="text-blue-400 border-blue-400">
                                    {table}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                            
                            {results.extractedData.columns && results.extractedData.columns.length > 0 && (
                              <div>
                                <h4 className="font-medium text-gray-200 mb-2">Columns:</h4>
                                <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                                  {results.extractedData.columns.map((column, index) => (
                                    <Badge key={index} variant="outline" className="text-green-400 border-green-400">
                                      {column}
                                    </Badge>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        ) : (
                          <p className="text-gray-400">No data extracted</p>
                        )}
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
              About SQL Injection Testing
            </CardTitle>
          </CardHeader>
          <CardContent className="text-gray-300 space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2 text-white">Common Injection Types:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• <strong>UNION-based:</strong> Extract data using UNION SELECT</li>
                  <li>• <strong>Boolean-blind:</strong> True/false condition responses</li>
                  <li>• <strong>Time-based:</strong> Delays in response timing</li>
                  <li>• <strong>Error-based:</strong> Database error message exploitation</li>
                  <li>• <strong>Second-order:</strong> Stored payload execution</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-white">Prevention Methods:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Use parameterized queries/prepared statements</li>
                  <li>• Input validation and sanitization</li>
                  <li>• Least privilege database user accounts</li>
                  <li>• Web Application Firewall (WAF)</li>
                  <li>• Regular security code reviews</li>
                </ul>
              </div>
            </div>

            <Alert className="bg-amber-900/20 border-amber-500/50 text-amber-200">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Ethical Use Only:</strong> SQL injection testing should only be performed on systems you own 
                or have explicit written permission to test. Unauthorized testing is illegal and unethical.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}