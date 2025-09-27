"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Globe, Shield, Zap, Bug, Search, Target, Activity, Settings, AlertTriangle } from "lucide-react"

interface VulnerabilityFinding {
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  type: string
  url: string
  description: string
  request: string
  response: string
  remediation: string
}

interface ProxyRequest {
  id: string
  method: string
  url: string
  status: number
  length: number
  mimeType: string
  timestamp: string
}

export default function BurpSuitePage() {
  const [targetUrl, setTargetUrl] = useState("")
  const [isScanning, setIsScanning] = useState(false)
  const [scanProgress, setScanProgress] = useState(0)
  const [findings, setFindings] = useState<VulnerabilityFinding[]>([])
  const [proxyHistory, setProxyHistory] = useState<ProxyRequest[]>([])
  const [selectedPayloadType, setSelectedPayloadType] = useState("")
  const [customPayload, setCustomPayload] = useState("")
  const [activeTab, setActiveTab] = useState("scanner")
  const [interceptEnabled, setInterceptEnabled] = useState(false)

  const handleScan = async () => {
    if (!targetUrl) return

    setIsScanning(true)
    setScanProgress(0)
    setFindings([])

    // Simulate scanning progress
    const stages = [
      "Crawling application...",
      "Passive scanning...",
      "Active vulnerability testing...",
      "SQL injection testing...",
      "XSS testing...",
      "CSRF testing...",
      "Authentication bypass...",
      "Generating report..."
    ]

    for (let i = 0; i < stages.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 1500))
      setScanProgress(((i + 1) / stages.length) * 100)
    }

    // Mock vulnerability findings
    const mockFindings: VulnerabilityFinding[] = [
      {
        severity: "Critical",
        type: "SQL Injection",
        url: `${targetUrl}/login.php`,
        description: "SQL injection vulnerability in login parameter allows database access",
        request: "POST /login.php HTTP/1.1\nHost: example.com\nContent-Type: application/x-www-form-urlencoded\n\nusername=admin' OR 1=1--&password=test",
        response: "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>Welcome admin!</html>",
        remediation: "Use parameterized queries and input validation"
      },
      {
        severity: "High",
        type: "Cross-Site Scripting (XSS)",
        url: `${targetUrl}/search.php`,
        description: "Reflected XSS vulnerability in search parameter",
        request: "GET /search.php?q=<script>alert('XSS')</script> HTTP/1.1\nHost: example.com",
        response: "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>Results for: <script>alert('XSS')</script></html>",
        remediation: "Implement proper output encoding and CSP headers"
      },
      {
        severity: "Medium",
        type: "Directory Traversal",
        url: `${targetUrl}/download.php`,
        description: "Path traversal vulnerability allows access to sensitive files",
        request: "GET /download.php?file=../../../etc/passwd HTTP/1.1\nHost: example.com",
        response: "HTTP/1.1 200 OK\nContent-Type: text/plain\n\nroot:x:0:0:root:/root:/bin/bash",
        remediation: "Validate and sanitize file path parameters"
      },
      {
        severity: "Low",
        type: "Information Disclosure",
        url: `${targetUrl}/info.php`,
        description: "PHP configuration information exposed",
        request: "GET /info.php HTTP/1.1\nHost: example.com",
        response: "HTTP/1.1 200 OK\nContent-Type: text/html\n\n<html>PHP Version 7.4.3</html>",
        remediation: "Remove or restrict access to diagnostic pages"
      }
    ]

    // Mock proxy history
    const mockProxyHistory: ProxyRequest[] = [
      {
        id: "1",
        method: "GET",
        url: `${targetUrl}/`,
        status: 200,
        length: 2048,
        mimeType: "text/html",
        timestamp: new Date().toLocaleTimeString()
      },
      {
        id: "2",
        method: "GET",
        url: `${targetUrl}/login.php`,
        status: 200,
        length: 1024,
        mimeType: "text/html",
        timestamp: new Date().toLocaleTimeString()
      },
      {
        id: "3",
        method: "POST",
        url: `${targetUrl}/login.php`,
        status: 302,
        length: 512,
        mimeType: "text/html",
        timestamp: new Date().toLocaleTimeString()
      }
    ]

    setFindings(mockFindings)
    setProxyHistory(mockProxyHistory)
    setIsScanning(false)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "text-red-700 bg-red-100 border-red-200"
      case "High": return "text-orange-700 bg-orange-100 border-orange-200"
      case "Medium": return "text-yellow-700 bg-yellow-100 border-yellow-200"
      case "Low": return "text-blue-700 bg-blue-100 border-blue-200"
      default: return "text-gray-700 bg-gray-100 border-gray-200"
    }
  }

  const getSeverityCount = (severity: string) => {
    return findings.filter(f => f.severity === severity).length
  }

  const payloadTypes = [
    { value: "xss", label: "Cross-Site Scripting" },
    { value: "sqli", label: "SQL Injection" },
    { value: "lfi", label: "Local File Inclusion" },
    { value: "rfi", label: "Remote File Inclusion" },
    { value: "cmd", label: "Command Injection" },
    { value: "xxe", label: "XML External Entity" }
  ]

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-orange-50 to-red-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 p-4">
      <div className="container mx-auto max-w-7xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-3">
            <div className="p-3 rounded-xl bg-gradient-to-br from-orange-600 to-red-600 text-white shadow-xl">
              <Bug className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-orange-600 to-red-600 bg-clip-text text-transparent">
                Burp Suite Professional
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Advanced web application security testing platform
              </p>
            </div>
          </div>
          
          <div className="flex items-center justify-center space-x-4">
            <Badge className="bg-orange-500/10 text-orange-600 border-orange-200 dark:border-orange-800">
              <Target className="w-3 h-3 mr-1" />
              Expert Level
            </Badge>
            <Badge className="bg-red-500/10 text-red-600 border-red-200 dark:border-red-800">
              <Bug className="w-3 h-3 mr-1" />
              Web App Testing
            </Badge>
          </div>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="scanner">Scanner</TabsTrigger>
            <TabsTrigger value="proxy">Proxy</TabsTrigger>
            <TabsTrigger value="intruder">Intruder</TabsTrigger>
            <TabsTrigger value="repeater">Repeater</TabsTrigger>
            <TabsTrigger value="findings">Findings</TabsTrigger>
          </TabsList>

          <TabsContent value="scanner" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Scanner Configuration */}
              <div className="lg:col-span-1">
                <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Search className="h-5 w-5" />
                      Web App Scanner
                    </CardTitle>
                    <CardDescription>
                      Automated vulnerability scanning
                    </CardDescription>
                  </CardHeader>
                  <CardContent className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="target-url">Target URL</Label>
                      <Input
                        id="target-url"
                        value={targetUrl}
                        onChange={(e) => setTargetUrl(e.target.value)}
                        placeholder="https://example.com"
                        disabled={isScanning}
                      />
                    </div>

                    <Button 
                      onClick={handleScan} 
                      disabled={!targetUrl || isScanning}
                      className="w-full"
                    >
                      {isScanning ? (
                        <>
                          <Activity className="mr-2 h-4 w-4 animate-spin" />
                          Scanning...
                        </>
                      ) : (
                        <>
                          <Search className="mr-2 h-4 w-4" />
                          Start Security Scan
                        </>
                      )}
                    </Button>

                    {isScanning && (
                      <div className="space-y-2">
                        <Progress value={scanProgress} className="w-full" />
                        <p className="text-sm text-center">{Math.round(scanProgress)}%</p>
                      </div>
                    )}

                    {findings.length > 0 && (
                      <div className="space-y-2">
                        <h3 className="font-semibold">Vulnerability Summary</h3>
                        <div className="grid grid-cols-2 gap-2 text-sm">
                          <div className="text-center p-2 bg-red-100 rounded">
                            <div className="font-bold text-red-700">{getSeverityCount("Critical")}</div>
                            <div className="text-red-600">Critical</div>
                          </div>
                          <div className="text-center p-2 bg-orange-100 rounded">
                            <div className="font-bold text-orange-700">{getSeverityCount("High")}</div>
                            <div className="text-orange-600">High</div>
                          </div>
                          <div className="text-center p-2 bg-yellow-100 rounded">
                            <div className="font-bold text-yellow-700">{getSeverityCount("Medium")}</div>
                            <div className="text-yellow-600">Medium</div>
                          </div>
                          <div className="text-center p-2 bg-blue-100 rounded">
                            <div className="font-bold text-blue-700">{getSeverityCount("Low")}</div>
                            <div className="text-blue-600">Low</div>
                          </div>
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>

              {/* Scanner Results */}
              <div className="lg:col-span-2">
                <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Activity className="h-5 w-5" />
                      Scanner Activity
                    </CardTitle>
                    <CardDescription>
                      Real-time scanning progress and results
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    {findings.length > 0 ? (
                      <div className="space-y-3 max-h-96 overflow-y-auto">
                        {findings.slice(0, 3).map((finding, index) => (
                          <div key={index} className="p-4 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-center space-x-2">
                                <AlertTriangle className="h-4 w-4 text-red-500" />
                                <span className="font-semibold">{finding.type}</span>
                              </div>
                              <Badge className={getSeverityColor(finding.severity)}>
                                {finding.severity}
                              </Badge>
                            </div>
                            <div className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                              <strong>URL:</strong> {finding.url}
                            </div>
                            <div className="text-sm text-gray-700 dark:text-gray-300 mb-3">
                              {finding.description}
                            </div>
                            <div className="text-sm bg-blue-50 dark:bg-blue-900/20 p-2 rounded">
                              <strong className="text-blue-700 dark:text-blue-300">Remediation:</strong>
                              <p className="text-blue-600 dark:text-blue-400 mt-1">{finding.remediation}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-12 text-gray-500">
                        <Search className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>No scan results yet.</p>
                        <p className="text-sm">Enter a target URL and start scanning to find vulnerabilities.</p>
                      </div>
                    )}
                  </CardContent>
                </Card>
              </div>
            </div>
          </TabsContent>

          <TabsContent value="proxy" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Globe className="h-5 w-5" />
                  HTTP Proxy
                </CardTitle>
                <CardDescription>
                  Intercept and modify HTTP traffic
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center space-x-4">
                  <Button
                    variant={interceptEnabled ? "destructive" : "default"}
                    onClick={() => setInterceptEnabled(!interceptEnabled)}
                  >
                    {interceptEnabled ? "Stop Intercept" : "Start Intercept"}
                  </Button>
                  <Badge className={interceptEnabled ? "bg-red-100 text-red-700" : "bg-green-100 text-green-700"}>
                    {interceptEnabled ? "Intercepting" : "Passthrough"}
                  </Badge>
                </div>

                {proxyHistory.length > 0 && (
                  <div className="space-y-3">
                    <h3 className="font-semibold">Proxy History</h3>
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {proxyHistory.map((request) => (
                        <div key={request.id} className="p-3 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                          <div className="flex items-center justify-between text-sm">
                            <div className="flex items-center space-x-2">
                              <Badge variant="outline">{request.method}</Badge>
                              <span className="font-mono">{request.url}</span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Badge className={request.status < 400 ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}>
                                {request.status}
                              </Badge>
                              <span className="text-gray-500">{request.length} bytes</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="intruder" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Burp Intruder
                </CardTitle>
                <CardDescription>
                  Automated customized attacks
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="payload-type">Payload Type</Label>
                  <Select value={selectedPayloadType} onValueChange={setSelectedPayloadType}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select payload type..." />
                    </SelectTrigger>
                    <SelectContent>
                      {payloadTypes.map((type) => (
                        <SelectItem key={type.value} value={type.value}>
                          {type.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="custom-payload">Custom Payloads</Label>
                  <Textarea
                    id="custom-payload"
                    value={customPayload}
                    onChange={(e) => setCustomPayload(e.target.value)}
                    placeholder="Enter custom payloads (one per line)..."
                    rows={6}
                  />
                </div>

                <Button disabled className="w-full">
                  <Zap className="mr-2 h-4 w-4" />
                  Configure Attack (Pro Feature)
                </Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="repeater" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Settings className="h-5 w-5" />
                  Burp Repeater
                </CardTitle>
                <CardDescription>
                  Manual request modification and testing
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8 text-gray-500">
                  <Settings className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>HTTP Request/Response Editor</p>
                  <p className="text-sm">Manually craft and test HTTP requests</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="findings" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Bug className="h-5 w-5" />
                  Security Findings
                </CardTitle>
                <CardDescription>
                  Detailed vulnerability analysis and remediation
                </CardDescription>
              </CardHeader>
              <CardContent>
                {findings.length > 0 ? (
                  <div className="space-y-4">
                    {findings.map((finding, index) => (
                      <div key={index} className="p-4 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center space-x-2">
                            <AlertTriangle className="h-5 w-5 text-red-500" />
                            <span className="text-lg font-semibold">{finding.type}</span>
                          </div>
                          <Badge className={getSeverityColor(finding.severity)}>
                            {finding.severity}
                          </Badge>
                        </div>

                        <div className="space-y-3">
                          <div>
                            <h4 className="font-semibold text-sm mb-1">URL:</h4>
                            <p className="text-sm font-mono bg-gray-100 dark:bg-gray-800 p-2 rounded">
                              {finding.url}
                            </p>
                          </div>

                          <div>
                            <h4 className="font-semibold text-sm mb-1">Description:</h4>
                            <p className="text-sm text-gray-700 dark:text-gray-300">
                              {finding.description}
                            </p>
                          </div>

                          <div>
                            <h4 className="font-semibold text-sm mb-1">Request:</h4>
                            <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded overflow-x-auto">
                              {finding.request}
                            </pre>
                          </div>

                          <div>
                            <h4 className="font-semibold text-sm mb-1">Response:</h4>
                            <pre className="text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded overflow-x-auto">
                              {finding.response}
                            </pre>
                          </div>

                          <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded">
                            <h4 className="font-semibold text-sm text-blue-700 dark:text-blue-300 mb-1">
                              Remediation:
                            </h4>
                            <p className="text-sm text-blue-600 dark:text-blue-400">
                              {finding.remediation}
                            </p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12 text-gray-500">
                    <Bug className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No vulnerabilities found yet.</p>
                    <p className="text-sm">Run a security scan to discover potential vulnerabilities.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}