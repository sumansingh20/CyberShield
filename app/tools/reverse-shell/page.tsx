"use client"

import React, { useState } from 'react'
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Badge } from "@/src/ui/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Alert, AlertDescription } from "@/src/ui/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { 
  Terminal, 
  Code,
  Copy,
  Download,
  AlertTriangle, 
  Zap, 
  Eye,
  Server,
  ArrowLeft,
  Play,
  CheckCircle,
  Globe,
  Shield,
  Settings,
  FileCode
} from 'lucide-react'
import Link from 'next/link'

interface ReverseShellResult {
  platform: string;
  payloads: {
    language: string;
    name: string;
    payload: string;
    description: string;
    encoded?: {
      base64?: string;
      url?: string;
      powershell?: string;
    };
  }[];
  listenerCommands: {
    tool: string;
    command: string;
    description: string;
  }[];
  obfuscatedVersions: {
    method: string;
    payload: string;
    description: string;
  }[];
  encodingMethods: string[];
  recommendations: string[];
  summary: string;
}

export default function ReverseShellGeneratorPage() {
  const [targetIP, setTargetIP] = useState('')
  const [targetPort, setTargetPort] = useState('4444')
  const [platform, setPlatform] = useState('linux')
  const [shellTypes, setShellTypes] = useState(['bash', 'netcat', 'python'])
  const [includeObfuscation, setIncludeObfuscation] = useState(true)
  const [includeEncoding, setIncludeEncoding] = useState(true)
  const [results, setResults] = useState<ReverseShellResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleGenerate = async () => {
    if (!targetIP.trim()) {
      setError('Please enter a target IP address')
      return
    }
    if (!targetPort.trim()) {
      setError('Please enter a target port')
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const response = await fetch('/api/tools/reverse-shell', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetIP: targetIP.trim(),
          targetPort: parseInt(targetPort),
          platform,
          shellTypes,
          includeObfuscation,
          includeEncoding,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to generate reverse shells')
      }

      const data = await response.json()
      setResults(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const handleShellTypeToggle = (shellType: string) => {
    setShellTypes(prev => 
      prev.includes(shellType) 
        ? prev.filter(s => s !== shellType)
        : [...prev, shellType]
    )
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      // Could add a toast notification here
    })
  }

  const downloadPayload = (payload: string, filename: string) => {
    const blob = new Blob([payload], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-red-900 to-slate-900 p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/tools" className="p-2 hover:bg-white/10 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-white" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Reverse Shell Generator</h1>
            <p className="text-gray-300">
              Multi-platform reverse shell payload generator with listener commands
            </p>
          </div>
        </div>

        {/* Configuration Form */}
        <Card className="mb-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Terminal className="w-5 h-5" />
              Reverse Shell Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure reverse shell payload generation parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="targetIP" className="text-gray-200">Target IP Address (Your IP)</Label>
                <Input
                  id="targetIP"
                  placeholder="192.168.1.100"
                  value={targetIP}
                  onChange={(e) => setTargetIP(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="targetPort" className="text-gray-200">Target Port</Label>
                <Input
                  id="targetPort"
                  placeholder="4444"
                  value={targetPort}
                  onChange={(e) => setTargetPort(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="platform" className="text-gray-200">Target Platform</Label>
              <Select value={platform} onValueChange={setPlatform}>
                <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-700 border-slate-600">
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                  <SelectItem value="multi">Multi-Platform</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-gray-200 mb-2 block">Shell Types</Label>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                {[
                  { id: 'bash', label: 'Bash' },
                  { id: 'netcat', label: 'Netcat' },
                  { id: 'python', label: 'Python' },
                  { id: 'perl', label: 'Perl' },
                  { id: 'php', label: 'PHP' },
                  { id: 'ruby', label: 'Ruby' },
                  { id: 'java', label: 'Java' },
                  { id: 'powershell', label: 'PowerShell' },
                  { id: 'nodejs', label: 'Node.js' },
                  { id: 'socat', label: 'Socat' },
                  { id: 'awk', label: 'AWK' },
                  { id: 'telnet', label: 'Telnet' }
                ].map((shell) => (
                  <div key={shell.id} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id={shell.id}
                      checked={shellTypes.includes(shell.id)}
                      onChange={() => handleShellTypeToggle(shell.id)}
                      className="rounded"
                      aria-label={shell.label}
                    />
                    <Label 
                      htmlFor={shell.id} 
                      className="text-gray-300 text-sm cursor-pointer"
                    >
                      {shell.label}
                    </Label>
                  </div>
                ))}
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="includeObfuscation"
                  checked={includeObfuscation}
                  onChange={(e) => setIncludeObfuscation(e.target.checked)}
                  className="rounded"
                  aria-label="Include obfuscated versions"
                />
                <Label htmlFor="includeObfuscation" className="text-gray-200">
                  Include Obfuscated Versions
                </Label>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="includeEncoding"
                  checked={includeEncoding}
                  onChange={(e) => setIncludeEncoding(e.target.checked)}
                  className="rounded"
                  aria-label="Include encoded payloads"
                />
                <Label htmlFor="includeEncoding" className="text-gray-200">
                  Include Encoded Payloads
                </Label>
              </div>
            </div>

            <Button 
              onClick={handleGenerate}
              disabled={loading}
              className="w-full bg-red-600 hover:bg-red-700"
            >
              {loading ? (
                <>
                  <Settings className="w-4 h-4 mr-2 animate-spin" />
                  Generating Payloads...
                </>
              ) : (
                <>
                  <Code className="w-4 h-4 mr-2" />
                  Generate Reverse Shell Payloads
                </>
              )}
            </Button>
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
                  <Server className="w-5 h-5" />
                  Generated Reverse Shell Payloads
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-red-400">
                      {results.payloads.length}
                    </div>
                    <div className="text-sm text-gray-300">Shell Payloads</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">
                      {results.listenerCommands.length}
                    </div>
                    <div className="text-sm text-gray-300">Listener Commands</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-400">
                      {results.obfuscatedVersions.length}
                    </div>
                    <div className="text-sm text-gray-300">Obfuscated Versions</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-green-400">
                      {results.platform.toUpperCase()}
                    </div>
                    <div className="text-sm text-gray-300">Target Platform</div>
                  </div>
                </div>

                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-white mb-2">Generation Summary</h3>
                  <p className="text-gray-300">{results.summary}</p>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Reverse Shell Payloads</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="payloads" className="space-y-4">
                  <TabsList className="bg-slate-700">
                    <TabsTrigger value="payloads">Shell Payloads</TabsTrigger>
                    <TabsTrigger value="listeners">Listener Commands</TabsTrigger>
                    <TabsTrigger value="obfuscated">Obfuscated</TabsTrigger>
                    <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                  </TabsList>

                  <TabsContent value="payloads" className="space-y-4">
                    {results.payloads.map((payload, index) => (
                      <Card key={index} className="bg-slate-700/30">
                        <CardHeader className="pb-3">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <CardTitle className="text-lg text-white">{payload.name}</CardTitle>
                              <Badge variant="outline" className="text-blue-400 border-blue-400">
                                {payload.language}
                              </Badge>
                            </div>
                            <div className="flex gap-2">
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => copyToClipboard(payload.payload)}
                                className="text-gray-300 border-gray-600 hover:bg-slate-600"
                              >
                                <Copy className="w-4 h-4" />
                              </Button>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => downloadPayload(payload.payload, `${payload.language}-shell.${payload.language === 'powershell' ? 'ps1' : 'sh'}`)}
                                className="text-gray-300 border-gray-600 hover:bg-slate-600"
                              >
                                <Download className="w-4 h-4" />
                              </Button>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div>
                            <span className="text-sm font-medium text-gray-200">Description:</span>
                            <p className="text-gray-300 text-sm mt-1">{payload.description}</p>
                          </div>
                          
                          <div>
                            <span className="text-sm font-medium text-gray-200">Payload:</span>
                            <pre className="mt-1 text-sm text-green-400 bg-slate-800 p-3 rounded overflow-x-auto border">
                              {payload.payload}
                            </pre>
                          </div>
                          
                          {payload.encoded && (
                            <div className="space-y-2">
                              {payload.encoded.base64 && (
                                <div>
                                  <span className="text-sm font-medium text-gray-200">Base64 Encoded:</span>
                                  <pre className="mt-1 text-xs text-yellow-400 bg-slate-800 p-2 rounded overflow-x-auto border">
                                    {payload.encoded.base64}
                                  </pre>
                                </div>
                              )}
                              {payload.encoded.url && (
                                <div>
                                  <span className="text-sm font-medium text-gray-200">URL Encoded:</span>
                                  <pre className="mt-1 text-xs text-purple-400 bg-slate-800 p-2 rounded overflow-x-auto border">
                                    {payload.encoded.url}
                                  </pre>
                                </div>
                              )}
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    ))}
                  </TabsContent>

                  <TabsContent value="listeners" className="space-y-4">
                    <Alert className="bg-blue-900/20 border-blue-500/50 text-blue-200">
                      <Server className="h-4 w-4" />
                      <AlertDescription>
                        <strong>Important:</strong> Run these listener commands on your attacking machine before executing the reverse shell payloads.
                      </AlertDescription>
                    </Alert>

                    {results.listenerCommands.map((listener, index) => (
                      <Card key={index} className="bg-slate-700/30">
                        <CardHeader className="pb-3">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-lg text-white">{listener.tool}</CardTitle>
                            <Button
                              variant="outline"
                              size="sm"
                              onClick={() => copyToClipboard(listener.command)}
                              className="text-gray-300 border-gray-600 hover:bg-slate-600"
                            >
                              <Copy className="w-4 h-4" />
                            </Button>
                          </div>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div>
                            <span className="text-sm font-medium text-gray-200">Description:</span>
                            <p className="text-gray-300 text-sm mt-1">{listener.description}</p>
                          </div>
                          
                          <div>
                            <span className="text-sm font-medium text-gray-200">Command:</span>
                            <pre className="mt-1 text-sm text-blue-400 bg-slate-800 p-3 rounded overflow-x-auto border">
                              {listener.command}
                            </pre>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </TabsContent>

                  <TabsContent value="obfuscated" className="space-y-4">
                    {results.obfuscatedVersions.length > 0 ? (
                      results.obfuscatedVersions.map((obfuscated, index) => (
                        <Card key={index} className="bg-slate-700/30">
                          <CardHeader className="pb-3">
                            <div className="flex items-center justify-between">
                              <CardTitle className="text-lg text-white">{obfuscated.method}</CardTitle>
                              <Button
                                variant="outline"
                                size="sm"
                                onClick={() => copyToClipboard(obfuscated.payload)}
                                className="text-gray-300 border-gray-600 hover:bg-slate-600"
                              >
                                <Copy className="w-4 h-4" />
                              </Button>
                            </div>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <div>
                              <span className="text-sm font-medium text-gray-200">Description:</span>
                              <p className="text-gray-300 text-sm mt-1">{obfuscated.description}</p>
                            </div>
                            
                            <div>
                              <span className="text-sm font-medium text-gray-200">Obfuscated Payload:</span>
                              <pre className="mt-1 text-sm text-orange-400 bg-slate-800 p-3 rounded overflow-x-auto border">
                                {obfuscated.payload}
                              </pre>
                            </div>
                          </CardContent>
                        </Card>
                      ))
                    ) : (
                      <div className="text-center py-8 text-gray-400">
                        <FileCode className="w-12 h-12 mx-auto mb-4 text-gray-500" />
                        <p>No obfuscated versions generated</p>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="recommendations" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Usage Recommendations</CardTitle>
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
              About Reverse Shells
            </CardTitle>
          </CardHeader>
          <CardContent className="text-gray-300 space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2 text-white">Common Use Cases:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• <strong>Penetration Testing:</strong> Post-exploitation access</li>
                  <li>• <strong>Red Team Operations:</strong> Persistent access</li>
                  <li>• <strong>CTF Competitions:</strong> Flag capture challenges</li>
                  <li>• <strong>Security Research:</strong> Vulnerability assessment</li>
                  <li>• <strong>Remote Administration:</strong> Bypass firewalls</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-white">Defense Strategies:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Network monitoring and intrusion detection</li>
                  <li>• Endpoint detection and response (EDR)</li>
                  <li>• Application whitelisting</li>
                  <li>• Network segmentation and firewalls</li>
                  <li>• Regular security awareness training</li>
                </ul>
              </div>
            </div>

            <Alert className="bg-amber-900/20 border-amber-500/50 text-amber-200">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Legal Warning:</strong> Reverse shells should only be used in authorized penetration tests, 
                your own systems, or educational environments. Unauthorized use is illegal and unethical.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}