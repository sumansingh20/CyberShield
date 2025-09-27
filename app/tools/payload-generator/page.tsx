"use client"

import React, { useState } from 'react'
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Alert, AlertDescription } from "@/src/ui/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { 
  Code2, 
  Copy,
  Download,
  AlertTriangle, 
  Shield, 
  Terminal,
  ArrowLeft,
  RefreshCw,
  Target,
  Activity,
  Zap,
  FileCode,
  Bug,
  Eye,
  Settings
} from 'lucide-react'
import Link from 'next/link'

interface PayloadResult {
  payloadType: string;
  generatedPayloads: {
    name: string;
    description: string;
    payload: string;
    encoding: string;
    platform: string;
    category: string;
    difficulty: 'Basic' | 'Intermediate' | 'Advanced';
    effectiveness: number;
    obfuscated?: string;
    variants?: string[];
  }[];
  encodingOptions: {
    base64: string;
    urlEncoded: string;
    hexEncoded: string;
    htmlEncoded: string;
    unicodeEncoded: string;
  };
  customizations: {
    callbacks: string[];
    reversShells: string[];
    bindShells: string[];
  };
  testingGuidelines: string[];
  mitigations: string[];
  references: string[];
  summary: string;
}

export default function PayloadGeneratorPage() {
  const [payloadType, setPayloadType] = useState('web_shells')
  const [targetPlatform, setTargetPlatform] = useState('cross_platform')
  const [encoding, setEncoding] = useState('none')
  const [obfuscation, setObfuscation] = useState('none')
  const [customTarget, setCustomTarget] = useState('')
  const [customPort, setCustomPort] = useState('4444')
  const [shellType, setShellType] = useState('reverse')
  const [language, setLanguage] = useState('bash')
  const [advancedOptions, setAdvancedOptions] = useState(false)
  const [includeBypass, setIncludeBypass] = useState(false)
  const [includeVariants, setIncludeVariants] = useState(true)
  const [results, setResults] = useState<PayloadResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleGenerate = async () => {
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const response = await fetch('/api/tools/payload-generator', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          payloadType,
          targetPlatform,
          encoding,
          obfuscation,
          customTarget,
          customPort,
          shellType,
          language,
          advancedOptions,
          includeBypass,
          includeVariants,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to generate payloads')
      }

      const data = await response.json()
      
      if (data.success && data.data) {
        setResults(data.data)
      } else {
        throw new Error(data.message || 'Failed to generate payloads')
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Basic': return 'bg-green-500 text-white'
      case 'Intermediate': return 'bg-yellow-500 text-black'
      case 'Advanced': return 'bg-red-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  const getEffectivenessColor = (score: number) => {
    if (score >= 9) return 'text-red-400'
    if (score >= 7) return 'text-orange-400'
    if (score >= 5) return 'text-yellow-400'
    return 'text-blue-400'
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      // Could add a toast notification here
    })
  }

  const downloadPayload = (payload: string, name: string) => {
    const blob = new Blob([payload], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${name.toLowerCase().replace(/\s+/g, '_')}.txt`
    a.click()
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
            <h1 className="text-3xl font-bold text-white mb-2">Payload Generator</h1>
            <p className="text-gray-300">
              Generate custom payloads for penetration testing and security research
            </p>
          </div>
        </div>

        {/* Configuration Form */}
        <Card className="mb-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Code2 className="w-5 h-5" />
              Payload Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure payload parameters for generation
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label htmlFor="payloadType" className="text-gray-200">Payload Type</Label>
                <Select value={payloadType} onValueChange={setPayloadType}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="web_shells">Web Shells</SelectItem>
                    <SelectItem value="reverse_shells">Reverse Shells</SelectItem>
                    <SelectItem value="bind_shells">Bind Shells</SelectItem>
                    <SelectItem value="meterpreter">Meterpreter</SelectItem>
                    <SelectItem value="powershell">PowerShell</SelectItem>
                    <SelectItem value="sql_injection">SQL Injection</SelectItem>
                    <SelectItem value="xss_payloads">XSS Payloads</SelectItem>
                    <SelectItem value="command_injection">Command Injection</SelectItem>
                    <SelectItem value="buffer_overflow">Buffer Overflow</SelectItem>
                    <SelectItem value="privilege_escalation">Privilege Escalation</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="targetPlatform" className="text-gray-200">Target Platform</Label>
                <Select value={targetPlatform} onValueChange={setTargetPlatform}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="cross_platform">Cross Platform</SelectItem>
                    <SelectItem value="windows">Windows</SelectItem>
                    <SelectItem value="linux">Linux</SelectItem>
                    <SelectItem value="macos">macOS</SelectItem>
                    <SelectItem value="android">Android</SelectItem>
                    <SelectItem value="ios">iOS</SelectItem>
                    <SelectItem value="web">Web Applications</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="language" className="text-gray-200">Script Language</Label>
                <Select value={language} onValueChange={setLanguage}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="bash">Bash</SelectItem>
                    <SelectItem value="powershell">PowerShell</SelectItem>
                    <SelectItem value="python">Python</SelectItem>
                    <SelectItem value="perl">Perl</SelectItem>
                    <SelectItem value="php">PHP</SelectItem>
                    <SelectItem value="javascript">JavaScript</SelectItem>
                    <SelectItem value="c">C/C++</SelectItem>
                    <SelectItem value="java">Java</SelectItem>
                    <SelectItem value="ruby">Ruby</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="customTarget" className="text-gray-200">Target IP/Domain</Label>
                <Input
                  id="customTarget"
                  placeholder="192.168.1.100 or attacker.com"
                  value={customTarget}
                  onChange={(e) => setCustomTarget(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="customPort" className="text-gray-200">Target Port</Label>
                <Input
                  id="customPort"
                  placeholder="4444"
                  value={customPort}
                  onChange={(e) => setCustomPort(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>
            </div>

            <div className="grid md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label htmlFor="shellType" className="text-gray-200">Shell Type</Label>
                <Select value={shellType} onValueChange={setShellType}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="reverse">Reverse Shell</SelectItem>
                    <SelectItem value="bind">Bind Shell</SelectItem>
                    <SelectItem value="web">Web Shell</SelectItem>
                    <SelectItem value="meterpreter">Meterpreter</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="encoding" className="text-gray-200">Encoding</Label>
                <Select value={encoding} onValueChange={setEncoding}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="none">None</SelectItem>
                    <SelectItem value="base64">Base64</SelectItem>
                    <SelectItem value="url">URL Encoding</SelectItem>
                    <SelectItem value="hex">Hex Encoding</SelectItem>
                    <SelectItem value="unicode">Unicode</SelectItem>
                    <SelectItem value="html">HTML Entity</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="obfuscation" className="text-gray-200">Obfuscation</Label>
                <Select value={obfuscation} onValueChange={setObfuscation}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="none">None</SelectItem>
                    <SelectItem value="basic">Basic</SelectItem>
                    <SelectItem value="intermediate">Intermediate</SelectItem>
                    <SelectItem value="advanced">Advanced</SelectItem>
                    <SelectItem value="custom">Custom</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid md:grid-cols-3 gap-4">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="advancedOptions"
                  checked={advancedOptions}
                  onChange={(e) => setAdvancedOptions(e.target.checked)}
                  className="rounded"
                  aria-label="Include advanced options"
                />
                <Label htmlFor="advancedOptions" className="text-gray-200">
                  Advanced Options
                </Label>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="includeBypass"
                  checked={includeBypass}
                  onChange={(e) => setIncludeBypass(e.target.checked)}
                  className="rounded"
                  aria-label="Include bypass techniques"
                />
                <Label htmlFor="includeBypass" className="text-gray-200">
                  Bypass Techniques
                </Label>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="includeVariants"
                  checked={includeVariants}
                  onChange={(e) => setIncludeVariants(e.target.checked)}
                  className="rounded"
                  aria-label="Include payload variants"
                />
                <Label htmlFor="includeVariants" className="text-gray-200">
                  Multiple Variants
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
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Generating Payloads...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Generate Payloads
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
                  <Target className="w-5 h-5" />
                  Generated Payloads Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-red-400">
                      {results.generatedPayloads.length}
                    </div>
                    <div className="text-sm text-gray-300">Payloads</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">
                      {results.generatedPayloads.filter(p => p.variants?.length).length}
                    </div>
                    <div className="text-sm text-gray-300">With Variants</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-green-400">
                      {results.generatedPayloads.filter(p => p.obfuscated).length}
                    </div>
                    <div className="text-sm text-gray-300">Obfuscated</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-400">
                      {Object.keys(results.encodingOptions).length}
                    </div>
                    <div className="text-sm text-gray-300">Encodings</div>
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
                <CardTitle className="text-white">Generated Payloads</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="payloads" className="space-y-4">
                  <TabsList className="bg-slate-700">
                    <TabsTrigger value="payloads">Payloads</TabsTrigger>
                    <TabsTrigger value="encodings">Encodings</TabsTrigger>
                    <TabsTrigger value="customizations">Customizations</TabsTrigger>
                    <TabsTrigger value="guidelines">Testing Guidelines</TabsTrigger>
                  </TabsList>

                  <TabsContent value="payloads" className="space-y-4">
                    {results.generatedPayloads.map((payload, index) => (
                      <Card key={index} className="bg-slate-700/30">
                        <CardHeader className="pb-3">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-lg text-white">{payload.name}</CardTitle>
                            <div className="flex items-center gap-2">
                              <Badge className={getDifficultyColor(payload.difficulty)}>
                                {payload.difficulty}
                              </Badge>
                              <Badge className={`bg-opacity-20 border ${getEffectivenessColor(payload.effectiveness)}`}>
                                {payload.effectiveness}/10
                              </Badge>
                            </div>
                          </div>
                          <p className="text-gray-300 text-sm">{payload.description}</p>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div className="grid md:grid-cols-2 gap-4 text-sm">
                            <div className="space-y-1">
                              <div className="flex justify-between">
                                <span className="text-gray-400">Platform:</span>
                                <span className="text-blue-400">{payload.platform}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-400">Category:</span>
                                <span className="text-orange-400">{payload.category}</span>
                              </div>
                            </div>
                            <div className="space-y-1">
                              <div className="flex justify-between">
                                <span className="text-gray-400">Encoding:</span>
                                <span className="text-purple-400">{payload.encoding}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-gray-400">Effectiveness:</span>
                                <span className={getEffectivenessColor(payload.effectiveness)}>
                                  {payload.effectiveness}/10
                                </span>
                              </div>
                            </div>
                          </div>

                          {/* Main Payload */}
                          <div>
                            <Label className="text-gray-200 block mb-2">Payload Code:</Label>
                            <div className="bg-slate-800 rounded-lg p-4 relative">
                              <pre className="text-green-400 text-sm overflow-x-auto font-mono whitespace-pre-wrap">
                                {payload.payload}
                              </pre>
                              <div className="absolute top-2 right-2 flex gap-2">
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => copyToClipboard(payload.payload)}
                                  className="text-gray-300 hover:bg-slate-700"
                                >
                                  <Copy className="w-4 h-4" />
                                </Button>
                                <Button
                                  variant="ghost"
                                  size="sm"
                                  onClick={() => downloadPayload(payload.payload, payload.name)}
                                  className="text-gray-300 hover:bg-slate-700"
                                >
                                  <Download className="w-4 h-4" />
                                </Button>
                              </div>
                            </div>
                          </div>

                          {/* Obfuscated Version */}
                          {payload.obfuscated && (
                            <div>
                              <Label className="text-gray-200 block mb-2">Obfuscated Version:</Label>
                              <div className="bg-slate-800 rounded-lg p-4 relative">
                                <pre className="text-cyan-400 text-sm overflow-x-auto font-mono whitespace-pre-wrap">
                                  {payload.obfuscated}
                                </pre>
                                <div className="absolute top-2 right-2 flex gap-2">
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyToClipboard(payload.obfuscated!)}
                                    className="text-gray-300 hover:bg-slate-700"
                                  >
                                    <Copy className="w-4 h-4" />
                                  </Button>
                                </div>
                              </div>
                            </div>
                          )}

                          {/* Variants */}
                          {payload.variants && payload.variants.length > 0 && (
                            <div>
                              <Label className="text-gray-200 block mb-2">Payload Variants:</Label>
                              <div className="space-y-2">
                                {payload.variants.map((variant, vIndex) => (
                                  <div key={vIndex} className="bg-slate-800 rounded-lg p-3 relative">
                                    <pre className="text-yellow-400 text-sm overflow-x-auto font-mono whitespace-pre-wrap">
                                      {variant}
                                    </pre>
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => copyToClipboard(variant)}
                                      className="absolute top-2 right-2 text-gray-300 hover:bg-slate-700"
                                    >
                                      <Copy className="w-3 h-3" />
                                    </Button>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    ))}
                  </TabsContent>

                  <TabsContent value="encodings" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Encoding Options</CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        {Object.entries(results.encodingOptions).map(([encoding, value]) => (
                          <div key={encoding}>
                            <Label className="text-gray-200 block mb-2 capitalize">
                              {encoding.replace(/([A-Z])/g, ' $1').trim()}:
                            </Label>
                            <div className="bg-slate-800 rounded-lg p-4 relative">
                              <pre className="text-blue-400 text-sm overflow-x-auto font-mono whitespace-pre-wrap">
                                {value}
                              </pre>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => copyToClipboard(value)}
                                className="absolute top-2 right-2 text-gray-300 hover:bg-slate-700"
                              >
                                <Copy className="w-4 h-4" />
                              </Button>
                            </div>
                          </div>
                        ))}
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="customizations" className="space-y-4">
                    <div className="grid md:grid-cols-3 gap-4">
                      {Object.entries(results.customizations).map(([type, items]) => (
                        <Card key={type} className="bg-slate-700/30">
                          <CardHeader>
                            <CardTitle className="text-white capitalize">
                              {type.replace(/([A-Z])/g, ' $1').trim()}
                            </CardTitle>
                          </CardHeader>
                          <CardContent>
                            <div className="space-y-2">
                              {items.map((item, index) => (
                                <div key={index} className="bg-slate-800 rounded p-3 relative">
                                  <pre className="text-green-400 text-sm overflow-x-auto font-mono whitespace-pre-wrap">
                                    {item}
                                  </pre>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyToClipboard(item)}
                                    className="absolute top-1 right-1 text-gray-300 hover:bg-slate-700 h-6 w-6 p-0"
                                  >
                                    <Copy className="w-3 h-3" />
                                  </Button>
                                </div>
                              ))}
                            </div>
                          </CardContent>
                        </Card>
                      ))}
                    </div>
                  </TabsContent>

                  <TabsContent value="guidelines" className="space-y-4">
                    <div className="grid md:grid-cols-2 gap-6">
                      <Card className="bg-slate-700/30">
                        <CardHeader>
                          <CardTitle className="text-white">Testing Guidelines</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-2">
                            {results.testingGuidelines.map((guideline, index) => (
                              <li key={index} className="flex items-start gap-2">
                                <Activity className="w-4 h-4 text-blue-400 mt-1 flex-shrink-0" />
                                <span className="text-gray-300 text-sm">{guideline}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>

                      <Card className="bg-slate-700/30">
                        <CardHeader>
                          <CardTitle className="text-white">Security Mitigations</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-2">
                            {results.mitigations.map((mitigation, index) => (
                              <li key={index} className="flex items-start gap-2">
                                <Shield className="w-4 h-4 text-green-400 mt-1 flex-shrink-0" />
                                <span className="text-gray-300 text-sm">{mitigation}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    </div>

                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">References</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-2">
                          {results.references.map((reference, index) => (
                            <div key={index} className="text-blue-400 hover:text-blue-300 cursor-pointer text-sm">
                              {reference}
                            </div>
                          ))}
                        </div>
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
              Payload Generation Best Practices
            </CardTitle>
          </CardHeader>
          <CardContent className="text-gray-300 space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2 text-white">Payload Types:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• <strong>Reverse Shells:</strong> Connect back to attacker</li>
                  <li>• <strong>Bind Shells:</strong> Listen on target system</li>
                  <li>• <strong>Web Shells:</strong> HTTP-based command execution</li>
                  <li>• <strong>Meterpreter:</strong> Advanced post-exploitation</li>
                  <li>• <strong>Injection Payloads:</strong> SQL, XSS, command injection</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-white">Evasion Techniques:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Encoding and obfuscation</li>
                  <li>• Polymorphic payloads</li>
                  <li>• Anti-detection mechanisms</li>
                  <li>• Staged and stageless payloads</li>
                  <li>• Living-off-the-land techniques</li>
                </ul>
              </div>
            </div>

            <Alert className="bg-amber-900/20 border-amber-500/50 text-amber-200">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Ethical Use Only:</strong> These payloads are for authorized penetration testing, 
                security research, and educational purposes only. Always ensure proper authorization 
                before using any payload against systems you do not own.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}