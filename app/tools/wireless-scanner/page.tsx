"use client"

import React, { useState } from 'react'
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Alert, AlertDescription } from "@/src/ui/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { 
  Wifi, 
  Signal,
  Lock,
  Unlock,
  AlertTriangle, 
  Zap, 
  Eye,
  Terminal,
  Shield,
  ArrowLeft,
  Play,
  RefreshCw,
  CheckCircle,
  XCircle,
  Radio,
  Target,
  Activity
} from 'lucide-react'
import Link from 'next/link'

interface WirelessScanResult {
  interface: string;
  networks: {
    ssid: string;
    bssid: string;
    channel: number;
    frequency: string;
    signal: number;
    quality: string;
    encryption: string;
    mode: string;
    vendor: string;
    vulnerabilities: string[];
    securityRating: 'Excellent' | 'Good' | 'Fair' | 'Poor' | 'Critical';
  }[];
  hiddenNetworks: number;
  openNetworks: number;
  wepNetworks: number;
  wpaNetworks: number;
  wpa2Networks: number;
  wpa3Networks: number;
  channelDistribution: { [channel: number]: number };
  securityAnalysis: {
    overallScore: number;
    issues: string[];
    recommendations: string[];
  };
  timeElapsed: string;
  summary: string;
}

export default function WirelessNetworkScannerPage() {
  const [networkInterface, setNetworkInterface] = useState('wlan0')
  const [scanDuration, setScanDuration] = useState('30')
  const [channelRange, setChannelRange] = useState('all')
  const [includeHidden, setIncludeHidden] = useState(true)
  const [securityAnalysis, setSecurityAnalysis] = useState(true)
  const [results, setResults] = useState<WirelessScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    if (!networkInterface.trim()) {
      setError('Please specify a network interface')
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)
    setProgress(0)

    // Simulate progress
    const progressInterval = setInterval(() => {
      setProgress(prev => Math.min(prev + Math.random() * 10, 90))
    }, 2000)

    try {
      const response = await fetch('/api/tools/wireless-scanner', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          interface: networkInterface.trim(),
          scanDuration: parseInt(scanDuration),
          channelRange,
          includeHidden,
          securityAnalysis,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to perform wireless network scan')
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

  const getSecurityRatingColor = (rating: string) => {
    switch (rating) {
      case 'Excellent': return 'bg-green-500 text-white'
      case 'Good': return 'bg-blue-500 text-white'
      case 'Fair': return 'bg-yellow-500 text-black'
      case 'Poor': return 'bg-orange-500 text-white'
      case 'Critical': return 'bg-red-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  const getSignalStrengthColor = (signal: number) => {
    if (signal >= -30) return 'text-green-400'
    if (signal >= -50) return 'text-blue-400'
    if (signal >= -70) return 'text-yellow-400'
    if (signal >= -90) return 'text-orange-400'
    return 'text-red-400'
  }

  const getEncryptionIcon = (encryption: string) => {
    return encryption.toLowerCase().includes('open') ? <Unlock className="w-4 h-4" /> : <Lock className="w-4 h-4" />
  }

  const getEncryptionColor = (encryption: string) => {
    if (encryption.toLowerCase().includes('open')) return 'text-red-400'
    if (encryption.toLowerCase().includes('wep')) return 'text-orange-400'
    if (encryption.toLowerCase().includes('wpa3')) return 'text-green-400'
    if (encryption.toLowerCase().includes('wpa2')) return 'text-blue-400'
    if (encryption.toLowerCase().includes('wpa')) return 'text-yellow-400'
    return 'text-gray-400'
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-blue-900 to-slate-900 p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/tools" className="p-2 hover:bg-white/10 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-white" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Wireless Network Scanner</h1>
            <p className="text-gray-300">
              WiFi network analysis and security assessment with handshake capture
            </p>
          </div>
        </div>

        {/* Configuration Form */}
        <Card className="mb-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Wifi className="w-5 h-5" />
              Wireless Scan Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure wireless network scanning parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="interface" className="text-gray-200">Network Interface</Label>
                <Input
                  id="interface"
                  placeholder="wlan0, wlan1, etc."
                  value={networkInterface}
                  onChange={(e) => setNetworkInterface(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="scanDuration" className="text-gray-200">Scan Duration (seconds)</Label>
                <Select value={scanDuration} onValueChange={setScanDuration}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="10">10 seconds (Quick)</SelectItem>
                    <SelectItem value="30">30 seconds (Standard)</SelectItem>
                    <SelectItem value="60">60 seconds (Thorough)</SelectItem>
                    <SelectItem value="120">120 seconds (Deep)</SelectItem>
                    <SelectItem value="300">300 seconds (Extensive)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="channelRange" className="text-gray-200">Channel Range</Label>
              <Select value={channelRange} onValueChange={setChannelRange}>
                <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-700 border-slate-600">
                  <SelectItem value="all">All Channels</SelectItem>
                  <SelectItem value="2.4ghz">2.4 GHz (1-14)</SelectItem>
                  <SelectItem value="5ghz">5 GHz (36-165)</SelectItem>
                  <SelectItem value="common">Common Channels (1,6,11)</SelectItem>
                  <SelectItem value="custom">Custom Range</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="includeHidden"
                  checked={includeHidden}
                  onChange={(e) => setIncludeHidden(e.target.checked)}
                  className="rounded"
                  aria-label="Include hidden networks"
                />
                <Label htmlFor="includeHidden" className="text-gray-200">
                  Detect Hidden Networks
                </Label>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="securityAnalysis"
                  checked={securityAnalysis}
                  onChange={(e) => setSecurityAnalysis(e.target.checked)}
                  className="rounded"
                  aria-label="Perform security analysis"
                />
                <Label htmlFor="securityAnalysis" className="text-gray-200">
                  Perform Security Analysis
                </Label>
              </div>
            </div>

            <Button 
              onClick={handleScan}
              disabled={loading}
              className="w-full bg-blue-600 hover:bg-blue-700"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Scanning Wireless Networks...
                </>
              ) : (
                <>
                  <Radio className="w-4 h-4 mr-2" />
                  Start Wireless Network Scan
                </>
              )}
            </Button>

            {loading && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm text-gray-300">
                  <span>Scanning for wireless networks...</span>
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
                  Wireless Network Scan Results
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">
                      {results.networks.length}
                    </div>
                    <div className="text-sm text-gray-300">Networks Found</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-red-400">
                      {results.openNetworks}
                    </div>
                    <div className="text-sm text-gray-300">Open Networks</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-green-400">
                      {results.wpa3Networks}
                    </div>
                    <div className="text-sm text-gray-300">WPA3 Networks</div>
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

                {/* Security Overview */}
                <div className="bg-slate-700/30 rounded-lg p-4">
                  <h4 className="font-medium text-white mb-3">Security Distribution</h4>
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-4 text-center">
                    <div>
                      <div className="text-lg font-semibold text-red-400">{results.openNetworks}</div>
                      <div className="text-xs text-gray-400">Open</div>
                    </div>
                    <div>
                      <div className="text-lg font-semibold text-orange-400">{results.wepNetworks}</div>
                      <div className="text-xs text-gray-400">WEP</div>
                    </div>
                    <div>
                      <div className="text-lg font-semibold text-yellow-400">{results.wpaNetworks}</div>
                      <div className="text-xs text-gray-400">WPA</div>
                    </div>
                    <div>
                      <div className="text-lg font-semibold text-blue-400">{results.wpa2Networks}</div>
                      <div className="text-xs text-gray-400">WPA2</div>
                    </div>
                    <div>
                      <div className="text-lg font-semibold text-green-400">{results.wpa3Networks}</div>
                      <div className="text-xs text-gray-400">WPA3</div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Network Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="networks" className="space-y-4">
                  <TabsList className="bg-slate-700">
                    <TabsTrigger value="networks">Networks</TabsTrigger>
                    <TabsTrigger value="channels">Channel Analysis</TabsTrigger>
                    <TabsTrigger value="security">Security Assessment</TabsTrigger>
                  </TabsList>

                  <TabsContent value="networks" className="space-y-4">
                    {results.networks.length > 0 ? (
                      <div className="space-y-3">
                        {results.networks.map((network, index) => (
                          <Card key={index} className="bg-slate-700/30">
                            <CardHeader className="pb-3">
                              <div className="flex items-center justify-between">
                                <div className="flex items-center gap-2">
                                  {getEncryptionIcon(network.encryption)}
                                  <CardTitle className="text-lg text-white">
                                    {network.ssid || '<Hidden Network>'}
                                  </CardTitle>
                                </div>
                                <div className="flex items-center gap-2">
                                  <Badge className={getSecurityRatingColor(network.securityRating)}>
                                    {network.securityRating}
                                  </Badge>
                                  <Badge variant="outline" className="text-blue-400 border-blue-400">
                                    Ch {network.channel}
                                  </Badge>
                                </div>
                              </div>
                            </CardHeader>
                            <CardContent className="space-y-3">
                              <div className="grid md:grid-cols-2 gap-4">
                                <div className="space-y-2">
                                  <div className="flex justify-between">
                                    <span className="text-gray-300 text-sm">BSSID:</span>
                                    <code className="text-green-400 text-sm">{network.bssid}</code>
                                  </div>
                                  <div className="flex justify-between">
                                    <span className="text-gray-300 text-sm">Encryption:</span>
                                    <span className={`text-sm ${getEncryptionColor(network.encryption)}`}>
                                      {network.encryption}
                                    </span>
                                  </div>
                                  <div className="flex justify-between">
                                    <span className="text-gray-300 text-sm">Frequency:</span>
                                    <span className="text-blue-400 text-sm">{network.frequency}</span>
                                  </div>
                                </div>
                                <div className="space-y-2">
                                  <div className="flex justify-between">
                                    <span className="text-gray-300 text-sm">Signal:</span>
                                    <span className={`text-sm font-medium ${getSignalStrengthColor(network.signal)}`}>
                                      {network.signal} dBm
                                    </span>
                                  </div>
                                  <div className="flex justify-between">
                                    <span className="text-gray-300 text-sm">Quality:</span>
                                    <span className="text-purple-400 text-sm">{network.quality}</span>
                                  </div>
                                  <div className="flex justify-between">
                                    <span className="text-gray-300 text-sm">Vendor:</span>
                                    <span className="text-orange-400 text-sm">{network.vendor}</span>
                                  </div>
                                </div>
                              </div>

                              {network.vulnerabilities.length > 0 && (
                                <div>
                                  <span className="text-sm font-medium text-red-400 block mb-2">Security Issues:</span>
                                  <div className="space-y-1">
                                    {network.vulnerabilities.map((vuln, vIndex) => (
                                      <div key={vIndex} className="text-sm text-red-300 bg-red-900/20 p-2 rounded">
                                        {vuln}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              )}
                            </CardContent>
                          </Card>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-8 text-gray-400">
                        <Wifi className="w-12 h-12 mx-auto mb-4 text-gray-500" />
                        <p>No wireless networks detected</p>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="channels" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Channel Distribution</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="space-y-3">
                          {Object.entries(results.channelDistribution).map(([channel, count]) => (
                            <div key={channel} className="flex items-center justify-between">
                              <span className="text-gray-300">Channel {channel}:</span>
                              <div className="flex items-center gap-2">
                                <div className="w-32 bg-slate-600 rounded-full h-2">
                                  <div 
                                    className="bg-blue-400 h-2 rounded-full transition-all duration-300" 
                                    style={{ width: `${(count / Math.max(...Object.values(results.channelDistribution))) * 100}%` }}
                                  />
                                </div>
                                <span className="text-blue-400 font-medium text-sm">{count}</span>
                              </div>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  </TabsContent>

                  <TabsContent value="security" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="flex items-center justify-between text-white">
                          <span>Security Assessment</span>
                          <div className="flex items-center gap-2">
                            <span className="text-sm">Overall Score:</span>
                            <div className="flex items-center gap-2">
                              <Progress value={results.securityAnalysis.overallScore} className="w-20 bg-slate-600" />
                              <span className="text-sm font-medium text-blue-400">
                                {results.securityAnalysis.overallScore}%
                              </span>
                            </div>
                          </div>
                        </CardTitle>
                      </CardHeader>
                      <CardContent className="space-y-4">
                        {results.securityAnalysis.issues.length > 0 && (
                          <div>
                            <h4 className="font-medium text-red-400 mb-2">Security Issues:</h4>
                            <ul className="space-y-2">
                              {results.securityAnalysis.issues.map((issue, index) => (
                                <li key={index} className="flex items-start gap-2">
                                  <AlertTriangle className="w-4 h-4 text-red-400 mt-0.5 flex-shrink-0" />
                                  <span className="text-gray-300 text-sm">{issue}</span>
                                </li>
                              ))}
                            </ul>
                          </div>
                        )}

                        <div>
                          <h4 className="font-medium text-green-400 mb-2">Recommendations:</h4>
                          <ul className="space-y-2">
                            {results.securityAnalysis.recommendations.map((rec, index) => (
                              <li key={index} className="flex items-start gap-2">
                                <Shield className="w-4 h-4 text-green-400 mt-0.5 flex-shrink-0" />
                                <span className="text-gray-300 text-sm">{rec}</span>
                              </li>
                            ))}
                          </ul>
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
              About Wireless Network Security
            </CardTitle>
          </CardHeader>
          <CardContent className="text-gray-300 space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2 text-white">Security Standards:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• <strong>Open:</strong> No encryption - highly vulnerable</li>
                  <li>• <strong>WEP:</strong> Legacy, easily crackable</li>
                  <li>• <strong>WPA:</strong> Better but still vulnerable</li>
                  <li>• <strong>WPA2:</strong> Secure with strong password</li>
                  <li>• <strong>WPA3:</strong> Latest and most secure</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-white">Security Best Practices:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Use WPA3 or WPA2 with strong passwords</li>
                  <li>• Disable WPS if not needed</li>
                  <li>• Hide SSID for additional security</li>
                  <li>• Use MAC address filtering</li>
                  <li>• Regular firmware updates</li>
                </ul>
              </div>
            </div>

            <Alert className="bg-amber-900/20 border-amber-500/50 text-amber-200">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Legal Notice:</strong> Only scan wireless networks you own or have explicit permission to test. 
                Unauthorized network scanning may violate local laws and regulations.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}