"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Checkbox } from "@/src/ui/components/ui/checkbox"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { AlertTriangle, Wifi, Shield, Lock, Unlock, Signal, AlertCircle, CheckCircle, Copy, ArrowLeft } from "lucide-react"
import Link from "next/link"

interface WirelessNetwork {
  ssid: string
  bssid: string
  channel: number
  frequency: number
  signal_strength: number
  encryption: string
  security: string
  vendor: string
  vulnerability_score: number
  security_issues: string[]
  handshake_captured: boolean
  clients: number
  beacon_interval: number
  uptime: string
  country_code: string
  wps_enabled: boolean
  hidden: boolean
}

interface ScanResult {
  target: string
  scan_type: string
  duration: number
  networks_found: number
  vulnerable_networks: number
  open_networks: number
  networks: WirelessNetwork[]
  handshakes_captured: number
  deauth_successful: number
  recommendations: string[]
  timestamp: string
}

export default function WirelessScannerPage() {
  const [target, setTarget] = useState("")
  const [scanType, setScanType] = useState("passive")
  const [interface_name, setInterfaceName] = useState("wlan0")
  const [channel, setChannel] = useState("")
  const [timeout, setTimeout] = useState("30")
  const [captureHandshakes, setCaptureHandshakes] = useState(false)
  const [performDeauth, setPerformDeauth] = useState(false)
  const [scanHidden, setScanHidden] = useState(false)
  const [result, setResult] = useState<ScanResult | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")
    setResult(null)

    try {
      const response = await fetch("/api/tools/wireless-scanner", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          target,
          scan_type: scanType,
          interface: interface_name,
          channel: channel || null,
          timeout: parseInt(timeout),
          capture_handshakes: captureHandshakes,
          perform_deauth: performDeauth,
          scan_hidden: scanHidden
        })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || "Scan failed")
      }

      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred")
    } finally {
      setIsLoading(false)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const getSecurityColor = (encryption: string) => {
    if (encryption === "Open" || encryption === "None") return "text-red-500"
    if (encryption.includes("WEP")) return "text-orange-500"
    if (encryption.includes("WPA")) return "text-yellow-500"
    if (encryption.includes("WPA2")) return "text-blue-500"
    if (encryption.includes("WPA3")) return "text-green-500"
    return "text-gray-500"
  }

  const getVulnerabilityLevel = (score: number) => {
    if (score >= 8) return { level: "Critical", color: "text-red-500", bg: "bg-red-500/10" }
    if (score >= 6) return { level: "High", color: "text-orange-500", bg: "bg-orange-500/10" }
    if (score >= 4) return { level: "Medium", color: "text-yellow-500", bg: "bg-yellow-500/10" }
    if (score >= 2) return { level: "Low", color: "text-blue-500", bg: "bg-blue-500/10" }
    return { level: "Info", color: "text-gray-500", bg: "bg-gray-500/10" }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-4">
      <div className="container mx-auto max-w-7xl">
        <div className="mb-8 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Link href="/tools">
              <Button variant="outline" size="sm">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Tools
              </Button>
            </Link>
            <div>
              <h1 className="text-4xl font-bold text-white">Wireless Network Scanner</h1>
              <p className="text-slate-300 mt-2">
                Advanced WiFi security assessment and network discovery
              </p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
          {/* Input Form */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Wifi className="h-5 w-5" />
                Wireless Scan Configuration
              </CardTitle>
              <CardDescription>
                Configure your wireless network security assessment
              </CardDescription>
            </CardHeader>
            <CardContent>
              <form onSubmit={handleSubmit} className="space-y-4">
                <div>
                  <Label htmlFor="target">Target Area/BSSID (Optional)</Label>
                  <Input
                    id="target"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    placeholder="Leave empty for general scan or specify BSSID"
                  />
                </div>

                <div>
                  <Label htmlFor="scanType">Scan Type</Label>
                  <Select value={scanType} onValueChange={setScanType}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select scan type" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="passive">Passive Scan (Safe)</SelectItem>
                      <SelectItem value="active">Active Scan (Probe)</SelectItem>
                      <SelectItem value="aggressive">Aggressive Scan (All Channels)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <Label htmlFor="interface">Wireless Interface</Label>
                    <Input
                      id="interface"
                      value={interface_name}
                      onChange={(e) => setInterfaceName(e.target.value)}
                      placeholder="wlan0"
                    />
                  </div>
                  
                  <div>
                    <Label htmlFor="channel">Channel (Optional)</Label>
                    <Input
                      id="channel"
                      value={channel}
                      onChange={(e) => setChannel(e.target.value)}
                      placeholder="1-14, or leave empty for all"
                    />
                  </div>
                </div>

                <div>
                  <Label htmlFor="timeout">Scan Duration (seconds)</Label>
                  <Input
                    id="timeout"
                    type="number"
                    value={timeout}
                    onChange={(e) => setTimeout(e.target.value)}
                    min="10"
                    max="300"
                  />
                </div>

                <div className="space-y-3">
                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="handshakes"
                      checked={captureHandshakes}
                      onCheckedChange={setCaptureHandshakes}
                    />
                    <Label htmlFor="handshakes">Capture WPA/WPA2 Handshakes</Label>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="deauth"
                      checked={performDeauth}
                      onCheckedChange={setPerformDeauth}
                    />
                    <Label htmlFor="deauth">Perform Deauth Attacks (Advanced)</Label>
                  </div>

                  <div className="flex items-center space-x-2">
                    <Checkbox
                      id="hidden"
                      checked={scanHidden}
                      onCheckedChange={setScanHidden}
                    />
                    <Label htmlFor="hidden">Scan for Hidden Networks</Label>
                  </div>
                </div>

                <div className="bg-yellow-500/10 border border-yellow-500/20 rounded-lg p-4">
                  <div className="flex items-center gap-2 text-yellow-500 mb-2">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="font-semibold">Legal Notice</span>
                  </div>
                  <p className="text-sm text-yellow-400">
                    Only scan networks you own or have explicit permission to test. 
                    Unauthorized network scanning may be illegal in your jurisdiction.
                  </p>
                </div>

                <Button type="submit" className="w-full" disabled={isLoading}>
                  {isLoading ? "Scanning..." : "Start Wireless Scan"}
                </Button>
              </form>
            </CardContent>
          </Card>

          {/* Results */}
          <div className="space-y-6">
            {error && (
              <Card className="border-red-500/20 bg-red-500/10">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2 text-red-500">
                    <AlertCircle className="h-4 w-4" />
                    <span className="font-semibold">Error</span>
                  </div>
                  <p className="mt-2 text-red-400">{error}</p>
                </CardContent>
              </Card>
            )}

            {isLoading && (
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2 mb-4">
                    <Wifi className="h-4 w-4 animate-pulse" />
                    <span>Scanning wireless networks...</span>
                  </div>
                  <Progress value={33} className="mb-2" />
                  <p className="text-sm text-gray-500">
                    This may take several minutes depending on your scan settings
                  </p>
                </CardContent>
              </Card>
            )}

            {result && (
              <Tabs defaultValue="networks" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="networks">Networks ({result.networks_found})</TabsTrigger>
                  <TabsTrigger value="security">Security Issues</TabsTrigger>
                  <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                </TabsList>

                <TabsContent value="networks" className="space-y-4">
                  <Card>
                    <CardHeader>
                      <CardTitle>Scan Summary</CardTitle>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-2 gap-4 text-sm">
                        <div>
                          <span className="text-gray-500">Networks Found:</span>
                          <span className="ml-2 font-semibold">{result.networks_found}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Vulnerable:</span>
                          <span className="ml-2 font-semibold text-red-500">{result.vulnerable_networks}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Open Networks:</span>
                          <span className="ml-2 font-semibold text-orange-500">{result.open_networks}</span>
                        </div>
                        <div>
                          <span className="text-gray-500">Handshakes:</span>
                          <span className="ml-2 font-semibold text-green-500">{result.handshakes_captured}</span>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  <div className="space-y-4">
                    {result.networks.map((network, index) => {
                      const vuln = getVulnerabilityLevel(network.vulnerability_score)
                      return (
                        <Card key={index} className="relative">
                          <CardHeader className="pb-3">
                            <div className="flex justify-between items-start">
                              <div>
                                <CardTitle className="flex items-center gap-2">
                                  {network.hidden ? <Lock className="h-4 w-4" /> : <Wifi className="h-4 w-4" />}
                                  {network.ssid || "(Hidden Network)"}
                                  {network.encryption === "Open" && (
                                    <Badge variant="destructive">OPEN</Badge>
                                  )}
                                </CardTitle>
                                <CardDescription className="flex items-center gap-2">
                                  <code className="bg-gray-100 dark:bg-gray-800 px-1 rounded text-xs">
                                    {network.bssid}
                                  </code>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyToClipboard(network.bssid)}
                                  >
                                    <Copy className="h-3 w-3" />
                                  </Button>
                                </CardDescription>
                              </div>
                              <Badge className={`${vuln.bg} ${vuln.color}`}>
                                {vuln.level}
                              </Badge>
                            </div>
                          </CardHeader>
                          <CardContent className="space-y-3">
                            <div className="grid grid-cols-2 gap-4 text-sm">
                              <div>
                                <span className="text-gray-500">Channel:</span>
                                <span className="ml-2">{network.channel}</span>
                              </div>
                              <div>
                                <span className="text-gray-500">Signal:</span>
                                <span className="ml-2">{network.signal_strength} dBm</span>
                              </div>
                              <div>
                                <span className="text-gray-500">Security:</span>
                                <span className={`ml-2 ${getSecurityColor(network.encryption)}`}>
                                  {network.encryption}
                                </span>
                              </div>
                              <div>
                                <span className="text-gray-500">Clients:</span>
                                <span className="ml-2">{network.clients}</span>
                              </div>
                            </div>

                            {network.security_issues.length > 0 && (
                              <div>
                                <h4 className="font-semibold text-sm mb-2 flex items-center gap-1">
                                  <AlertTriangle className="h-3 w-3 text-red-500" />
                                  Security Issues
                                </h4>
                                <ul className="text-sm text-red-400 space-y-1">
                                  {network.security_issues.map((issue, i) => (
                                    <li key={i} className="flex items-center gap-1">
                                      <span className="w-1 h-1 bg-red-400 rounded-full"></span>
                                      {issue}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            )}

                            {network.handshake_captured && (
                              <div className="bg-green-500/10 border border-green-500/20 rounded p-2">
                                <span className="text-green-500 text-sm flex items-center gap-1">
                                  <CheckCircle className="h-3 w-3" />
                                  WPA/WPA2 Handshake Captured
                                </span>
                              </div>
                            )}
                          </CardContent>
                        </Card>
                      )
                    })}
                  </div>
                </TabsContent>

                <TabsContent value="security" className="space-y-4">
                  <Card>
                    <CardHeader>
                      <CardTitle>Security Assessment</CardTitle>
                      <CardDescription>
                        Identified security issues and vulnerabilities
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-4">
                        {result.open_networks > 0 && (
                          <div className="bg-red-500/10 border border-red-500/20 rounded p-4">
                            <h4 className="font-semibold text-red-500 mb-2">Open Networks Detected</h4>
                            <p className="text-sm text-red-400">
                              {result.open_networks} network(s) without encryption were found. 
                              These networks allow anyone to connect and intercept traffic.
                            </p>
                          </div>
                        )}
                        
                        {result.vulnerable_networks > 0 && (
                          <div className="bg-orange-500/10 border border-orange-500/20 rounded p-4">
                            <h4 className="font-semibold text-orange-500 mb-2">Vulnerable Networks</h4>
                            <p className="text-sm text-orange-400">
                              {result.vulnerable_networks} network(s) with security vulnerabilities were identified.
                              These may be susceptible to various attacks.
                            </p>
                          </div>
                        )}

                        {result.handshakes_captured > 0 && (
                          <div className="bg-yellow-500/10 border border-yellow-500/20 rounded p-4">
                            <h4 className="font-semibold text-yellow-500 mb-2">Handshakes Captured</h4>
                            <p className="text-sm text-yellow-400">
                              {result.handshakes_captured} WPA/WPA2 handshake(s) were captured.
                              These can be used for offline password attacks.
                            </p>
                          </div>
                        )}
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>

                <TabsContent value="recommendations" className="space-y-4">
                  <Card>
                    <CardHeader>
                      <CardTitle>Security Recommendations</CardTitle>
                      <CardDescription>
                        Suggested actions to improve wireless security
                      </CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="space-y-3">
                        {result.recommendations.map((rec, index) => (
                          <div key={index} className="flex items-start gap-2">
                            <CheckCircle className="h-4 w-4 text-green-500 mt-0.5 flex-shrink-0" />
                            <span className="text-sm">{rec}</span>
                          </div>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                </TabsContent>
              </Tabs>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
