"use client"

import type React from "react"

import { useState } from "react"
import { ThemeToggle } from "@/src/ui/components/ThemeToggle"
import { TerminalOutput } from "@/components/TerminalOutput"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Card, CardContent, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Badge } from "@/src/ui/components/ui/badge"
import { ArrowLeft, Network, Shield, Info, AlertTriangle, Play } from "lucide-react"
import Link from "next/link"
import { useApi } from "@/src/ui/hooks/useApi"

export default function NetworkScanPage() {
  const [results, setResults] = useState<string>("")
  const [isScanning, setIsScanning] = useState(false)
  const [formData, setFormData] = useState({
    target: "",
    scanType: "basic",
    timing: "T3",
    ports: ""
  })
  const { apiCall, loading } = useApi()

  const handleScan = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsScanning(true)
    setResults("")

    try {
      const response = await apiCall("/api/tools/network-scan", {
        method: "POST",
        body: formData,
      })

      if (response?.output) {
        setResults(response.output)
      }
    } catch (error) {
      console.error("Network scan error:", error)
    } finally {
      setIsScanning(false)
    }
  }

  const handleInputChange = (field: string, value: string) => {
    setFormData(prev => ({
      ...prev,
      [field]: value
    }))
  }

  return (
    <div className="min-h-screen gradient-bg">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-cyber-grid opacity-5"></div>
      
      {/* Theme Toggle */}
      <div className="absolute top-4 right-4 z-10">
        <ThemeToggle />
      </div>

      <div className="relative z-10 container mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/dashboard">
            <Button variant="outline" size="sm" className="glass hover:glow-hover bg-transparent">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Dashboard
            </Button>
          </Link>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/10 glow">
              <Network className="h-6 w-6 text-purple-500" />
            </div>
            <div>
              <h1 className="text-xl font-bold">Network Scanner</h1>
              <p className="text-xs text-muted-foreground">Advanced Network Discovery & Port Scanning</p>
            </div>
          </div>
          <div className="flex gap-2 ml-auto">
            <Badge variant="secondary" className="glass">
              <Shield className="h-3 w-3 mr-1" />
              Basic
            </Badge>
          </div>
        </div>

        <div className="grid lg:grid-cols-2 gap-8">
          {/* Tool Form */}
          <div className="space-y-6">
            <Card className="glass-card">
              <CardHeader>
                <CardTitle>Network Scan Configuration</CardTitle>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleScan} className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="target">Target Network/IP</Label>
                    <Input
                      id="target"
                      value={formData.target}
                      onChange={(e) => handleInputChange("target", e.target.value)}
                      placeholder="192.168.1.0/24 or 192.168.1.1"
                      required
                      className="glass focus-ring"
                    />
                    <p className="text-xs text-muted-foreground">
                      Enter network range (CIDR) or single IP address
                    </p>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="scanType">Scan Type</Label>
                    <Select value={formData.scanType} onValueChange={(value) => handleInputChange("scanType", value)}>
                      <SelectTrigger className="glass">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="ping">Ping Sweep - Discover live hosts</SelectItem>
                        <SelectItem value="basic">Basic Scan - Common ports</SelectItem>
                        <SelectItem value="comprehensive">Comprehensive - All ports</SelectItem>
                        <SelectItem value="stealth">Stealth Scan - SYN scan</SelectItem>
                        <SelectItem value="service">Service Detection - Version detection</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="timing">Timing Template</Label>
                    <Select value={formData.timing} onValueChange={(value) => handleInputChange("timing", value)}>
                      <SelectTrigger className="glass">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="T1">T1 - Paranoid (very slow)</SelectItem>
                        <SelectItem value="T2">T2 - Sneaky (slow)</SelectItem>
                        <SelectItem value="T3">T3 - Normal (default)</SelectItem>
                        <SelectItem value="T4">T4 - Aggressive (fast)</SelectItem>
                        <SelectItem value="T5">T5 - Insane (very fast)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="ports">Port Range (Optional)</Label>
                    <Input
                      id="ports"
                      value={formData.ports}
                      onChange={(e) => handleInputChange("ports", e.target.value)}
                      placeholder="1-1000, 80,443,8080 or leave empty for defaults"
                      className="glass focus-ring"
                    />
                    <p className="text-xs text-muted-foreground">
                      Specify custom port range or leave empty for scan type defaults
                    </p>
                  </div>

                  <Button 
                    type="submit" 
                    className="w-full glow-hover group" 
                    disabled={loading || isScanning || !formData.target.trim()}
                    size="lg"
                  >
                    {isScanning ? (
                      <>
                        <div className="spinner w-4 h-4 mr-2"></div>
                        Scanning...
                      </>
                    ) : (
                      <>
                        <Play className="mr-2 h-4 w-4" />
                        Start Scan
                      </>
                    )}
                  </Button>
                </form>
              </CardContent>
            </Card>

            {/* Tool Information */}
            <Card className="glass-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Info className="h-5 w-5" />
                  About Network Scanner
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <p className="text-sm text-muted-foreground">
                  Network Scanner combines multiple techniques to discover live hosts, open ports, and running services 
                  on your network. It uses Nmap as the core scanning engine with various scan types optimized for 
                  different scenarios.
                </p>
                
                <div className="space-y-3">
                  <div>
                    <h4 className="font-medium text-sm">Scan Types:</h4>
                    <ul className="text-xs text-muted-foreground mt-1 space-y-1">
                      <li>• <strong>Ping Sweep:</strong> Quickly discover live hosts (ICMP echo)</li>
                      <li>• <strong>Basic Scan:</strong> Scan most common 1000 ports</li>
                      <li>• <strong>Comprehensive:</strong> Scan all 65535 ports (slow)</li>
                      <li>• <strong>Stealth:</strong> SYN scan to avoid detection</li>
                      <li>• <strong>Service Detection:</strong> Identify service versions</li>
                    </ul>
                  </div>
                  
                  <div>
                    <h4 className="font-medium text-sm">Common Network Ranges:</h4>
                    <ul className="text-xs text-muted-foreground mt-1 space-y-1">
                      <li>• <code>192.168.1.0/24</code> - Home networks (256 hosts)</li>
                      <li>• <code>10.0.0.0/24</code> - Corporate networks</li>
                      <li>• <code>172.16.0.0/24</code> - Private networks</li>
                      <li>• <code>127.0.0.1</code> - Local host</li>
                    </ul>
                  </div>
                </div>

                <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3">
                  <div className="flex items-start gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-500 mt-0.5 flex-shrink-0" />
                    <div className="text-xs">
                      <p className="text-amber-500 font-medium">Important Notice</p>
                      <p className="text-muted-foreground mt-1">
                        Only scan networks you own or have explicit permission to test. Unauthorized network scanning 
                        may violate laws and network policies. Always ensure you have proper authorization.
                      </p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Results */}
          <div className="space-y-6">
            <TerminalOutput
              output={results}
              isLoading={isScanning}
              title="Scan Results"
            />

            {results && (
              <Card className="glass-card">
                <CardHeader>
                  <CardTitle className="text-sm">Scan Summary</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="text-xs text-muted-foreground space-y-1">
                    <p>• Use the results to identify active hosts and services</p>
                    <p>• Open ports may indicate running services</p>
                    <p>• Consider running service detection for detailed analysis</p>
                    <p>• Document findings for security assessment</p>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
