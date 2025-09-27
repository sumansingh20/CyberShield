"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Shield, Network, CheckCircle, AlertCircle, Loader2, Router } from "lucide-react"
import { useApi } from "@/src/ui/hooks/useApi"
import { useToast } from "@/src/ui/hooks/use-toast"

export default function NetworkScannerPage() {
  const [target, setTarget] = useState("")
  const [scanType, setScanType] = useState("discovery")
  const [portRange, setPortRange] = useState("21,22,23,25,53,80,110,443,993,995")
  const [results, setResults] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(false)
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleScan = async () => {
    if (!target.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target to scan",
        variant: "destructive"
      })
      return
    }

    setIsLoading(true)
    setResults(null)

    try {
      const response = await apiCall("/api/tools/network-scanner", {
        method: "POST",
        body: { 
          target: target.trim(),
          scanType,
          portRange: scanType !== 'discovery' ? portRange : undefined
        },
        requiresAuth: false
      })

      if (response && response.success) {
        setResults(response.data)
        toast({
          title: "Success",
          description: response.data.summary || "Network scan completed successfully"
        })
      } else {
        throw new Error(response?.message || 'Network scan failed')
      }
    } catch (error) {
      toast({
        title: "Error", 
        description: error instanceof Error ? error.message : "Failed to perform network scan",
        variant: "destructive"
      })
    } finally {
      setIsLoading(false)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'up': return 'text-green-600 bg-green-100 dark:bg-green-900'
      case 'down': return 'text-red-600 bg-red-100 dark:bg-red-900'
      case 'error': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900'
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-900'
    }
  }

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel) {
      case 'LOW': return 'text-green-600 bg-green-100 dark:bg-green-900'
      case 'MEDIUM': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900'
      case 'HIGH': return 'text-orange-600 bg-orange-100 dark:bg-orange-900'
      case 'CRITICAL': return 'text-red-600 bg-red-100 dark:bg-red-900'
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-900'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-6 sm:mb-8">
          <div className="flex flex-col sm:flex-row items-center justify-center mb-4 gap-2 sm:gap-4">
            <Network className="h-8 w-8 sm:h-10 sm:w-10 lg:h-12 lg:w-12 text-blue-500" />
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent text-center">
              Network Scanner
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-300 text-sm sm:text-base lg:text-lg px-2 sm:px-4">
            Discover hosts and analyze network infrastructure
          </p>
          <Badge className="mt-2" variant="outline">Advanced</Badge>
        </div>

        {/* Input Form */}
        <Card className="mb-6 sm:mb-8 mx-2 sm:mx-0">
          <CardHeader className="px-4 sm:px-6">
            <CardTitle className="flex items-center text-lg sm:text-xl">
              <Router className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
              Scan Configuration
            </CardTitle>
            <CardDescription className="text-sm">
              Configure your network scan parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="px-4 sm:px-6">
            <div className="space-y-4">
              <div>
                <Label htmlFor="target" className="text-sm font-medium">Target (IP, Domain, or CIDR)</Label>
                <Input
                  id="target"
                  placeholder="192.168.1.0/24 or 192.168.1.1-10 or example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="mt-1"
                />
                <p className="text-xs sm:text-sm text-gray-500 mt-1">
                  Supports: Single IP, hostname, CIDR range (192.168.1.0/24), IP range (192.168.1.1-10)
                </p>
              </div>
              
              <div>
                <Label htmlFor="scanType" className="text-sm font-medium">Scan Type</Label>
                <Select value={scanType} onValueChange={setScanType}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="discovery">Discovery (Host Detection)</SelectItem>
                    <SelectItem value="port-scan">Port Scan (with Service Detection)</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive (Security Analysis)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {scanType !== 'discovery' && (
                <div>
                  <Label htmlFor="portRange" className="text-sm font-medium">Port Range</Label>
                  <Select value={portRange} onValueChange={setPortRange}>
                    <SelectTrigger className="mt-1">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="21,22,23,25,53,80,110,443,993,995">Common Ports</SelectItem>
                      <SelectItem value="1-1000">Extended Range (1-1000)</SelectItem>
                      <SelectItem value="1-5000">Full Range (1-5000)</SelectItem>
                    </SelectContent>
                  </Select>
                  <p className="text-xs sm:text-sm text-gray-500 mt-1">
                    More ports = longer scan time
                  </p>
                </div>
              )}
              
              <Button 
                onClick={handleScan}
                disabled={isLoading}
                className="w-full"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Scanning Network...
                  </>
                ) : (
                  <>
                    <Network className="h-4 w-4 mr-2" />
                    Start Network Scan
                  </>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        {results && (
          <Card className="mx-2 sm:mx-0">
            <CardHeader className="px-4 sm:px-6">
              <CardTitle className="flex items-center text-lg sm:text-xl">
                <CheckCircle className="h-4 w-4 sm:h-5 sm:w-5 mr-2 text-green-500" />
                Network Scan Results
              </CardTitle>
              <CardDescription className="text-sm">
                {results.summary}
              </CardDescription>
            </CardHeader>
            <CardContent className="px-4 sm:px-6">
              {results.hosts && results.hosts.length > 0 ? (
                <div className="space-y-4">
                  {/* Security Summary for comprehensive scans */}
                  {results.securitySummary && (
                    <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg mb-6">
                      <h4 className="font-semibold text-blue-800 dark:text-blue-200 mb-3">Security Overview</h4>
                      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
                        <div>
                          <div className="text-gray-600 dark:text-gray-400">Critical Hosts</div>
                          <div className="font-bold text-red-600">{results.securitySummary.criticalHosts}</div>
                        </div>
                        <div>
                          <div className="text-gray-600 dark:text-gray-400">High Risk Hosts</div>
                          <div className="font-bold text-orange-600">{results.securitySummary.highRiskHosts}</div>
                        </div>
                        <div>
                          <div className="text-gray-600 dark:text-gray-400">Vulnerabilities</div>
                          <div className="font-bold text-yellow-600">{results.securitySummary.vulnerabilityCount}</div>
                        </div>
                        <div>
                          <div className="text-gray-600 dark:text-gray-400">Avg Security Score</div>
                          <div className="font-bold text-green-600">{results.securitySummary.averageSecurityScore}%</div>
                        </div>
                      </div>
                    </div>
                  )}

                  {/* Host Results */}
                  {results.hosts.map((host: any, index: number) => (
                    <div key={index} className="border rounded-lg p-4 space-y-3">
                      {/* Host Header */}
                      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
                        <div className="flex items-center space-x-3">
                          <div className="font-mono text-lg font-semibold">{host.ip}</div>
                          {host.hostname && (
                            <div className="text-gray-600 dark:text-gray-400">({host.hostname})</div>
                          )}
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge className={getStatusColor(host.status)}>
                            {host.status.toUpperCase()}
                          </Badge>
                          {host.securityAnalysis && (
                            <Badge className={getRiskColor(host.securityAnalysis.riskLevel)}>
                              {host.securityAnalysis.riskLevel} RISK
                            </Badge>
                          )}
                        </div>
                      </div>

                      {/* Host Details */}
                      {host.responseTime && (
                        <div className="text-sm text-gray-600 dark:text-gray-400">
                          Response Time: {host.responseTime}ms
                        </div>
                      )}

                      {/* Device Fingerprint */}
                      {host.deviceFingerprint && (
                        <div className="bg-gray-50 dark:bg-gray-800 p-3 rounded-lg">
                          <h5 className="font-semibold mb-2">Device Information</h5>
                          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-sm">
                            <div>
                              <span className="text-gray-600 dark:text-gray-400">OS:</span> {host.deviceFingerprint.osGuess}
                            </div>
                            <div>
                              <span className="text-gray-600 dark:text-gray-400">Type:</span> {host.deviceFingerprint.deviceType}
                            </div>
                            <div>
                              <span className="text-gray-600 dark:text-gray-400">Confidence:</span> {host.deviceFingerprint.confidence}%
                            </div>
                          </div>
                        </div>
                      )}

                      {/* Open Ports */}
                      {host.openPorts && host.openPorts.length > 0 && (
                        <div className="bg-green-50 dark:bg-green-900/20 p-3 rounded-lg">
                          <h5 className="font-semibold text-green-800 dark:text-green-200 mb-2">
                            Open Ports ({host.openPorts.length})
                          </h5>
                          <div className="flex flex-wrap gap-2">
                            {host.openPorts.map((port: number) => (
                              <span key={port} className="px-2 py-1 bg-green-100 dark:bg-green-800 text-green-800 dark:text-green-200 text-xs rounded">
                                {port}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Services */}
                      {host.services && host.services.length > 0 && (
                        <div className="space-y-2">
                          <h5 className="font-semibold">Detected Services</h5>
                          <div className="space-y-2">
                            {host.services.map((service: any, sIndex: number) => (
                              <div key={sIndex} className="flex justify-between items-center p-2 bg-gray-50 dark:bg-gray-800 rounded">
                                <div>
                                  <span className="font-mono font-semibold">{service.port}</span>
                                  <span className="ml-2">{service.service}</span>
                                </div>
                                {service.version && (
                                  <span className="text-sm text-gray-600 dark:text-gray-400">{service.version}</span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Security Analysis */}
                      {host.securityAnalysis && (
                        <div className="border-t pt-3 space-y-3">
                          <div className="flex items-center justify-between">
                            <h5 className="font-semibold">Security Analysis</h5>
                            <div className="text-lg font-bold">
                              Score: {host.securityAnalysis.securityScore}/100
                            </div>
                          </div>

                          {/* Vulnerabilities */}
                          {host.securityAnalysis.vulnerabilities.length > 0 && (
                            <div className="bg-red-50 dark:bg-red-900/20 p-3 rounded-lg">
                              <h6 className="font-semibold text-red-800 dark:text-red-200 mb-2">
                                Vulnerabilities ({host.securityAnalysis.vulnerabilities.length})
                              </h6>
                              <div className="space-y-2">
                                {host.securityAnalysis.vulnerabilities.map((vuln: any, vIndex: number) => (
                                  <div key={vIndex} className="text-sm">
                                    <div className="flex items-center space-x-2">
                                      <Badge className={getRiskColor(vuln.severity)}>
                                        {vuln.severity}
                                      </Badge>
                                      <span className="font-medium">{vuln.type}</span>
                                    </div>
                                    <p className="text-gray-700 dark:text-gray-300 mt-1">{vuln.description}</p>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Recommendations */}
                          {host.securityAnalysis.recommendations.length > 0 && (
                            <div className="bg-blue-50 dark:bg-blue-900/20 p-3 rounded-lg">
                              <h6 className="font-semibold text-blue-800 dark:text-blue-200 mb-2">Recommendations</h6>
                              <ul className="text-sm space-y-1">
                                {host.securityAnalysis.recommendations.map((rec: string, rIndex: number) => (
                                  <li key={rIndex} className="text-blue-700 dark:text-blue-300">{rec}</li>
                                ))}
                              </ul>
                            </div>
                          )}
                        </div>
                      )}
                    </div>
                  ))}

                  {/* Scan Summary */}
                  <div className="mt-6 p-4 bg-gray-50 dark:bg-gray-800 rounded-lg">
                    <h4 className="font-semibold mb-3">Scan Summary</h4>
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 text-sm">
                      <div>
                        <div className="text-gray-600 dark:text-gray-400">Active Hosts</div>
                        <div className="font-semibold text-green-600">{results.totalHosts}</div>
                      </div>
                      {results.totalPorts !== undefined && (
                        <div>
                          <div className="text-gray-600 dark:text-gray-400">Open Ports</div>
                          <div className="font-semibold text-blue-600">{results.totalPorts}</div>
                        </div>
                      )}
                      <div>
                        <div className="text-gray-600 dark:text-gray-400">Scan Time</div>
                        <div className="font-semibold">{(results.scanTime / 1000).toFixed(2)}s</div>
                      </div>
                      <div>
                        <div className="text-gray-600 dark:text-gray-400">Scan Type</div>
                        <div className="font-semibold capitalize">{results.scanType}</div>
                      </div>
                    </div>
                  </div>
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <AlertCircle className="h-8 w-8 mx-auto mb-2" />
                  <p>No active hosts found in the specified range</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Info */}
        <Card className="mt-6 sm:mt-8 mx-2 sm:mx-0">
          <CardHeader className="px-4 sm:px-6">
            <CardTitle className="text-lg sm:text-xl">About Network Scanning</CardTitle>
          </CardHeader>
          <CardContent className="px-4 sm:px-6">
            <div className="prose dark:prose-invert max-w-none text-sm sm:text-base">
              <p>
                Network scanning is a method for discovering active hosts, open ports, and running 
                services on a network. It's essential for network inventory, security assessment, 
                and identifying potential vulnerabilities.
              </p>
              <h4>Scan Types:</h4>
              <ul>
                <li><strong>Discovery:</strong> Basic host discovery using ping</li>
                <li><strong>Port Scan:</strong> Identifies open ports and services</li>
                <li><strong>Comprehensive:</strong> Includes security analysis and device fingerprinting</li>
              </ul>
              <h4>Supported Targets:</h4>
              <ul>
                <li><strong>Single IP:</strong> 192.168.1.1</li>
                <li><strong>Hostname:</strong> example.com</li>
                <li><strong>CIDR Range:</strong> 192.168.1.0/24</li>
                <li><strong>IP Range:</strong> 192.168.1.1-10</li>
              </ul>
              <div className="mt-4 p-3 sm:p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                <p className="text-xs sm:text-sm text-yellow-800 dark:text-yellow-200">
                  <strong>Important:</strong> Only scan networks you own or have explicit permission to test. 
                  Unauthorized network scanning may be illegal.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}