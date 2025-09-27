"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Shield, Wifi, CheckCircle, AlertCircle, Loader2 } from "lucide-react"
import { useApi } from "@/src/ui/hooks/useApi"
import { useToast } from "@/src/ui/hooks/use-toast"

export default function PortScannerPage() {
  const [target, setTarget] = useState("")
  const [ports, setPorts] = useState("80,443,22,21,25,53,135,139,445")
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
      const response = await apiCall("/api/tools/port-scanner", {
        method: "POST",
        body: { 
          target: target.trim(),
          ports: ports // Send as string, API will parse it
        },
        requiresAuth: false
      })

      if (response && response.success) {
        setResults(response.data)
        toast({
          title: "Success",
          description: `Scan completed. Found ${response.data.openPorts || 0} open ports`
        })
      } else {
        throw new Error(response?.message || 'Port scan failed')
      }
    } catch (error) {
      toast({
        title: "Error", 
        description: error instanceof Error ? error.message : "Failed to perform port scan",
        variant: "destructive"
      })
    } finally {
      setIsLoading(false)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'open': return 'text-green-600 bg-green-100 dark:bg-green-900'
      case 'closed': return 'text-red-600 bg-red-100 dark:bg-red-900'
      case 'filtered': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900'
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-900'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-6 sm:mb-8">
          <div className="flex flex-col sm:flex-row items-center justify-center mb-4 gap-2 sm:gap-4">
            <Shield className="h-8 w-8 sm:h-10 sm:w-10 lg:h-12 lg:w-12 text-blue-500" />
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent text-center">
              Port Scanner
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-300 text-sm sm:text-base lg:text-lg px-2 sm:px-4">
            Scan for open ports and running services
          </p>
          <Badge className="mt-2" variant="outline">Intermediate</Badge>
        </div>

        {/* Input Form */}
        <Card className="mb-6 sm:mb-8 mx-2 sm:mx-0">
          <CardHeader className="px-4 sm:px-6">
            <CardTitle className="flex items-center text-lg sm:text-xl">
              <Wifi className="h-4 w-4 sm:h-5 sm:w-5 mr-2" />
              Scan Configuration
            </CardTitle>
            <CardDescription className="text-sm">
              Configure your port scan parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="px-4 sm:px-6">
            <div className="space-y-4">
              <div>
                <Label htmlFor="target" className="text-sm font-medium">Target (IP or Domain)</Label>
                <Input
                  id="target"
                  placeholder="192.168.1.1 or example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="mt-1"
                />
              </div>
              <div>
                <Label htmlFor="ports" className="text-sm font-medium">Ports (comma separated)</Label>
                <Input
                  id="ports"
                  placeholder="80,443,22,21,25,53"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  className="mt-1"
                />
                <p className="text-xs sm:text-sm text-gray-500 mt-1">
                  Common ports: 80 (HTTP), 443 (HTTPS), 22 (SSH), 21 (FTP), 25 (SMTP), 53 (DNS)
                </p>
              </div>
              <Button 
                onClick={handleScan}
                disabled={isLoading}
                className="w-full"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Shield className="h-4 w-4 mr-2" />
                    Start Port Scan
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
                Scan Results
              </CardTitle>
              <CardDescription className="text-sm">
                Port scan results for {results.target}
              </CardDescription>
            </CardHeader>
            <CardContent className="px-4 sm:px-6">
              {results.ports?.open && results.ports.open.length > 0 ? (
                <div className="space-y-3">
                  {results.ports.open.map((port: any, index: number) => (
                    <div key={index} className="flex flex-col sm:flex-row sm:items-center justify-between p-3 sm:p-4 bg-gray-50 dark:bg-gray-700 rounded-lg gap-2 sm:gap-4">
                      <div className="flex items-start sm:items-center">
                        <div className="font-mono text-base sm:text-lg font-semibold mr-3 sm:mr-4 min-w-0">
                          {port.port}
                        </div>
                        <div className="min-w-0 flex-1">
                          <div className="font-medium text-sm sm:text-base truncate">{port.service || 'Unknown Service'}</div>
                          <div className="text-xs sm:text-sm text-gray-500">TCP</div>
                          {port.banner && (
                            <div className="text-xs text-gray-400 mt-1 break-all">
                              {port.banner}
                            </div>
                          )}
                          {port.responseTime && (
                            <div className="text-xs text-gray-400">
                              Response: {port.responseTime}ms
                            </div>
                          )}
                        </div>
                      </div>
                      <Badge className="text-green-600 bg-green-100 dark:bg-green-900 shrink-0">
                        Open
                      </Badge>
                    </div>
                  ))}
                  
                  {/* Summary Statistics */}
                  <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <h4 className="font-semibold text-blue-800 dark:text-blue-200 mb-2 text-sm sm:text-base">Scan Summary</h4>
                    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 sm:gap-4 text-xs sm:text-sm">
                      <div>
                        <div className="text-gray-600 dark:text-gray-400">Total Scanned</div>
                        <div className="font-semibold">{results.totalPorts}</div>
                      </div>
                      <div>
                        <div className="text-gray-600 dark:text-gray-400">Open Ports</div>
                        <div className="font-semibold text-green-600">{results.openPorts}</div>
                      </div>
                      <div>
                        <div className="text-gray-600 dark:text-gray-400">Closed Ports</div>
                        <div className="font-semibold text-red-600">{results.closedPorts}</div>
                      </div>
                      <div>
                        <div className="text-gray-600 dark:text-gray-400">Scan Time</div>
                        <div className="font-semibold">{(results.executionTime / 1000).toFixed(2)}s</div>
                      </div>
                    </div>
                  </div>

                  {/* Security Flags */}
                  {results.securityFlags && results.securityFlags.length > 0 && (
                    <div className="mt-4 p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                      <h4 className="font-semibold text-yellow-800 dark:text-yellow-200 mb-2">Security Observations</h4>
                      <ul className="space-y-1">
                        {results.securityFlags.map((flag: string, index: number) => (
                          <li key={index} className="text-sm text-yellow-700 dark:text-yellow-300 flex items-center">
                            <AlertCircle className="h-3 w-3 mr-2" />
                            {flag}
                          </li>
                        ))}
                      </ul>
                    </div>
                  )}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <AlertCircle className="h-8 w-8 mx-auto mb-2" />
                  <p>No open ports found</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Info */}
        <Card className="mt-6 sm:mt-8 mx-2 sm:mx-0">
          <CardHeader className="px-4 sm:px-6">
            <CardTitle className="text-lg sm:text-xl">About Port Scanning</CardTitle>
          </CardHeader>
          <CardContent className="px-4 sm:px-6">
            <div className="prose dark:prose-invert max-w-none text-sm sm:text-base">
              <p>
                Port scanning is a reconnaissance technique used to discover open ports and services 
                running on a target system. This information helps identify potential attack vectors 
                and security vulnerabilities.
              </p>
              <h4>Common port states:</h4>
              <ul>
                <li><strong>Open:</strong> Port is accepting connections</li>
                <li><strong>Closed:</strong> Port is not accepting connections</li>
                <li><strong>Filtered:</strong> Port is blocked by firewall</li>
              </ul>
              <div className="mt-4 p-3 sm:p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                <p className="text-xs sm:text-sm text-yellow-800 dark:text-yellow-200">
                  <strong>Note:</strong> Only use this tool on systems you own or have explicit permission to test.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}