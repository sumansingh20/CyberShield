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
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <div className="container mx-auto max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Shield className="h-12 w-12 text-blue-500 mr-4" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              Port Scanner
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-300 text-lg">
            Scan for open ports and running services
          </p>
          <Badge className="mt-2" variant="outline">Intermediate</Badge>
        </div>

        {/* Input Form */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center">
              <Wifi className="h-5 w-5 mr-2" />
              Scan Configuration
            </CardTitle>
            <CardDescription>
              Configure your port scan parameters
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <Label htmlFor="target">Target (IP or Domain)</Label>
                <Input
                  id="target"
                  placeholder="192.168.1.1 or example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="mt-1"
                />
              </div>
              <div>
                <Label htmlFor="ports">Ports (comma separated)</Label>
                <Input
                  id="ports"
                  placeholder="80,443,22,21,25,53"
                  value={ports}
                  onChange={(e) => setPorts(e.target.value)}
                  className="mt-1"
                />
                <p className="text-sm text-gray-500 mt-1">
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
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <CheckCircle className="h-5 w-5 mr-2 text-green-500" />
                Scan Results
              </CardTitle>
              <CardDescription>
                Port scan results for {results.target}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {results.ports?.open && results.ports.open.length > 0 ? (
                <div className="space-y-3">
                  {results.ports.open.map((port: any, index: number) => (
                    <div key={index} className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                      <div className="flex items-center">
                        <div className="font-mono text-lg font-semibold mr-4">
                          {port.port}
                        </div>
                        <div>
                          <div className="font-medium">{port.service || 'Unknown Service'}</div>
                          <div className="text-sm text-gray-500">TCP</div>
                          {port.banner && (
                            <div className="text-xs text-gray-400 mt-1 max-w-md truncate">
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
                      <Badge className="text-green-600 bg-green-100 dark:bg-green-900">
                        Open
                      </Badge>
                    </div>
                  ))}
                  
                  {/* Summary Statistics */}
                  <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <h4 className="font-semibold text-blue-800 dark:text-blue-200 mb-2">Scan Summary</h4>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
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
        <Card className="mt-8">
          <CardHeader>
            <CardTitle>About Port Scanning</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="prose dark:prose-invert max-w-none">
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
              <div className="mt-4 p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                <p className="text-sm text-yellow-800 dark:text-yellow-200">
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