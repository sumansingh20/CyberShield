'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Input } from '@/src/ui/components/ui/input'
import { Label } from '@/src/ui/components/ui/label'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Badge } from '@/src/ui/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select'
import { useApi } from '@/src/ui/hooks/useApi'
import { useToast } from '@/src/ui/hooks/use-toast'
import { Loader2, Network, Shield, AlertTriangle, CheckCircle, Info, Globe, Wifi, Server } from 'lucide-react'

interface NetworkScanResult {
  target: string
  scanType: string
  summary: string
  hosts: {
    ip: string
    hostname?: string
    status: string
    openPorts: number[]
    os?: string
    mac?: string
  }[]
  totalHosts: number
  totalPorts: number
  scanTime: number
  timestamp: string
}

export default function NetworkScannerPage() {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('discovery')
  const [portRange, setPortRange] = useState('1-1000')
  const [results, setResults] = useState<NetworkScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleScan = async () => {
    if (!target.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target IP range or hostname",
        variant: "destructive",
      })
      return
    }

    setLoading(true)
    try {
      const response = await apiCall('/api/tools/network-scanner', {
        method: 'POST',
        body: JSON.stringify({
          target: target.trim(),
          scanType,
          portRange: scanType === 'port-scan' ? portRange : undefined
        })
      })

      if (response?.success) {
        setResults(response.data)
        toast({
          title: "Success",
          description: `Network scan completed. Found ${response.data.totalHosts} hosts.`
        })
      } else {
        toast({
          title: "Error",
          description: response?.message || "Network scan failed",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('Network scan error:', error)
      toast({
        title: "Error",
        description: "Failed to perform network scan",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'up': return 'bg-green-100 text-green-800'
      case 'down': return 'bg-red-100 text-red-800'
      case 'filtered': return 'bg-yellow-100 text-yellow-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 max-w-7xl">
      {/* Header */}
      <div className="mb-6 sm:mb-8">
        <div className="flex flex-col sm:flex-row items-start sm:items-center gap-3 mb-4">
          <div className="p-2 sm:p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
            <Network className="w-5 h-5 sm:w-6 sm:h-6 text-blue-600 dark:text-blue-400" />
          </div>
          <div className="flex-1">
            <h1 className="text-2xl sm:text-3xl font-bold">Network Scanner</h1>
            <p className="text-muted-foreground text-sm sm:text-base">Comprehensive network discovery and port scanning</p>
          </div>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="text-blue-600 text-xs">
            <Globe className="w-3 h-3 mr-1" />
            Network Discovery
          </Badge>
          <Badge variant="outline" className="text-green-600 text-xs">
            <Server className="w-3 h-3 mr-1" />
            Port Scanning
          </Badge>
          <Badge variant="outline" className="text-purple-600 text-xs">
            <Wifi className="w-3 h-3 mr-1" />
            Host Detection
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4 sm:gap-6">
        {/* Scan Configuration */}
        <div className="xl:col-span-1">
          <Card>
            <CardHeader className="px-4 sm:px-6">
              <CardTitle className="flex items-center gap-2 text-lg">
                <Shield className="w-4 h-4 sm:w-5 sm:h-5" />
                Scan Configuration
              </CardTitle>
              <CardDescription className="text-sm">
                Configure your network scan parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4 px-4 sm:px-6">
              <div>
                <Label htmlFor="target" className="text-sm font-medium">Target Network/IP</Label>
                <Input
                  id="target"
                  placeholder="e.g., 192.168.1.0/24 or example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="mt-1"
                />
              </div>

              <div>
                <Label htmlFor="scanType">Scan Type</Label>
                <Select value={scanType} onValueChange={setScanType}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="discovery">Host Discovery</SelectItem>
                    <SelectItem value="port-scan">Port Scan</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {(scanType === 'port-scan' || scanType === 'comprehensive') && (
                <div>
                  <Label htmlFor="portRange">Port Range</Label>
                  <Select value={portRange} onValueChange={setPortRange}>
                    <SelectTrigger className="mt-1">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1-1000">Common Ports (1-1000)</SelectItem>
                      <SelectItem value="1-5000">Extended Range (1-5000)</SelectItem>
                      <SelectItem value="1-65535">All Ports (1-65535)</SelectItem>
                      <SelectItem value="21,22,23,25,53,80,110,443,993,995">Well-known Ports</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              )}

              <Button 
                onClick={handleScan} 
                disabled={loading} 
                className="w-full"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Network className="w-4 h-4 mr-2" />
                    Start Network Scan
                  </>
                )}
              </Button>

              {/* Information */}
              <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-blue-800 dark:text-blue-200">
                    <p className="font-medium mb-1">Scan Types:</p>
                    <ul className="space-y-1 text-xs">
                      <li>• <strong>Host Discovery:</strong> Find active hosts</li>
                      <li>• <strong>Port Scan:</strong> Find open ports on hosts</li>
                      <li>• <strong>Comprehensive:</strong> Complete analysis</li>
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Results */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Network Scan Results</CardTitle>
              <CardDescription>
                {results 
                  ? `Scan completed in ${results.scanTime}ms` 
                  : 'Results will appear here after scanning'
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              {loading && (
                <div className="flex items-center justify-center py-12">
                  <div className="text-center">
                    <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-blue-600" />
                    <p className="text-sm text-muted-foreground">Performing network scan...</p>
                  </div>
                </div>
              )}

              {results && !loading && (
                <Tabs defaultValue="summary" className="w-full">
                  <TabsList className="grid w-full grid-cols-3">
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="hosts">Hosts ({results.totalHosts})</TabsTrigger>
                    <TabsTrigger value="raw">Raw Data</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="summary" className="mt-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                      <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-green-800 dark:text-green-200">Total Hosts</p>
                            <p className="text-2xl font-bold text-green-600">{results.totalHosts}</p>
                          </div>
                          <Server className="w-8 h-8 text-green-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-blue-800 dark:text-blue-200">Open Ports</p>
                            <p className="text-2xl font-bold text-blue-600">{results.totalPorts}</p>
                          </div>
                          <Network className="w-8 h-8 text-blue-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-purple-800 dark:text-purple-200">Scan Type</p>
                            <p className="text-lg font-bold text-purple-600 capitalize">{results.scanType}</p>
                          </div>
                          <Shield className="w-8 h-8 text-purple-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-orange-800 dark:text-orange-200">Scan Time</p>
                            <p className="text-lg font-bold text-orange-600">{results.scanTime}ms</p>
                          </div>
                          <Wifi className="w-8 h-8 text-orange-600" />
                        </div>
                      </div>
                    </div>

                    <div className="p-4 bg-gray-50 dark:bg-gray-900/20 rounded-lg">
                      <h3 className="font-medium mb-2">Scan Summary</h3>
                      <p className="text-sm text-muted-foreground">{results.summary}</p>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="hosts" className="mt-4">
                    <div className="space-y-3">
                      {results.hosts.map((host, index) => (
                        <div key={index} className="p-4 border rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <h3 className="font-medium">{host.ip}</h3>
                              {host.hostname && (
                                <Badge variant="outline">{host.hostname}</Badge>
                              )}
                            </div>
                            <Badge className={getStatusColor(host.status)}>
                              {host.status.toUpperCase()}
                            </Badge>
                          </div>
                          
                          {host.openPorts.length > 0 && (
                            <div className="mb-2">
                              <p className="text-sm font-medium mb-1">Open Ports:</p>
                              <div className="flex flex-wrap gap-1">
                                {host.openPorts.map((port) => (
                                  <Badge key={port} variant="secondary" className="text-xs">
                                    {port}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                          
                          {host.os && (
                            <p className="text-sm text-muted-foreground">OS: {host.os}</p>
                          )}
                          {host.mac && (
                            <p className="text-sm text-muted-foreground">MAC: {host.mac}</p>
                          )}
                        </div>
                      ))}
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="raw" className="mt-4">
                    <Textarea
                      value={JSON.stringify(results, null, 2)}
                      readOnly
                      className="font-mono text-sm h-96"
                    />
                  </TabsContent>
                </Tabs>
              )}

              {!results && !loading && (
                <div className="text-center py-12">
                  <Network className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">Enter a target and start scanning to view results</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}