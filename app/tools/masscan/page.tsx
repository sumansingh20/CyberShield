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
import { Loader2, Zap, Shield, AlertTriangle, CheckCircle, Info, Activity, Timer, Target } from 'lucide-react'

interface MasscanResult {
  target: string
  portRange: string
  rate: number
  summary: string
  openPorts: {
    ip: string
    port: number
    protocol: 'tcp' | 'udp'
    service?: string
    banner?: string
    timestamp: string
  }[]
  statistics: {
    totalHosts: number
    totalPorts: number
    scannedPorts: number
    scanRate: number
    packetsPerSecond: number
  }
  scanTime: number
  timestamp: string
}

export default function MasscanPage() {
  const [target, setTarget] = useState('')
  const [portRange, setPortRange] = useState('1-65535')
  const [rate, setRate] = useState('1000')
  const [protocol, setProtocol] = useState('tcp')
  const [results, setResults] = useState<MasscanResult | null>(null)
  const [loading, setLoading] = useState(false)
  
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleScan = async () => {
    if (!target.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target IP or IP range",
        variant: "destructive",
      })
      return
    }

    const rateNum = parseInt(rate)
    if (isNaN(rateNum) || rateNum < 1 || rateNum > 100000) {
      toast({
        title: "Error",
        description: "Scan rate must be between 1 and 100,000 packets/second",
        variant: "destructive",
      })
      return
    }

    setLoading(true)
    try {
      const response = await apiCall('/api/tools/masscan', {
        method: 'POST',
        body: JSON.stringify({
          target: target.trim(),
          portRange,
          rate: rateNum,
          protocol
        })
      })

      if (response?.success) {
        setResults(response.data)
        toast({
          title: "Success",
          description: `Masscan completed. Found ${response.data.openPorts.length} open ports.`
        })
      } else {
        toast({
          title: "Error",
          description: response?.message || "Masscan failed",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('Masscan error:', error)
      toast({
        title: "Error",
        description: "Failed to perform Masscan",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const getProtocolColor = (protocol: string) => {
    switch (protocol.toLowerCase()) {
      case 'tcp': return 'bg-blue-100 text-blue-800'
      case 'udp': return 'bg-purple-100 text-purple-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const formatNumber = (num: number) => {
    return new Intl.NumberFormat().format(num)
  }

  const getServiceName = (port: number) => {
    const services: { [key: number]: string } = {
      21: 'FTP',
      22: 'SSH',
      23: 'Telnet',
      25: 'SMTP',
      53: 'DNS',
      80: 'HTTP',
      110: 'POP3',
      143: 'IMAP',
      443: 'HTTPS',
      993: 'IMAPS',
      995: 'POP3S'
    }
    return services[port] || 'Unknown'
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-yellow-100 dark:bg-yellow-900/20 rounded-lg">
            <Zap className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold">Masscan</h1>
            <p className="text-muted-foreground">High-speed port scanner for large-scale network analysis</p>
          </div>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="text-yellow-600">
            <Zap className="w-3 h-3 mr-1" />
            Ultra-Fast Scanning
          </Badge>
          <Badge variant="outline" className="text-red-600">
            <Activity className="w-3 h-3 mr-1" />
            High Performance
          </Badge>
          <Badge variant="outline" className="text-blue-600">
            <Target className="w-3 h-3 mr-1" />
            Large Networks
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan Configuration */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Scan Configuration
              </CardTitle>
              <CardDescription>
                Configure high-speed network scanning parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="target">Target IP/Range</Label>
                <Input
                  id="target"
                  placeholder="e.g., 192.168.1.0/24 or 10.0.0.1-10.0.0.255"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="mt-1"
                />
              </div>

              <div>
                <Label htmlFor="portRange">Port Range</Label>
                <Select value={portRange} onValueChange={setPortRange}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1-1000">Top 1000 Ports</SelectItem>
                    <SelectItem value="1-65535">All Ports (1-65535)</SelectItem>
                    <SelectItem value="21,22,23,25,53,80,110,443,993,995">Common Services</SelectItem>
                    <SelectItem value="80,443,8080,8443,8000,8888">Web Servers</SelectItem>
                    <SelectItem value="21,22,23,3389">Remote Access</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="rate">Scan Rate (packets/sec)</Label>
                <Select value={rate} onValueChange={setRate}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="100">Conservative (100)</SelectItem>
                    <SelectItem value="1000">Standard (1,000)</SelectItem>
                    <SelectItem value="10000">Fast (10,000)</SelectItem>
                    <SelectItem value="50000">Very Fast (50,000)</SelectItem>
                    <SelectItem value="100000">Maximum (100,000)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="protocol">Protocol</Label>
                <Select value={protocol} onValueChange={setProtocol}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="tcp">TCP</SelectItem>
                    <SelectItem value="udp">UDP</SelectItem>
                    <SelectItem value="both">Both TCP & UDP</SelectItem>
                  </SelectContent>
                </Select>
              </div>

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
                    <Zap className="w-4 h-4 mr-2" />
                    Start Masscan
                  </>
                )}
              </Button>

              {/* Warning */}
              <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-red-600 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-red-800 dark:text-red-200">
                    <p className="font-medium mb-1">High-Impact Scanning</p>
                    <p className="text-xs">Masscan generates significant network traffic. Use responsibly and only on authorized networks.</p>
                  </div>
                </div>
              </div>

              {/* Performance Info */}
              <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-yellow-600 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-yellow-800 dark:text-yellow-200">
                    <p className="font-medium mb-1">Performance Tips:</p>
                    <ul className="space-y-1 text-xs">
                      <li>• Higher rates = faster scans but more network load</li>
                      <li>• TCP scans are more reliable than UDP</li>
                      <li>• Use smaller port ranges for targeted scans</li>
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
              <CardTitle>Masscan Results</CardTitle>
              <CardDescription>
                {results 
                  ? `Scan completed in ${(results.scanTime / 1000).toFixed(2)}s at ${formatNumber(results.statistics.packetsPerSecond)} pps` 
                  : 'High-speed scan results will appear here'
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              {loading && (
                <div className="flex items-center justify-center py-12">
                  <div className="text-center">
                    <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-yellow-600" />
                    <p className="text-sm text-muted-foreground">Performing high-speed port scan...</p>
                    <p className="text-xs text-muted-foreground mt-1">This may generate significant network traffic</p>
                  </div>
                </div>
              )}

              {results && !loading && (
                <Tabs defaultValue="summary" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="ports">Open Ports ({results.openPorts.length})</TabsTrigger>
                    <TabsTrigger value="statistics">Statistics</TabsTrigger>
                    <TabsTrigger value="raw">Raw Data</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="summary" className="mt-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                      <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-green-800 dark:text-green-200">Open Ports</p>
                            <p className="text-2xl font-bold text-green-600">{results.openPorts.length}</p>
                          </div>
                          <CheckCircle className="w-8 h-8 text-green-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-blue-800 dark:text-blue-200">Hosts Scanned</p>
                            <p className="text-2xl font-bold text-blue-600">{formatNumber(results.statistics.totalHosts)}</p>
                          </div>
                          <Target className="w-8 h-8 text-blue-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200">Scan Rate</p>
                            <p className="text-lg font-bold text-yellow-600">{formatNumber(results.statistics.scanRate)} pps</p>
                          </div>
                          <Zap className="w-8 h-8 text-yellow-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-purple-800 dark:text-purple-200">Scan Time</p>
                            <p className="text-lg font-bold text-purple-600">{(results.scanTime / 1000).toFixed(2)}s</p>
                          </div>
                          <Timer className="w-8 h-8 text-purple-600" />
                        </div>
                      </div>
                    </div>

                    <div className="p-4 bg-gray-50 dark:bg-gray-900/20 rounded-lg">
                      <h3 className="font-medium mb-2">Scan Summary</h3>
                      <p className="text-sm text-muted-foreground">{results.summary}</p>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="ports" className="mt-4">
                    <div className="space-y-3">
                      {results.openPorts.map((port, index) => (
                        <div key={index} className="p-4 border rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <span className="font-mono font-medium">{port.ip}:{port.port}</span>
                              <Badge variant="outline" className="text-xs">
                                {getServiceName(port.port)}
                              </Badge>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge className={getProtocolColor(port.protocol)}>
                                {port.protocol.toUpperCase()}
                              </Badge>
                            </div>
                          </div>
                          
                          {port.service && (
                            <p className="text-sm text-muted-foreground mb-1">Service: {port.service}</p>
                          )}
                          {port.banner && (
                            <p className="text-sm text-muted-foreground mb-1">Banner: {port.banner}</p>
                          )}
                          <p className="text-xs text-muted-foreground">
                            Discovered: {new Date(port.timestamp).toLocaleString()}
                          </p>
                        </div>
                      ))}
                      {results.openPorts.length === 0 && (
                        <div className="text-center py-8 text-muted-foreground">
                          No open ports discovered
                        </div>
                      )}
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="statistics" className="mt-4">
                    <div className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="p-4 border rounded-lg">
                          <h3 className="font-medium mb-2">Scan Statistics</h3>
                          <div className="space-y-2 text-sm">
                            <div className="flex justify-between">
                              <span>Total Hosts:</span>
                              <span className="font-mono">{formatNumber(results.statistics.totalHosts)}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Total Ports:</span>
                              <span className="font-mono">{formatNumber(results.statistics.totalPorts)}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Scanned Ports:</span>
                              <span className="font-mono">{formatNumber(results.statistics.scannedPorts)}</span>
                            </div>
                          </div>
                        </div>
                        
                        <div className="p-4 border rounded-lg">
                          <h3 className="font-medium mb-2">Performance Metrics</h3>
                          <div className="space-y-2 text-sm">
                            <div className="flex justify-between">
                              <span>Scan Rate:</span>
                              <span className="font-mono">{formatNumber(results.statistics.scanRate)} pps</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Packets/Second:</span>
                              <span className="font-mono">{formatNumber(results.statistics.packetsPerSecond)}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Duration:</span>
                              <span className="font-mono">{(results.scanTime / 1000).toFixed(2)}s</span>
                            </div>
                          </div>
                        </div>
                      </div>
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
                  <Zap className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">Configure scan parameters and start Masscan to view results</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}