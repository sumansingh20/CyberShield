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
import { Loader2, Target, Shield, AlertTriangle, CheckCircle, Info, Globe, Server, Eye, Zap, Terminal } from 'lucide-react'

interface NmapScanResult {
  target: string
  scanType: string
  summary: string
  hosts: Array<{
    ip: string
    hostname: string
    status: string
    ports: Array<{
      port: number
      state: string
      service: string
      version: string
      protocol: string
    }>
    os: string
    services: Array<{
      port: number
      service: string
      version: string
      state: string
    }>
  }>
  scanTime: number
  timestamp: string
}

export default function NmapPage() {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('syn-scan')
  const [portRange, setPortRange] = useState('top-100')
  const [timing, setTiming] = useState('normal')
  const [results, setResults] = useState<NmapScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleScan = async () => {
    if (!target.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target IP address, hostname, or network range",
        variant: "destructive",
      })
      return
    }

    setLoading(true)
    try {
      const response = await apiCall('/api/tools/nmap', {
        method: 'POST',
        body: JSON.stringify({
          target: target.trim(),
          scanType,
          options: {
            portRange,
            timing,
            osDetection: true,
            serviceVersion: true
          }
        })
      })

      if (response?.success) {
        setResults(response.data)
        const totalHosts = response.data.hosts.length
        const upHosts = response.data.hosts.filter((h: any) => h.status === 'up').length
        toast({
          title: "Success",
          description: `Advanced scan completed. Found ${upHosts}/${totalHosts} hosts up.`
        })
      } else {
        toast({
          title: "Error",
          description: response?.message || "Advanced scan failed",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('Nmap scan error:', error)
      toast({
        title: "Error",
        description: "Failed to perform advanced scan",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const getStatusColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'up': return 'bg-green-100 text-green-800 border-green-200'
      case 'down': return 'bg-red-100 text-red-800 border-red-200'
      case 'filtered': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getPortStateColor = (state: string) => {
    switch (state.toLowerCase()) {
      case 'open': return 'bg-green-100 text-green-800'
      case 'closed': return 'bg-red-100 text-red-800'
      case 'filtered': return 'bg-yellow-100 text-yellow-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-orange-100 dark:bg-orange-900/20 rounded-lg">
            <Target className="w-6 h-6 text-orange-600 dark:text-orange-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold">Nmap Advanced</h1>
            <p className="text-muted-foreground">Professional network mapping with stealth techniques</p>
          </div>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="text-orange-600">
            <Target className="w-3 h-3 mr-1" />
            Advanced Scanning
          </Badge>
          <Badge variant="outline" className="text-red-600">
            <Eye className="w-3 h-3 mr-1" />
            Stealth Techniques
          </Badge>
          <Badge variant="outline" className="text-blue-600">
            <Server className="w-3 h-3 mr-1" />
            OS Detection
          </Badge>
          <Badge variant="outline" className="text-purple-600">
            <Zap className="w-3 h-3 mr-1" />
            Service Enumeration
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan Configuration */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="w-5 h-5" />
                Advanced Configuration
              </CardTitle>
              <CardDescription>
                Configure professional-grade Nmap scanning parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="target">Target Network</Label>
                <Input
                  id="target"
                  placeholder="e.g., 192.168.1.0/24, scanme.nmap.org"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="mt-1"
                />
              </div>

              <div>
                <Label htmlFor="scanType">Scan Technique</Label>
                <Select value={scanType} onValueChange={setScanType}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="syn-scan">SYN Scan (Stealth)</SelectItem>
                    <SelectItem value="connect-scan">TCP Connect Scan</SelectItem>
                    <SelectItem value="stealth">Advanced Stealth Scan</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
                    <SelectItem value="aggressive">Aggressive Scan</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="portRange">Port Range</Label>
                <Select value={portRange} onValueChange={setPortRange}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="top-100">Top 100 Ports</SelectItem>
                    <SelectItem value="top-1000">Top 1000 Ports</SelectItem>
                    <SelectItem value="1-1000">Ports 1-1000</SelectItem>
                    <SelectItem value="1-65535">All Ports (1-65535)</SelectItem>
                    <SelectItem value="21,22,23,25,53,80,110,443">Common Services</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="timing">Timing Template</Label>
                <Select value={timing} onValueChange={setTiming}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="paranoid">T0 - Paranoid (Very Slow)</SelectItem>
                    <SelectItem value="sneaky">T1 - Sneaky (Slow)</SelectItem>
                    <SelectItem value="polite">T2 - Polite</SelectItem>
                    <SelectItem value="normal">T3 - Normal (Default)</SelectItem>
                    <SelectItem value="aggressive">T4 - Aggressive</SelectItem>
                    <SelectItem value="insane">T5 - Insane (Very Fast)</SelectItem>
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
                    <Target className="w-4 h-4 mr-2" />
                    Start Advanced Scan
                  </>
                )}
              </Button>

              {/* Information */}
              <div className="p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-orange-600 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-orange-800 dark:text-orange-200">
                    <p className="font-medium mb-1">Advanced Features:</p>
                    <ul className="space-y-1 text-xs">
                      <li>• <strong>OS Detection:</strong> Identify target operating systems</li>
                      <li>• <strong>Service Enumeration:</strong> Detect running services</li>
                      <li>• <strong>Stealth Scanning:</strong> Avoid detection systems</li>
                      <li>• <strong>Version Detection:</strong> Identify service versions</li>
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
              <CardTitle>Advanced Nmap Results</CardTitle>
              <CardDescription>
                {results 
                  ? `Scan completed in ${results.scanTime}ms` 
                  : 'Professional network reconnaissance results will appear here'
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              {loading && (
                <div className="flex items-center justify-center py-12">
                  <div className="text-center">
                    <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-orange-600" />
                    <p className="text-sm text-muted-foreground">Performing advanced network reconnaissance...</p>
                    <p className="text-xs text-muted-foreground mt-2">Using professional Nmap techniques</p>
                  </div>
                </div>
              )}

              {results && !loading && (
                <Tabs defaultValue="summary" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="hosts">Hosts ({results.hosts.length})</TabsTrigger>
                    <TabsTrigger value="services">Services</TabsTrigger>
                    <TabsTrigger value="raw">Raw Output</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="summary" className="mt-4">
                    {/* Statistics */}
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                      <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-green-800 dark:text-green-200">Hosts Up</p>
                            <p className="text-2xl font-bold text-green-600">
                              {results.hosts.filter(h => h.status === 'up').length}
                            </p>
                          </div>
                          <CheckCircle className="w-8 h-8 text-green-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-blue-800 dark:text-blue-200">Open Ports</p>
                            <p className="text-2xl font-bold text-blue-600">
                              {results.hosts.reduce((sum, h) => sum + h.ports.filter(p => p.state === 'open').length, 0)}
                            </p>
                          </div>
                          <Server className="w-8 h-8 text-blue-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-purple-800 dark:text-purple-200">Services</p>
                            <p className="text-2xl font-bold text-purple-600">
                              {results.hosts.reduce((sum, h) => sum + h.services.length, 0)}
                            </p>
                          </div>
                          <Zap className="w-8 h-8 text-purple-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-orange-800 dark:text-orange-200">Scan Time</p>
                            <p className="text-lg font-bold text-orange-600">{results.scanTime}ms</p>
                          </div>
                          <Target className="w-8 h-8 text-orange-600" />
                        </div>
                      </div>
                    </div>

                    <div className="p-4 bg-gray-50 dark:bg-gray-900/20 rounded-lg">
                      <h3 className="font-medium mb-2">Scan Summary</h3>
                      <p className="text-sm text-muted-foreground">{results.summary}</p>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="hosts" className="mt-4">
                    <div className="space-y-4">
                      {results.hosts.map((host, index) => (
                        <div key={index} className="p-4 border rounded-lg">
                          <div className="flex items-center justify-between mb-3">
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
                          
                          {host.os && host.os !== 'Unknown' && (
                            <div className="mb-3">
                              <p className="text-sm font-medium mb-1">Operating System:</p>
                              <Badge variant="secondary">{host.os}</Badge>
                            </div>
                          )}
                          
                          {host.ports.length > 0 && (
                            <div className="mb-3">
                              <p className="text-sm font-medium mb-2">Open Ports & Services:</p>
                              <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                                {host.ports.filter(p => p.state === 'open').map((port) => (
                                  <div key={port.port} className="flex items-center justify-between p-2 bg-green-50 rounded border">
                                    <div>
                                      <span className="font-medium">{port.port}/{port.protocol}</span>
                                      <span className="text-sm text-muted-foreground ml-2">{port.service}</span>
                                    </div>
                                    <Badge className={getPortStateColor(port.state)}>
                                      {port.state}
                                    </Badge>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                          
                          {host.ports.filter(p => p.state === 'filtered').length > 0 && (
                            <div>
                              <p className="text-sm font-medium mb-2">Filtered Ports:</p>
                              <div className="flex flex-wrap gap-1">
                                {host.ports.filter(p => p.state === 'filtered').map((port) => (
                                  <Badge key={port.port} variant="outline" className="text-xs">
                                    {port.port}
                                  </Badge>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="services" className="mt-4">
                    <div className="space-y-3">
                      {results.hosts.flatMap(host => 
                        host.services.map(service => ({
                          ...service,
                          host: host.ip,
                          hostname: host.hostname
                        }))
                      ).map((service, index) => (
                        <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                          <div className="flex items-center gap-3">
                            <Badge variant="outline">{service.host}</Badge>
                            <div>
                              <p className="font-medium">Port {service.port} - {service.service}</p>
                              <p className="text-sm text-muted-foreground">{service.version}</p>
                            </div>
                          </div>
                          <Badge className={getPortStateColor(service.state)}>
                            {service.state}
                          </Badge>
                        </div>
                      ))}
                      
                      {results.hosts.flatMap(h => h.services).length === 0 && (
                        <div className="text-center py-8">
                          <Server className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                          <p className="text-muted-foreground">No services detected</p>
                        </div>
                      )}
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
                  <Target className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">Configure scan parameters and launch advanced reconnaissance</p>
                  <p className="text-sm text-muted-foreground mt-2">Professional Nmap techniques for network discovery</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}