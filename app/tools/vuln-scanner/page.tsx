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
import { Loader2, Shield, AlertTriangle, CheckCircle, Info, XCircle, Eye, Globe, Lock, Bug, Search } from 'lucide-react'

interface VulnScanResult {
  target: string
  scanType: string
  summary: string
  riskScore: number
  findings: Array<{
    id: string
    type: string
    severity: string
    title: string
    description: string
    recommendation: string
  }>
  statistics: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
    info: number
  }
  scanTime: number
  timestamp: string
  recommendations: string[]
}

export default function VulnScannerPage() {
  const [target, setTarget] = useState('')
  const [scanType, setScanType] = useState('web')
  const [results, setResults] = useState<VulnScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleScan = async () => {
    if (!target.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target URL or hostname",
        variant: "destructive",
      })
      return
    }

    setLoading(true)
    try {
      const response = await apiCall('/api/tools/vuln-scanner', {
        method: 'POST',
        body: JSON.stringify({
          target: target.trim(),
          scanType,
          options: {}
        })
      })

      if (response?.success) {
        setResults(response.data)
        toast({
          title: "Success",
          description: `Vulnerability scan completed. Found ${response.data.statistics.total} potential issues.`
        })
      } else {
        toast({
          title: "Error",
          description: response?.message || "Vulnerability scan failed",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('Vulnerability scan error:', error)
      toast({
        title: "Error",
        description: "Failed to perform vulnerability scan",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-red-100 text-red-800 border-red-200'
      case 'high': return 'bg-orange-100 text-orange-800 border-orange-200'
      case 'medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200'
      case 'low': return 'bg-blue-100 text-blue-800 border-blue-200'
      case 'info': return 'bg-gray-100 text-gray-800 border-gray-200'
      default: return 'bg-gray-100 text-gray-800 border-gray-200'
    }
  }

  const getSeverityIcon = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return <XCircle className="w-4 h-4" />
      case 'high': return <AlertTriangle className="w-4 h-4" />
      case 'medium': return <Shield className="w-4 h-4" />
      case 'low': return <Info className="w-4 h-4" />
      case 'info': return <CheckCircle className="w-4 h-4" />
      default: return <Info className="w-4 h-4" />
    }
  }

  const getRiskScoreColor = (score: number) => {
    if (score >= 80) return 'text-red-600'
    if (score >= 60) return 'text-orange-600'
    if (score >= 40) return 'text-yellow-600'
    if (score >= 20) return 'text-blue-600'
    return 'text-green-600'
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-red-100 dark:bg-red-900/20 rounded-lg">
            <Shield className="w-6 h-6 text-red-600 dark:text-red-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold">Vulnerability Scanner</h1>
            <p className="text-muted-foreground">Automated vulnerability detection and security assessment</p>
          </div>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="text-red-600">
            <Bug className="w-3 h-3 mr-1" />
            Vulnerability Detection
          </Badge>
          <Badge variant="outline" className="text-orange-600">
            <Shield className="w-3 h-3 mr-1" />
            Security Analysis
          </Badge>
          <Badge variant="outline" className="text-blue-600">
            <Search className="w-3 h-3 mr-1" />
            Risk Assessment
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan Configuration */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Eye className="w-5 h-5" />
                Scan Configuration
              </CardTitle>
              <CardDescription>
                Configure your vulnerability scan parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="target">Target URL/Hostname</Label>
                <Input
                  id="target"
                  placeholder="e.g., example.com or https://example.com"
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
                    <SelectItem value="web">Web Application Scan</SelectItem>
                    <SelectItem value="network">Network Security Scan</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
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
                    <Bug className="w-4 h-4 mr-2" />
                    Start Vulnerability Scan
                  </>
                )}
              </Button>

              {/* Information */}
              <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-red-600 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-red-800 dark:text-red-200">
                    <p className="font-medium mb-1">Scan Types:</p>
                    <ul className="space-y-1 text-xs">
                      <li>• <strong>Web App:</strong> HTTP headers, SSL, common paths</li>
                      <li>• <strong>Network:</strong> Port-based vulnerability assessment</li>
                      <li>• <strong>Comprehensive:</strong> Complete security analysis</li>
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
              <CardTitle>Vulnerability Assessment Results</CardTitle>
              <CardDescription>
                {results 
                  ? `Scan completed in ${results.scanTime}ms - Risk Score: ${results.riskScore}/100` 
                  : 'Results will appear here after scanning'
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              {loading && (
                <div className="flex items-center justify-center py-12">
                  <div className="text-center">
                    <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-red-600" />
                    <p className="text-sm text-muted-foreground">Performing vulnerability assessment...</p>
                  </div>
                </div>
              )}

              {results && !loading && (
                <Tabs defaultValue="summary" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="findings">Findings ({results.statistics.total})</TabsTrigger>
                    <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                    <TabsTrigger value="raw">Raw Data</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="summary" className="mt-4">
                    {/* Risk Score */}
                    <div className="mb-6 p-6 bg-gradient-to-r from-red-50 to-orange-50 dark:from-red-900/10 dark:to-orange-900/10 rounded-lg">
                      <div className="text-center">
                        <h3 className="text-lg font-semibold mb-2">Security Risk Score</h3>
                        <div className={`text-4xl font-bold mb-2 ${getRiskScoreColor(results.riskScore)}`}>
                          {results.riskScore}/100
                        </div>
                        <p className="text-sm text-muted-foreground">
                          {results.riskScore >= 80 ? 'Critical Risk' :
                           results.riskScore >= 60 ? 'High Risk' :
                           results.riskScore >= 40 ? 'Medium Risk' :
                           results.riskScore >= 20 ? 'Low Risk' : 'Minimal Risk'}
                        </p>
                      </div>
                    </div>

                    {/* Statistics Grid */}
                    <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
                      <div className="p-4 bg-red-50 dark:bg-red-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-red-800 dark:text-red-200">Critical</p>
                            <p className="text-2xl font-bold text-red-600">{results.statistics.critical}</p>
                          </div>
                          <XCircle className="w-8 h-8 text-red-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-orange-800 dark:text-orange-200">High</p>
                            <p className="text-2xl font-bold text-orange-600">{results.statistics.high}</p>
                          </div>
                          <AlertTriangle className="w-8 h-8 text-orange-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-yellow-800 dark:text-yellow-200">Medium</p>
                            <p className="text-2xl font-bold text-yellow-600">{results.statistics.medium}</p>
                          </div>
                          <Shield className="w-8 h-8 text-yellow-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-blue-800 dark:text-blue-200">Low</p>
                            <p className="text-2xl font-bold text-blue-600">{results.statistics.low}</p>
                          </div>
                          <Info className="w-8 h-8 text-blue-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-gray-50 dark:bg-gray-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-gray-800 dark:text-gray-200">Info</p>
                            <p className="text-2xl font-bold text-gray-600">{results.statistics.info}</p>
                          </div>
                          <CheckCircle className="w-8 h-8 text-gray-600" />
                        </div>
                      </div>
                    </div>

                    <div className="p-4 bg-gray-50 dark:bg-gray-900/20 rounded-lg">
                      <h3 className="font-medium mb-2">Scan Summary</h3>
                      <p className="text-sm text-muted-foreground">{results.summary}</p>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="findings" className="mt-4">
                    <div className="space-y-4">
                      {results.findings.map((finding, index) => (
                        <div key={index} className="p-4 border rounded-lg">
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center gap-2">
                              {getSeverityIcon(finding.severity)}
                              <h3 className="font-medium">{finding.title}</h3>
                            </div>
                            <Badge className={getSeverityColor(finding.severity)}>
                              {finding.severity.toUpperCase()}
                            </Badge>
                          </div>
                          
                          <div className="mb-2">
                            <Badge variant="outline" className="text-xs mb-2">
                              {finding.type}
                            </Badge>
                            <p className="text-sm text-muted-foreground mb-2">
                              {finding.description}
                            </p>
                          </div>
                          
                          <div className="p-3 bg-blue-50 dark:bg-blue-900/10 rounded border-l-4 border-blue-400">
                            <p className="text-sm">
                              <strong>Recommendation:</strong> {finding.recommendation}
                            </p>
                          </div>
                        </div>
                      ))}
                      
                      {results.findings.length === 0 && (
                        <div className="text-center py-8">
                          <CheckCircle className="w-12 h-12 text-green-600 mx-auto mb-4" />
                          <h3 className="font-medium text-green-600 mb-2">No Vulnerabilities Found</h3>
                          <p className="text-sm text-muted-foreground">
                            The scan did not identify any significant security issues.
                          </p>
                        </div>
                      )}
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="recommendations" className="mt-4">
                    <div className="space-y-4">
                      <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                        <h3 className="font-medium text-green-800 dark:text-green-200 mb-2">
                          Security Recommendations
                        </h3>
                        <p className="text-sm text-green-700 dark:text-green-300">
                          Follow these recommendations to improve your security posture:
                        </p>
                      </div>
                      
                      <div className="space-y-3">
                        {results.recommendations.map((recommendation, index) => (
                          <div key={index} className="flex items-start gap-3 p-3 border rounded-lg">
                            <div className="flex-shrink-0 w-6 h-6 bg-blue-100 rounded-full flex items-center justify-center">
                              <span className="text-xs font-medium text-blue-600">{index + 1}</span>
                            </div>
                            <p className="text-sm">{recommendation}</p>
                          </div>
                        ))}
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
                  <Bug className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">Enter a target and start scanning to view vulnerability results</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}