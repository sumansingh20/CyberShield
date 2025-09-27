'use client'

import { useState } from 'react'
import { Button } from '@/src/ui/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Input } from '@/src/ui/components/ui/input'
import { Label } from '@/src/ui/components/ui/label'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Badge } from '@/src/ui/components/ui/badge'
import { Progress } from '@/src/ui/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'

interface VulnScanRequest {
  target: string
  scan_type: 'quick' | 'comprehensive' | 'targeted'
  port_range: string
  scan_intensity: number
  include_services: boolean
  check_cves: boolean
  custom_scripts: string[]
  exclude_hosts: string[]
}

interface Vulnerability {
  id: string
  name: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  cvss_score: number
  cve_id?: string
  description: string
  affected_service: string
  port: number
  protocol: string
  solution: string
  references: string[]
  exploit_available: boolean
  risk_factor: string
}

interface VulnScanResult {
  scan_id: string
  target: string
  scan_type: string
  start_time: string
  end_time: string
  duration: number
  hosts_scanned: number
  ports_scanned: number
  vulnerabilities: Vulnerability[]
  summary: {
    critical: number
    high: number
    medium: number
    low: number
    info: number
    total: number
  }
  risk_score: number
  compliance_status: {
    pci_dss: string
    iso_27001: string
    nist: string
    gdpr: string
  }
  recommendations: string[]
  next_scan_date: string
}

export default function VulnScan() {
  const [request, setRequest] = useState<VulnScanRequest>({
    target: '',
    scan_type: 'quick',
    port_range: '1-1000',
    scan_intensity: 3,
    include_services: true,
    check_cves: true,
    custom_scripts: [],
    exclude_hosts: []
  })
  
  const [result, setResult] = useState<VulnScanResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [customScript, setCustomScript] = useState('')
  const [excludeHost, setExcludeHost] = useState('')

  const handleScan = async () => {
    if (!request.target.trim()) {
      setError('Please specify a target to scan')
      return
    }

    setLoading(true)
    setError('')
    
    try {
      const response = await fetch('/api/tools/vuln-scan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request),
      })

      if (!response.ok) {
        throw new Error('Vulnerability scan failed')
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const addCustomScript = () => {
    if (customScript.trim() && !request.custom_scripts.includes(customScript.trim())) {
      setRequest({
        ...request,
        custom_scripts: [...request.custom_scripts, customScript.trim()]
      })
      setCustomScript('')
    }
  }

  const removeCustomScript = (script: string) => {
    setRequest({
      ...request,
      custom_scripts: request.custom_scripts.filter(s => s !== script)
    })
  }

  const addExcludeHost = () => {
    if (excludeHost.trim() && !request.exclude_hosts.includes(excludeHost.trim())) {
      setRequest({
        ...request,
        exclude_hosts: [...request.exclude_hosts, excludeHost.trim()]
      })
      setExcludeHost('')
    }
  }

  const removeExcludeHost = (host: string) => {
    setRequest({
      ...request,
      exclude_hosts: request.exclude_hosts.filter(h => h !== host)
    })
  }

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-purple-100 text-purple-800'
      case 'high': return 'bg-red-100 text-red-800'
      case 'medium': return 'bg-orange-100 text-orange-800'
      case 'low': return 'bg-yellow-100 text-yellow-800'
      case 'info': return 'bg-blue-100 text-blue-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getComplianceColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'compliant': return 'bg-green-100 text-green-800'
      case 'partial': return 'bg-yellow-100 text-yellow-800'
      case 'non-compliant': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  const getRiskLevel = (score: number) => {
    if (score >= 9) return { level: 'Critical', color: 'text-purple-600' }
    if (score >= 7) return { level: 'High', color: 'text-red-600' }
    if (score >= 4) return { level: 'Medium', color: 'text-orange-600' }
    if (score >= 1) return { level: 'Low', color: 'text-yellow-600' }
    return { level: 'Minimal', color: 'text-green-600' }
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="mb-8">
        <h1 className="text-3xl font-bold flex items-center gap-2 mb-2">
          🛡️ Advanced Vulnerability Scanner
        </h1>
        <p className="text-gray-600">
          Comprehensive security vulnerability assessment and penetration testing tool
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              🎯 Scan Configuration
            </CardTitle>
            <CardDescription>
              Configure vulnerability scan parameters and target specifications
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-6">
            <div>
              <Label htmlFor="target">Target (IP/Domain/Network)</Label>
              <Input
                id="target"
                value={request.target}
                onChange={(e) => setRequest({...request, target: e.target.value})}
                placeholder="192.168.1.1, example.com, or 192.168.1.0/24"
              />
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <Label htmlFor="scan-type">Scan Type</Label>
                <select
                  id="scan-type"
                  title="Select scan type"
                  className="w-full p-2 border rounded-md"
                  value={request.scan_type}
                  onChange={(e) => setRequest({...request, scan_type: e.target.value as any})}
                >
                  <option value="quick">Quick Scan (Fast)</option>
                  <option value="comprehensive">Comprehensive (Thorough)</option>
                  <option value="targeted">Targeted (Specific)</option>
                </select>
              </div>
              <div>
                <Label htmlFor="port-range">Port Range</Label>
                <Input
                  id="port-range"
                  value={request.port_range}
                  onChange={(e) => setRequest({...request, port_range: e.target.value})}
                  placeholder="1-1000, 80,443,8080"
                />
              </div>
            </div>

            <div>
              <Label>Scan Intensity (1-5)</Label>
              <div className="flex items-center gap-4 mt-2">
                <span className="text-sm">Stealth</span>
                <input
                  type="range"
                  min="1"
                  max="5"
                  value={request.scan_intensity}
                  onChange={(e) => setRequest({...request, scan_intensity: parseInt(e.target.value)})}
                  className="flex-1"
                  title="Adjust scan intensity"
                />
                <span className="text-sm">Aggressive</span>
                <Badge>{request.scan_intensity}</Badge>
              </div>
            </div>

            <div className="space-y-3">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="services"
                  title="Include service detection"
                  checked={request.include_services}
                  onChange={(e) => setRequest({...request, include_services: e.target.checked})}
                />
                <Label htmlFor="services">Include service version detection</Label>
              </div>
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="cves"
                  title="Check for CVEs"
                  checked={request.check_cves}
                  onChange={(e) => setRequest({...request, check_cves: e.target.checked})}
                />
                <Label htmlFor="cves">Check for known CVEs</Label>
              </div>
            </div>

            <div>
              <Label>Custom Scripts (Optional)</Label>
              <div className="flex gap-2 mt-1">
                <Input
                  value={customScript}
                  onChange={(e) => setCustomScript(e.target.value)}
                  placeholder="e.g., http-enum, ssl-cert"
                />
                <Button type="button" onClick={addCustomScript}>Add</Button>
              </div>
              {request.custom_scripts.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {request.custom_scripts.map((script, index) => (
                    <Badge key={index} className="cursor-pointer" onClick={() => removeCustomScript(script)}>
                      {script} ×
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            <div>
              <Label>Exclude Hosts (Optional)</Label>
              <div className="flex gap-2 mt-1">
                <Input
                  value={excludeHost}
                  onChange={(e) => setExcludeHost(e.target.value)}
                  placeholder="192.168.1.1, domain.com"
                />
                <Button type="button" onClick={addExcludeHost}>Add</Button>
              </div>
              {request.exclude_hosts.length > 0 && (
                <div className="flex flex-wrap gap-2 mt-2">
                  {request.exclude_hosts.map((host, index) => (
                    <Badge key={index} className="cursor-pointer" onClick={() => removeExcludeHost(host)}>
                      {host} ×
                    </Badge>
                  ))}
                </div>
              )}
            </div>

            {error && (
              <Alert>
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button 
              onClick={handleScan} 
              disabled={loading}
              className="w-full"
            >
              {loading ? 'Scanning...' : 'Start Vulnerability Scan'}
            </Button>
          </CardContent>
        </Card>

        {result && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                📊 Scan Results
              </CardTitle>
              <CardDescription>
                Vulnerability assessment results and security recommendations
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                  <TabsTrigger value="compliance">Compliance</TabsTrigger>
                  <TabsTrigger value="recommendations">Actions</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <div className="space-y-4">
                    <div className="p-4 border rounded-lg">
                      <div className="grid grid-cols-2 gap-4 mb-4">
                        <div>
                          <p className="text-sm text-gray-600">Scan Duration</p>
                          <p className="font-semibold">{Math.round(result.duration / 1000)}s</p>
                        </div>
                        <div>
                          <p className="text-sm text-gray-600">Hosts Scanned</p>
                          <p className="font-semibold">{result.hosts_scanned}</p>
                        </div>
                        <div>
                          <p className="text-sm text-gray-600">Ports Scanned</p>
                          <p className="font-semibold">{result.ports_scanned}</p>
                        </div>
                        <div>
                          <p className="text-sm text-gray-600">Total Vulnerabilities</p>
                          <p className="font-semibold">{result.summary.total}</p>
                        </div>
                      </div>
                      
                      <div className="mb-4">
                        <div className="flex items-center justify-between mb-2">
                          <span>Risk Score</span>
                          <span className={`font-bold ${getRiskLevel(result.risk_score).color}`}>
                            {getRiskLevel(result.risk_score).level}
                          </span>
                        </div>
                        <Progress value={result.risk_score * 10} className="mb-1" />
                        <div className="flex justify-between text-xs text-gray-500">
                          <span>0</span>
                          <span>{result.risk_score}/10</span>
                        </div>
                      </div>
                    </div>

                    <div>
                      <h4 className="font-semibold mb-3">Vulnerability Breakdown</h4>
                      <div className="grid grid-cols-2 gap-2">
                        <div className="p-2 border rounded text-center">
                          <Badge className={getSeverityColor('critical')} 
                                 style={{marginBottom: '4px'}}>Critical</Badge>
                          <p className="font-bold text-lg">{result.summary.critical}</p>
                        </div>
                        <div className="p-2 border rounded text-center">
                          <Badge className={getSeverityColor('high')} 
                                 style={{marginBottom: '4px'}}>High</Badge>
                          <p className="font-bold text-lg">{result.summary.high}</p>
                        </div>
                        <div className="p-2 border rounded text-center">
                          <Badge className={getSeverityColor('medium')} 
                                 style={{marginBottom: '4px'}}>Medium</Badge>
                          <p className="font-bold text-lg">{result.summary.medium}</p>
                        </div>
                        <div className="p-2 border rounded text-center">
                          <Badge className={getSeverityColor('low')} 
                                 style={{marginBottom: '4px'}}>Low</Badge>
                          <p className="font-bold text-lg">{result.summary.low}</p>
                        </div>
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="vulnerabilities" className="space-y-4">
                  <div className="space-y-3">
                    {result.vulnerabilities.map((vuln, index) => (
                      <div key={index} className="p-3 border rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium">{vuln.name}</h4>
                          <div className="flex items-center gap-2">
                            <Badge className={getSeverityColor(vuln.severity)}>
                              {vuln.severity}
                            </Badge>
                            {vuln.exploit_available && (
                              <Badge className="bg-red-200 text-red-800">Exploit Available</Badge>
                            )}
                          </div>
                        </div>
                        
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-2 mb-2 text-sm">
                          <div>
                            <span className="font-medium">Service:</span> {vuln.affected_service}
                          </div>
                          <div>
                            <span className="font-medium">Port:</span> {vuln.port}/{vuln.protocol}
                          </div>
                          <div>
                            <span className="font-medium">CVSS:</span> {vuln.cvss_score}/10
                          </div>
                        </div>
                        
                        {vuln.cve_id && (
                          <div className="mb-2">
                            <Badge className="bg-blue-100 text-blue-800">{vuln.cve_id}</Badge>
                          </div>
                        )}
                        
                        <p className="text-sm text-gray-600 mb-2">{vuln.description}</p>
                        
                        <div className="text-sm">
                          <span className="font-medium">Solution:</span>
                          <p className="text-gray-600">{vuln.solution}</p>
                        </div>
                        
                        {vuln.references.length > 0 && (
                          <div className="mt-2">
                            <span className="text-xs font-medium">References:</span>
                            <ul className="text-xs space-y-1 mt-1">
                              {vuln.references.map((ref, idx) => (
                                <li key={idx} className="text-blue-600">• {ref}</li>
                              ))}
                            </ul>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="compliance" className="space-y-4">
                  <div className="space-y-4">
                    <h3 className="font-semibold">Compliance Status</h3>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="p-3 border rounded">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">PCI DSS</span>
                          <Badge className={getComplianceColor(result.compliance_status.pci_dss)}>
                            {result.compliance_status.pci_dss}
                          </Badge>
                        </div>
                      </div>
                      <div className="p-3 border rounded">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">ISO 27001</span>
                          <Badge className={getComplianceColor(result.compliance_status.iso_27001)}>
                            {result.compliance_status.iso_27001}
                          </Badge>
                        </div>
                      </div>
                      <div className="p-3 border rounded">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">NIST</span>
                          <Badge className={getComplianceColor(result.compliance_status.nist)}>
                            {result.compliance_status.nist}
                          </Badge>
                        </div>
                      </div>
                      <div className="p-3 border rounded">
                        <div className="flex items-center justify-between">
                          <span className="font-medium">GDPR</span>
                          <Badge className={getComplianceColor(result.compliance_status.gdpr)}>
                            {result.compliance_status.gdpr}
                          </Badge>
                        </div>
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="recommendations" className="space-y-4">
                  <div className="space-y-4">
                    <h3 className="font-semibold">Security Recommendations</h3>
                    <div className="space-y-2">
                      {result.recommendations.map((rec, index) => (
                        <div key={index} className="flex items-start gap-2 p-2 border rounded">
                          <input type="checkbox" className="mt-1" title="Mark as completed" />
                          <span className="text-sm">{rec}</span>
                        </div>
                      ))}
                    </div>
                    
                    <div className="p-3 border rounded bg-blue-50">
                      <h4 className="font-medium mb-2">Next Scheduled Scan</h4>
                      <p className="text-sm">{result.next_scan_date}</p>
                    </div>
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        )}
      </div>

      <div className="mt-8">
        <Alert>
          <AlertDescription>
            ⚠️ <strong>Legal Notice:</strong> Only perform vulnerability scans on systems you own or have explicit permission to test. 
            Unauthorized scanning may be illegal in your jurisdiction. Always follow responsible disclosure practices.
          </AlertDescription>
        </Alert>
      </div>
    </div>
  )
}
