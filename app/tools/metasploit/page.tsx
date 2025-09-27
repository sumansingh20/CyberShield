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
import { Loader2, Terminal, Shield, AlertTriangle, CheckCircle, Info, Bug, Target, Zap, Code } from 'lucide-react'

interface MetasploitResult {
  target: string
  exploit: string
  payload: string
  summary: string
  sessions: {
    id: string
    type: string
    tunnel: string
    via: string
    username?: string
    computer?: string
    arch?: string
    platform?: string
    status: 'active' | 'closed' | 'error'
    timestamp: string
  }[]
  exploitInfo: {
    name: string
    description: string
    author: string[]
    date: string
    references: string[]
    targets: string[]
    reliability: string
    sideEffects: string[]
  }
  payloadInfo: {
    name: string
    description: string
    size: number
    arch: string
    platform: string
  }
  scanTime: number
  timestamp: string
}

export default function MetasploitPage() {
  const [target, setTarget] = useState('')
  const [targetPort, setTargetPort] = useState('445')
  const [exploit, setExploit] = useState('ms17_010_eternalblue')
  const [payload, setPayload] = useState('windows/x64/meterpreter/reverse_tcp')
  const [lhost, setLhost] = useState('')
  const [lport, setLport] = useState('4444')
  const [results, setResults] = useState<MetasploitResult | null>(null)
  const [loading, setLoading] = useState(false)
  
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleExploit = async () => {
    if (!target.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target IP address",
        variant: "destructive",
      })
      return
    }

    if (!lhost.trim()) {
      toast({
        title: "Error",
        description: "Please enter your listening host IP",
        variant: "destructive",
      })
      return
    }

    setLoading(true)
    try {
      const response = await apiCall('/api/tools/metasploit', {
        method: 'POST',
        body: JSON.stringify({
          target: target.trim(),
          targetPort: parseInt(targetPort),
          exploit,
          payload,
          lhost: lhost.trim(),
          lport: parseInt(lport)
        })
      })

      if (response?.success) {
        setResults(response.data)
        toast({
          title: "Exploit Attempt Completed",
          description: `${response.data.sessions.length} session(s) created.`,
          variant: response.data.sessions.length > 0 ? "default" : "destructive"
        })
      } else {
        toast({
          title: "Error",
          description: response?.message || "Metasploit exploit failed",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('Metasploit error:', error)
      toast({
        title: "Error",
        description: "Failed to execute Metasploit exploit",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const getSessionColor = (status: string) => {
    switch (status) {
      case 'active': return 'bg-green-100 text-green-800'
      case 'closed': return 'bg-gray-100 text-gray-800'
      case 'error': return 'bg-red-100 text-red-800'
      default: return 'bg-yellow-100 text-yellow-800'
    }
  }

  const getSeverityColor = (reliability: string) => {
    switch (reliability.toLowerCase()) {
      case 'excellent': return 'bg-green-100 text-green-800'
      case 'great': return 'bg-blue-100 text-blue-800'
      case 'good': return 'bg-yellow-100 text-yellow-800'
      case 'normal': return 'bg-orange-100 text-orange-800'
      case 'average': return 'bg-red-100 text-red-800'
      default: return 'bg-gray-100 text-gray-800'
    }
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-red-100 dark:bg-red-900/20 rounded-lg">
            <Bug className="w-6 h-6 text-red-600 dark:text-red-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold">Metasploit Framework</h1>
            <p className="text-muted-foreground">Advanced exploitation framework for penetration testing</p>
          </div>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="text-red-600">
            <Bug className="w-3 h-3 mr-1" />
            Exploitation
          </Badge>
          <Badge variant="outline" className="text-purple-600">
            <Terminal className="w-3 h-3 mr-1" />
            Post-Exploitation
          </Badge>
          <Badge variant="outline" className="text-orange-600">
            <Zap className="w-3 h-3 mr-1" />
            Payloads
          </Badge>
        </div>
      </div>

      {/* Critical Warning */}
      <div className="mb-6 p-4 bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg">
        <div className="flex items-start gap-3">
          <AlertTriangle className="w-6 h-6 text-red-600 mt-0.5 flex-shrink-0" />
          <div>
            <h3 className="font-bold text-red-800 dark:text-red-200 mb-2">⚠️ AUTHORIZED USE ONLY</h3>
            <p className="text-sm text-red-800 dark:text-red-200 mb-2">
              This tool performs real exploitation attempts that can compromise systems and may be illegal if used without authorization.
            </p>
            <ul className="text-xs text-red-700 dark:text-red-300 space-y-1">
              <li>• Only use on systems you own or have explicit written permission to test</li>
              <li>• Exploitation may cause system instability or data loss</li>
              <li>• Ensure you have proper backups and recovery procedures</li>
              <li>• Follow responsible disclosure for any vulnerabilities discovered</li>
            </ul>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Exploit Configuration */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Exploit Configuration
              </CardTitle>
              <CardDescription>
                Configure Metasploit exploit parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <Label htmlFor="target">Target IP</Label>
                  <Input
                    id="target"
                    placeholder="192.168.1.100"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    className="mt-1"
                  />
                </div>
                <div>
                  <Label htmlFor="targetPort">Port</Label>
                  <Input
                    id="targetPort"
                    placeholder="445"
                    value={targetPort}
                    onChange={(e) => setTargetPort(e.target.value)}
                    className="mt-1"
                  />
                </div>
              </div>

              <div>
                <Label htmlFor="exploit">Exploit Module</Label>
                <Select value={exploit} onValueChange={setExploit}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="ms17_010_eternalblue">MS17-010 EternalBlue (SMB)</SelectItem>
                    <SelectItem value="ms08_067_netapi">MS08-067 NetAPI (RPC)</SelectItem>
                    <SelectItem value="ms03_026_dcom">MS03-026 DCOM (RPC)</SelectItem>
                    <SelectItem value="ssh_login">SSH Login Bruteforce</SelectItem>
                    <SelectItem value="http_login">HTTP Login Bruteforce</SelectItem>
                    <SelectItem value="ftp_login">FTP Login Bruteforce</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="payload">Payload</Label>
                <Select value={payload} onValueChange={setPayload}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="windows/x64/meterpreter/reverse_tcp">Windows x64 Meterpreter (Reverse TCP)</SelectItem>
                    <SelectItem value="windows/meterpreter/reverse_tcp">Windows x86 Meterpreter (Reverse TCP)</SelectItem>
                    <SelectItem value="linux/x64/meterpreter/reverse_tcp">Linux x64 Meterpreter (Reverse TCP)</SelectItem>
                    <SelectItem value="cmd/windows/reverse_powershell">Windows PowerShell (Reverse)</SelectItem>
                    <SelectItem value="generic/shell_reverse_tcp">Generic Shell (Reverse TCP)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="grid grid-cols-2 gap-2">
                <div>
                  <Label htmlFor="lhost">Listen Host</Label>
                  <Input
                    id="lhost"
                    placeholder="Your IP"
                    value={lhost}
                    onChange={(e) => setLhost(e.target.value)}
                    className="mt-1"
                  />
                </div>
                <div>
                  <Label htmlFor="lport">Listen Port</Label>
                  <Input
                    id="lport"
                    placeholder="4444"
                    value={lport}
                    onChange={(e) => setLport(e.target.value)}
                    className="mt-1"
                  />
                </div>
              </div>

              <Button 
                onClick={handleExploit} 
                disabled={loading} 
                className="w-full bg-red-600 hover:bg-red-700"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Exploiting...
                  </>
                ) : (
                  <>
                    <Bug className="w-4 h-4 mr-2" />
                    Launch Exploit
                  </>
                )}
              </Button>

              {/* Information */}
              <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-blue-800 dark:text-blue-200">
                    <p className="font-medium mb-1">Exploit Types:</p>
                    <ul className="space-y-1 text-xs">
                      <li>• <strong>Buffer Overflow:</strong> Memory corruption</li>
                      <li>• <strong>Code Injection:</strong> Execute arbitrary code</li>
                      <li>• <strong>Authentication:</strong> Bypass login systems</li>
                      <li>• <strong>Privilege Escalation:</strong> Gain higher access</li>
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
              <CardTitle>Exploitation Results</CardTitle>
              <CardDescription>
                {results 
                  ? `Exploit completed in ${(results.scanTime / 1000).toFixed(2)}s` 
                  : 'Exploitation results will appear here'
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              {loading && (
                <div className="flex items-center justify-center py-12">
                  <div className="text-center">
                    <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-red-600" />
                    <p className="text-sm text-muted-foreground">Launching exploit against target...</p>
                    <p className="text-xs text-muted-foreground mt-1">This may take several minutes</p>
                  </div>
                </div>
              )}

              {results && !loading && (
                <Tabs defaultValue="summary" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="sessions">Sessions ({results.sessions.length})</TabsTrigger>
                    <TabsTrigger value="details">Exploit Details</TabsTrigger>
                    <TabsTrigger value="raw">Raw Output</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="summary" className="mt-4">
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
                      <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-green-800 dark:text-green-200">Active Sessions</p>
                            <p className="text-2xl font-bold text-green-600">
                              {results.sessions.filter(s => s.status === 'active').length}
                            </p>
                          </div>
                          <Terminal className="w-8 h-8 text-green-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-blue-800 dark:text-blue-200">Total Sessions</p>
                            <p className="text-2xl font-bold text-blue-600">{results.sessions.length}</p>
                          </div>
                          <Target className="w-8 h-8 text-blue-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-purple-800 dark:text-purple-200">Exploit Time</p>
                            <p className="text-lg font-bold text-purple-600">{(results.scanTime / 1000).toFixed(2)}s</p>
                          </div>
                          <Zap className="w-8 h-8 text-purple-600" />
                        </div>
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="p-4 bg-gray-50 dark:bg-gray-900/20 rounded-lg">
                        <h3 className="font-medium mb-2">Exploitation Summary</h3>
                        <p className="text-sm text-muted-foreground">{results.summary}</p>
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="p-4 border rounded-lg">
                          <h4 className="font-medium mb-2">Exploit Used</h4>
                          <p className="text-sm font-mono bg-gray-100 dark:bg-gray-800 p-2 rounded">
                            {results.exploitInfo.name}
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
                            {results.exploitInfo.description}
                          </p>
                        </div>
                        
                        <div className="p-4 border rounded-lg">
                          <h4 className="font-medium mb-2">Payload Used</h4>
                          <p className="text-sm font-mono bg-gray-100 dark:bg-gray-800 p-2 rounded">
                            {results.payloadInfo.name}
                          </p>
                          <p className="text-xs text-muted-foreground mt-1">
                            {results.payloadInfo.description} ({results.payloadInfo.size} bytes)
                          </p>
                        </div>
                      </div>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="sessions" className="mt-4">
                    <div className="space-y-3">
                      {results.sessions.map((session, index) => (
                        <div key={index} className="p-4 border rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <Terminal className="w-4 h-4" />
                              <span className="font-medium">Session {session.id}</span>
                              <Badge variant="outline" className="text-xs">{session.type}</Badge>
                            </div>
                            <Badge className={getSessionColor(session.status)}>
                              {session.status.toUpperCase()}
                            </Badge>
                          </div>
                          
                          <div className="grid grid-cols-2 gap-4 text-sm">
                            <div>
                              <p><strong>Tunnel:</strong> {session.tunnel}</p>
                              <p><strong>Via:</strong> {session.via}</p>
                            </div>
                            <div>
                              {session.username && <p><strong>User:</strong> {session.username}</p>}
                              {session.computer && <p><strong>Computer:</strong> {session.computer}</p>}
                            </div>
                          </div>
                          
                          {session.arch && session.platform && (
                            <div className="mt-2 flex gap-2">
                              <Badge variant="secondary" className="text-xs">{session.arch}</Badge>
                              <Badge variant="secondary" className="text-xs">{session.platform}</Badge>
                            </div>
                          )}
                          
                          <p className="text-xs text-muted-foreground mt-2">
                            Created: {new Date(session.timestamp).toLocaleString()}
                          </p>
                        </div>
                      ))}
                      {results.sessions.length === 0 && (
                        <div className="text-center py-8 text-muted-foreground">
                          No sessions created - exploit may have failed
                        </div>
                      )}
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="details" className="mt-4">
                    <div className="space-y-4">
                      <div className="p-4 border rounded-lg">
                        <h3 className="font-medium mb-3">Exploit Information</h3>
                        <div className="space-y-2 text-sm">
                          <div className="flex justify-between">
                            <span>Name:</span>
                            <span className="font-mono">{results.exploitInfo.name}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Date:</span>
                            <span>{results.exploitInfo.date}</span>
                          </div>
                          <div className="flex justify-between">
                            <span>Reliability:</span>
                            <Badge className={getSeverityColor(results.exploitInfo.reliability)}>
                              {results.exploitInfo.reliability}
                            </Badge>
                          </div>
                        </div>
                        
                        <div className="mt-4">
                          <h4 className="font-medium mb-2">Authors</h4>
                          <div className="flex flex-wrap gap-1">
                            {results.exploitInfo.author.map((author, index) => (
                              <Badge key={index} variant="outline" className="text-xs">{author}</Badge>
                            ))}
                          </div>
                        </div>

                        <div className="mt-4">
                          <h4 className="font-medium mb-2">References</h4>
                          <ul className="text-xs space-y-1">
                            {results.exploitInfo.references.map((ref, index) => (
                              <li key={index} className="font-mono">{ref}</li>
                            ))}
                          </ul>
                        </div>

                        <div className="mt-4">
                          <h4 className="font-medium mb-2">Side Effects</h4>
                          <ul className="text-xs space-y-1">
                            {results.exploitInfo.sideEffects.map((effect, index) => (
                              <li key={index} className="text-yellow-600">⚠ {effect}</li>
                            ))}
                          </ul>
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
                  <Bug className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">Configure exploit parameters and launch to view results</p>
                  <p className="text-xs text-muted-foreground mt-2">
                    Remember: Only use on authorized targets
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}