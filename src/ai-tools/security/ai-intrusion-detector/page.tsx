"use client"

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Input } from '@/src/ui/components/ui/input'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Badge } from '@/src/ui/components/ui/badge'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Shield, Network, AlertTriangle, CheckCircle, Eye, Brain, Activity, Server } from 'lucide-react'
import { TerminalOutput } from '@/components/TerminalOutput'

interface IntrusionResult {
  isIntrusion: boolean
  threatLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  confidence: number
  attackType: string[]
  reasons: string[]
  aiAnalysis: {
    networkAnomalies: string[]
    trafficPatterns: string[]
    protocolAnalysis: {
      suspiciousProtocols: string[]
      unusualPorts: string[]
      malformedPackets: number
    }
    behaviorAnalysis: {
      repetitivePatterns: string[]
      volumeAnomalies: string[]
      timingAnomalies: string[]
    }
    signatureMatches: string[]
    geolocationRisks: string[]
  }
  recommendations: string[]
  mitigationSteps: string[]
}

export default function AIIntrusionDetector() {
  const [inputType, setInputType] = useState<'logs' | 'traffic' | 'realtime'>('logs')
  const [logData, setLogData] = useState('')
  const [trafficData, setTrafficData] = useState({
    sourceIP: '',
    destinationIP: '',
    port: '',
    protocol: '',
    payloadSize: '',
    frequency: ''
  })
  const [result, setResult] = useState<IntrusionResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [terminalOutput, setTerminalOutput] = useState<string[]>([])

  const handleAnalyze = async () => {
    const hasLogData = inputType === 'logs' && logData.trim()
    const hasTrafficData = inputType === 'traffic' && 
      (trafficData.sourceIP || trafficData.destinationIP || trafficData.port)
    const hasRealtimeData = inputType === 'realtime' // Simulate real-time

    if (!hasLogData && !hasTrafficData && !hasRealtimeData) {
      setError('Please provide data to analyze')
      return
    }

    setLoading(true)
    setError('')
    setResult(null)
    setTerminalOutput([])

    const addToTerminal = (message: string) => {
      setTerminalOutput(prev => [...prev, message])
    }

    try {
      addToTerminal('🛡️ Initializing AI Intrusion Detection System...')
      addToTerminal(`🔍 Analysis Mode: ${inputType.toUpperCase()}`)
      
      const payload = inputType === 'logs' 
        ? { type: 'logs', data: logData }
        : inputType === 'traffic'
        ? { type: 'traffic', data: trafficData }
        : { type: 'realtime', data: 'simulated' }

      addToTerminal('🔬 Analyzing network patterns...')
      addToTerminal('📊 Processing traffic anomalies...')
      addToTerminal('🌐 Checking protocol signatures...')
      addToTerminal('🎯 Matching attack patterns...')
      addToTerminal('📈 Calculating threat vectors...')
      
      const response = await fetch('/api/tools/ai-intrusion-detector', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(payload),
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || 'Failed to analyze data')
      }

      addToTerminal('✅ AI analysis complete!')
      addToTerminal(`⚠️ Threat Level: ${data.threatLevel}`)
      addToTerminal(`🎯 Confidence: ${data.confidence}%`)
      if (data.attackType.length > 0) {
        addToTerminal(`🚨 Attack Types: ${data.attackType.join(', ')}`)
      }
      
      setResult(data)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Analysis failed'
      setError(errorMessage)
      addToTerminal(`❌ Error: ${errorMessage}`)
    } finally {
      setLoading(false)
    }
  }

  const getThreatColor = (level: string) => {
    switch (level) {
      case 'LOW': return 'bg-green-500'
      case 'MEDIUM': return 'bg-yellow-500'
      case 'HIGH': return 'bg-orange-500'
      case 'CRITICAL': return 'bg-red-500'
      default: return 'bg-gray-500'
    }
  }

  const getThreatIcon = (level: string) => {
    switch (level) {
      case 'LOW': return <CheckCircle className="h-4 w-4" />
      case 'MEDIUM': return <Eye className="h-4 w-4" />
      case 'HIGH': return <AlertTriangle className="h-4 w-4" />
      case 'CRITICAL': return <Shield className="h-4 w-4" />
      default: return <Shield className="h-4 w-4" />
    }
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <Brain className="h-8 w-8 text-primary" />
          <h1 className="text-3xl font-bold">AI Intrusion Detection System</h1>
        </div>
        <p className="text-muted-foreground">
          Advanced AI-powered network intrusion detection using machine learning for real-time threat analysis
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Section */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Network className="h-5 w-5" />
              Network Analysis Input
            </CardTitle>
            <CardDescription>
              Analyze network logs, traffic patterns, or monitor in real-time
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Tabs value={inputType} onValueChange={(value) => setInputType(value as 'logs' | 'traffic' | 'realtime')}>
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="logs" className="flex items-center gap-2">
                  <Activity className="h-4 w-4" />
                  Log Analysis
                </TabsTrigger>
                <TabsTrigger value="traffic" className="flex items-center gap-2">
                  <Network className="h-4 w-4" />
                  Traffic Analysis
                </TabsTrigger>
                <TabsTrigger value="realtime" className="flex items-center gap-2">
                  <Server className="h-4 w-4" />
                  Real-time Monitor
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="logs" className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">Network/Security Logs</label>
                  <Textarea
                    placeholder="Paste your firewall logs, IDS alerts, server logs, or network traffic logs here..."
                    value={logData}
                    onChange={(e) => setLogData(e.target.value)}
                    rows={8}
                    className="min-h-[200px] font-mono text-sm"
                  />
                </div>
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Supports common log formats: Syslog, Apache, Nginx, Firewall, IDS/IPS logs
                  </AlertDescription>
                </Alert>
              </TabsContent>
              
              <TabsContent value="traffic" className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Source IP</label>
                    <Input
                      placeholder="192.168.1.100"
                      value={trafficData.sourceIP}
                      onChange={(e) => setTrafficData(prev => ({ ...prev, sourceIP: e.target.value }))}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Destination IP</label>
                    <Input
                      placeholder="10.0.0.1"
                      value={trafficData.destinationIP}
                      onChange={(e) => setTrafficData(prev => ({ ...prev, destinationIP: e.target.value }))}
                    />
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Port</label>
                    <Input
                      placeholder="80, 443, 22, etc."
                      value={trafficData.port}
                      onChange={(e) => setTrafficData(prev => ({ ...prev, port: e.target.value }))}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Protocol</label>
                    <Input
                      placeholder="TCP, UDP, ICMP, etc."
                      value={trafficData.protocol}
                      onChange={(e) => setTrafficData(prev => ({ ...prev, protocol: e.target.value }))}
                    />
                  </div>
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Payload Size (bytes)</label>
                    <Input
                      placeholder="1024"
                      value={trafficData.payloadSize}
                      onChange={(e) => setTrafficData(prev => ({ ...prev, payloadSize: e.target.value }))}
                      type="number"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Frequency (per min)</label>
                    <Input
                      placeholder="100"
                      value={trafficData.frequency}
                      onChange={(e) => setTrafficData(prev => ({ ...prev, frequency: e.target.value }))}
                      type="number"
                    />
                  </div>
                </div>
              </TabsContent>
              
              <TabsContent value="realtime" className="space-y-4">
                <Alert>
                  <Server className="h-4 w-4" />
                  <AlertDescription>
                    <strong>Real-time Monitoring Mode</strong>
                    <br />
                    This will simulate real-time network intrusion detection analysis using AI models 
                    to identify ongoing threats and anomalies.
                  </AlertDescription>
                </Alert>
                
                <div className="bg-muted/20 p-4 rounded-lg">
                  <h4 className="font-semibold mb-2">Monitoring Features:</h4>
                  <ul className="text-sm space-y-1">
                    <li>• DDoS attack detection</li>
                    <li>• Port scanning identification</li>
                    <li>• Brute force attempt recognition</li>
                    <li>• Malware communication patterns</li>
                    <li>• Data exfiltration detection</li>
                  </ul>
                </div>
              </TabsContent>
            </Tabs>

            {error && (
              <Alert variant="destructive">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription>{error}</AlertDescription>
              </Alert>
            )}

            <Button 
              onClick={handleAnalyze} 
              disabled={loading}
              className="w-full"
              size="lg"
            >
              {loading ? (
                <>
                  <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-white mr-2"></div>
                  Analyzing...
                </>
              ) : (
                <>
                  <Brain className="h-4 w-4 mr-2" />
                  Analyze for Intrusions
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Terminal Output */}
        <Card>
          <CardHeader>
            <CardTitle>AI Detection Process</CardTitle>
            <CardDescription>Real-time intrusion detection analysis</CardDescription>
          </CardHeader>
          <CardContent>
            <TerminalOutput 
              output={terminalOutput.join('\n')} 
              isLoading={loading}
              title="AI Detection Process"
            />
          </CardContent>
        </Card>
      </div>

      {/* Results Section */}
      {result && (
        <div className="mt-8 space-y-6">
          {/* Main Result */}
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                {getThreatIcon(result.threatLevel)}
                Intrusion Detection Results
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold mb-2">
                    {result.isIntrusion ? '🚨 THREAT' : '✅ SECURE'}
                  </div>
                  <p className="text-sm text-muted-foreground">Detection Status</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <Badge className={`${getThreatColor(result.threatLevel)} text-white`}>
                    {result.threatLevel}
                  </Badge>
                  <p className="text-sm text-muted-foreground mt-2">Threat Level</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold mb-2">{result.confidence}%</div>
                  <p className="text-sm text-muted-foreground">Confidence</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold mb-2">{result.attackType.length}</div>
                  <p className="text-sm text-muted-foreground">Attack Types</p>
                </div>
              </div>

              {result.attackType.length > 0 && (
                <div className="mb-6">
                  <h4 className="font-semibold mb-2">Detected Attack Types:</h4>
                  <div className="flex flex-wrap gap-2">
                    {result.attackType.map((attack, index) => (
                      <Badge key={index} variant="destructive">
                        {attack}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Detection Details:</h4>
                  <ul className="list-disc list-inside space-y-1">
                    {result.reasons.map((reason, index) => (
                      <li key={index} className="text-sm">{reason}</li>
                    ))}
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Detailed Analysis */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>Network Anomalies</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {result.aiAnalysis.networkAnomalies.map((anomaly, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 text-orange-500 mt-0.5" />
                      <span className="text-sm">{anomaly}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Traffic Patterns</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {result.aiAnalysis.trafficPatterns.map((pattern, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <Activity className="h-4 w-4 text-blue-500 mt-0.5" />
                      <span className="text-sm">{pattern}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Protocol Analysis */}
          <Card>
            <CardHeader>
              <CardTitle>Protocol Analysis</CardTitle>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="protocols" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="protocols">Suspicious Protocols</TabsTrigger>
                  <TabsTrigger value="ports">Unusual Ports</TabsTrigger>
                  <TabsTrigger value="behavior">Behavior Analysis</TabsTrigger>
                </TabsList>
                
                <TabsContent value="protocols" className="mt-4">
                  <div className="space-y-2">
                    {result.aiAnalysis.protocolAnalysis.suspiciousProtocols.map((protocol, index) => (
                      <Badge key={index} variant="outline" className="mr-2 mb-2">
                        {protocol}
                      </Badge>
                    ))}
                    {result.aiAnalysis.protocolAnalysis.malformedPackets > 0 && (
                      <p className="text-sm text-orange-500">
                        {result.aiAnalysis.protocolAnalysis.malformedPackets} malformed packets detected
                      </p>
                    )}
                  </div>
                </TabsContent>
                
                <TabsContent value="ports" className="mt-4">
                  <div className="space-y-2">
                    {result.aiAnalysis.protocolAnalysis.unusualPorts.map((port, index) => (
                      <Badge key={index} variant="outline" className="mr-2 mb-2">
                        Port {port}
                      </Badge>
                    ))}
                  </div>
                </TabsContent>
                
                <TabsContent value="behavior" className="mt-4">
                  <div className="space-y-3">
                    {result.aiAnalysis.behaviorAnalysis.repetitivePatterns.map((pattern, index) => (
                      <div key={index} className="flex items-start gap-2">
                        <AlertTriangle className="h-4 w-4 text-yellow-500 mt-0.5" />
                        <span className="text-sm">{pattern}</span>
                      </div>
                    ))}
                  </div>
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>

          {/* Recommendations */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle>AI Recommendations</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {result.recommendations.map((recommendation, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <CheckCircle className="h-4 w-4 text-blue-500 mt-0.5" />
                      <span className="text-sm">{recommendation}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle>Mitigation Steps</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {result.mitigationSteps.map((step, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <Shield className="h-4 w-4 text-green-500 mt-0.5" />
                      <span className="text-sm">{step}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </div>
  )
}
