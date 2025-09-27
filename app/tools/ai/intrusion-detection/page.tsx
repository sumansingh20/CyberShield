'use client'

import { useState } from 'react'
import { Shield, Activity, AlertTriangle, Network, FileText, Clock } from 'lucide-react'

interface IntrusionResult {
  isIntrusion: boolean
  threatLevel: string
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

export default function AIIntrusionDetection() {
  const [analysisType, setAnalysisType] = useState<'logs' | 'traffic' | 'realtime'>('logs')
  const [data, setData] = useState('')
  const [trafficData, setTrafficData] = useState({
    sourceIP: '',
    destinationIP: '',
    port: '',
    protocol: '',
    payloadSize: '',
    frequency: ''
  })
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<IntrusionResult | null>(null)
  const [error, setError] = useState('')

  const analyzeIntrusion = async () => {
    if (analysisType !== 'realtime') {
      if (analysisType === 'logs' && !data.trim()) {
        setError('Please provide network logs to analyze')
        return
      }
      if (analysisType === 'traffic' && !trafficData.sourceIP) {
        setError('Please provide at least source IP for traffic analysis')
        return
      }
    }

    setIsAnalyzing(true)
    setError('')
    setResult(null)

    try {
      const requestData = {
        type: analysisType,
        data: analysisType === 'traffic' ? trafficData : (data || 'realtime')
      }

      const response = await fetch('/api/tools/ai-intrusion-detector', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData),
      })

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.statusText}`)
      }

      const analysisResult = await response.json()
      setResult(analysisResult)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const getThreatColor = (threatLevel: string) => {
    switch (threatLevel.toUpperCase()) {
      case 'CRITICAL': return 'text-red-500'
      case 'HIGH': return 'text-orange-500'
      case 'MEDIUM': return 'text-yellow-500'
      case 'LOW': return 'text-green-500'
      default: return 'text-gray-500'
    }
  }

  const getThreatBgColor = (threatLevel: string) => {
    switch (threatLevel.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500/10'
      case 'HIGH': return 'bg-orange-500/10'
      case 'MEDIUM': return 'bg-yellow-500/10'
      case 'LOW': return 'bg-green-500/10'
      default: return 'bg-gray-500/10'
    }
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-indigo-500/10 rounded-lg">
              <Activity className="w-8 h-8 text-indigo-500" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">AI Intrusion Detection</h1>
              <p className="text-gray-600 dark:text-gray-400">
                Real-time AI network intrusion detection system
              </p>
            </div>
          </div>
        </div>

        {/* Analysis Form */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Network className="w-5 h-5 text-indigo-500" />
            Intrusion Analysis
          </h2>

          {/* Analysis Type Selection */}
          <div className="mb-6">
            <label className="block text-sm font-medium mb-2">Analysis Type</label>
            <div className="flex gap-4 flex-wrap">
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  value="logs"
                  checked={analysisType === 'logs'}
                  onChange={(e) => setAnalysisType(e.target.value as any)}
                  className="w-4 h-4 text-indigo-600"
                />
                <FileText className="w-4 h-4" />
                Network Logs
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  value="traffic"
                  checked={analysisType === 'traffic'}
                  onChange={(e) => setAnalysisType(e.target.value as any)}
                  className="w-4 h-4 text-indigo-600"
                />
                <Network className="w-4 h-4" />
                Traffic Data
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  value="realtime"
                  checked={analysisType === 'realtime'}
                  onChange={(e) => setAnalysisType(e.target.value as any)}
                  className="w-4 h-4 text-indigo-600"
                />
                <Clock className="w-4 h-4" />
                Real-time Simulation
              </label>
            </div>
          </div>

          {/* Network Logs Form */}
          {analysisType === 'logs' && (
            <div className="mb-4">
              <label className="block text-sm font-medium mb-2">Network Logs</label>
              <textarea
                value={data}
                onChange={(e) => setData(e.target.value)}
                placeholder="Paste network logs, firewall logs, or IDS alerts here...
Example:
2024-01-15 10:30:15 TCP 192.168.1.100:4444 -> 10.0.0.1:80 SYN flood detected
2024-01-15 10:30:16 HTTP 192.168.1.101 GET /admin/config.php - 401 Unauthorized
2024-01-15 10:30:17 SSH 203.0.113.1 Multiple failed login attempts for user 'root'"
                rows={8}
                className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
              />
            </div>
          )}

          {/* Traffic Data Form */}
          {analysisType === 'traffic' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Source IP *</label>
                  <input
                    type="text"
                    value={trafficData.sourceIP}
                    onChange={(e) => setTrafficData({...trafficData, sourceIP: e.target.value})}
                    placeholder="192.168.1.100"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Destination IP</label>
                  <input
                    type="text"
                    value={trafficData.destinationIP}
                    onChange={(e) => setTrafficData({...trafficData, destinationIP: e.target.value})}
                    placeholder="10.0.0.1"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Port</label>
                  <input
                    type="text"
                    value={trafficData.port}
                    onChange={(e) => setTrafficData({...trafficData, port: e.target.value})}
                    placeholder="80, 443, 22, etc."
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Protocol</label>
                  <input
                    type="text"
                    value={trafficData.protocol}
                    onChange={(e) => setTrafficData({...trafficData, protocol: e.target.value})}
                    placeholder="TCP, UDP, ICMP"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">Payload Size (bytes)</label>
                  <input
                    type="number"
                    value={trafficData.payloadSize}
                    onChange={(e) => setTrafficData({...trafficData, payloadSize: e.target.value})}
                    placeholder="1500"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Frequency (requests/min)</label>
                  <input
                    type="number"
                    value={trafficData.frequency}
                    onChange={(e) => setTrafficData({...trafficData, frequency: e.target.value})}
                    placeholder="100"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-indigo-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
              </div>
            </div>
          )}

          {/* Real-time Simulation Info */}
          {analysisType === 'realtime' && (
            <div className="bg-blue-50 dark:bg-blue-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-4 mb-4">
              <div className="flex items-center gap-2 text-blue-800 dark:text-blue-400 mb-2">
                <Clock className="w-5 h-5" />
                <span className="font-medium">Real-time Network Monitoring</span>
              </div>
              <p className="text-blue-700 dark:text-blue-300 text-sm">
                This mode simulates real-time network monitoring and threat detection. 
                The AI will analyze current network patterns and detect potential intrusions based on behavioral analysis.
              </p>
            </div>
          )}

          {/* Analyze Button */}
          <button
            onClick={analyzeIntrusion}
            disabled={isAnalyzing}
            className="w-full bg-indigo-600 hover:bg-indigo-700 disabled:bg-gray-400 text-white font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {isAnalyzing ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                Analyzing Network Traffic...
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                Analyze for Intrusions
              </>
            )}
          </button>
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
            <div className="flex items-center gap-2 text-red-800 dark:text-red-400">
              <AlertTriangle className="w-5 h-5" />
              <span className="font-medium">Analysis Error</span>
            </div>
            <p className="text-red-700 dark:text-red-300 mt-1">{error}</p>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="space-y-6">
            {/* Overall Assessment */}
            <div className={`rounded-lg border p-6 ${getThreatBgColor(result.threatLevel)}`}>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold">Intrusion Assessment</h2>
                <div className={`flex items-center gap-2 ${getThreatColor(result.threatLevel)}`}>
                  {result.isIntrusion ? (
                    <AlertTriangle className="w-6 h-6" />
                  ) : (
                    <Shield className="w-6 h-6" />
                  )}
                  <span className="font-bold">
                    {result.isIntrusion ? 'INTRUSION DETECTED' : 'NO INTRUSION DETECTED'}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Threat Level</p>
                  <p className={`text-2xl font-bold ${getThreatColor(result.threatLevel)}`}>
                    {result.threatLevel}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Confidence</p>
                  <p className={`text-2xl font-bold ${getThreatColor(result.threatLevel)}`}>
                    {result.confidence}%
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Attack Types</p>
                  <p className={`text-2xl font-bold ${getThreatColor(result.threatLevel)}`}>
                    {result.attackType.length}
                  </p>
                </div>
              </div>
            </div>

            {/* Attack Types */}
            {result.attackType.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-red-600">
                  <AlertTriangle className="w-5 h-5" />
                  Detected Attack Types
                </h3>
                <div className="flex flex-wrap gap-2">
                  {result.attackType.map((attack, index) => (
                    <span
                      key={index}
                      className="px-3 py-1 bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-400 rounded-full text-sm font-medium"
                    >
                      {attack}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Analysis Summary */}
            {result.reasons.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4">Analysis Summary</h3>
                <div className="space-y-2">
                  {result.reasons.map((reason, index) => (
                    <div key={index} className="flex items-start gap-2 p-2 bg-gray-50 dark:bg-gray-700 rounded">
                      <div className="w-6 h-6 bg-indigo-500 text-white rounded-full flex items-center justify-center text-sm font-bold mt-0.5">
                        {index + 1}
                      </div>
                      <span className="text-sm">{reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Detailed AI Analysis */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
              <h3 className="text-lg font-semibold mb-4">AI Analysis Details</h3>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                
                {/* Network Anomalies */}
                {result.aiAnalysis.networkAnomalies.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-3 flex items-center gap-2 text-orange-600">
                      <Network className="w-4 h-4" />
                      Network Anomalies
                    </h4>
                    <div className="space-y-2">
                      {result.aiAnalysis.networkAnomalies.map((anomaly, index) => (
                        <div key={index} className="text-sm p-2 bg-orange-50 dark:bg-orange-900/20 rounded">
                          {anomaly}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Traffic Patterns */}
                {result.aiAnalysis.trafficPatterns.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-3 flex items-center gap-2 text-blue-600">
                      <Activity className="w-4 h-4" />
                      Traffic Patterns
                    </h4>
                    <div className="space-y-2">
                      {result.aiAnalysis.trafficPatterns.map((pattern, index) => (
                        <div key={index} className="text-sm p-2 bg-blue-50 dark:bg-blue-900/20 rounded">
                          {pattern}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Protocol Analysis */}
                <div>
                  <h4 className="font-medium mb-3 text-purple-600">Protocol Analysis</h4>
                  <div className="space-y-2">
                    {result.aiAnalysis.protocolAnalysis.suspiciousProtocols.length > 0 && (
                      <div className="text-sm">
                        <span className="font-medium">Suspicious Protocols: </span>
                        <span>{result.aiAnalysis.protocolAnalysis.suspiciousProtocols.join(', ')}</span>
                      </div>
                    )}
                    {result.aiAnalysis.protocolAnalysis.unusualPorts.length > 0 && (
                      <div className="text-sm">
                        <span className="font-medium">Unusual Ports: </span>
                        <span>{result.aiAnalysis.protocolAnalysis.unusualPorts.join(', ')}</span>
                      </div>
                    )}
                    {result.aiAnalysis.protocolAnalysis.malformedPackets > 0 && (
                      <div className="text-sm">
                        <span className="font-medium">Malformed Packets: </span>
                        <span className="text-red-600">{result.aiAnalysis.protocolAnalysis.malformedPackets}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Behavior Analysis */}
                <div>
                  <h4 className="font-medium mb-3 text-green-600">Behavior Analysis</h4>
                  <div className="space-y-2">
                    {result.aiAnalysis.behaviorAnalysis.repetitivePatterns.map((pattern, index) => (
                      <div key={index} className="text-sm p-2 bg-green-50 dark:bg-green-900/20 rounded">
                        {pattern}
                      </div>
                    ))}
                    {result.aiAnalysis.behaviorAnalysis.volumeAnomalies.map((anomaly, index) => (
                      <div key={index} className="text-sm p-2 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                        {anomaly}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Recommendations */}
            {result.recommendations.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Shield className="w-5 h-5 text-blue-500" />
                  Security Recommendations
                </h3>
                <div className="space-y-2">
                  {result.recommendations.map((recommendation, index) => (
                    <div key={index} className="flex items-start gap-2 p-3 bg-blue-50 dark:bg-blue-900/20 rounded">
                      <div className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-bold mt-0.5">
                        {index + 1}
                      </div>
                      <span className="text-sm">{recommendation}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Mitigation Steps */}
            {result.mitigationSteps.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-red-500" />
                  Immediate Mitigation Steps
                </h3>
                <div className="space-y-2">
                  {result.mitigationSteps.map((step, index) => (
                    <div key={index} className="flex items-start gap-2 p-3 bg-red-50 dark:bg-red-900/20 rounded">
                      <div className="w-6 h-6 bg-red-500 text-white rounded-full flex items-center justify-center text-sm font-bold mt-0.5">
                        {index + 1}
                      </div>
                      <span className="text-sm">{step}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}