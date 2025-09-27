'use client'

import { useState } from 'react'
import { Shield, Search, AlertTriangle, Eye, Target, Globe } from 'lucide-react'

interface ThreatIntelResult {
  analysisType: string
  threatIntelligence: {
    iocIntelligence?: {
      maliciousIPs: any[]
      maliciousDomains: any[]
      maliciousURLs: any[]
      maliciousHashes: any[]
      riskScore: number
    }
    attackPatterns?: {
      mitreMapping: any[]
      threatGroups: any[]
      malwareFamilies: any[]
      riskScore: number
    }
    vulnerabilityIntel?: {
      criticalCVEs: any[]
      exploitKits: any[]
      riskScore: number
    }
  }
  threatHuntingQueries: string[]
  threatLandscape: {
    overallRiskLevel: string
    keyThreats: string[]
    industryTrends: string[]
    geopoliticalFactors: string[]
    emergingThreats: string[]
  }
  recommendations: string[]
  analysisMetrics: {
    processingTime: number
    indicatorsAnalyzed: number
    maliciousIndicators: number
    confidenceLevel: number
  }
}

export default function AIThreatIntelligence() {
  const [analysisType, setAnalysisType] = useState<'ioc' | 'attack-patterns' | 'vulnerabilities' | 'comprehensive'>('ioc')
  const [data, setData] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<ThreatIntelResult | null>(null)
  const [error, setError] = useState('')

  const analyzeThreats = async () => {
    if (!data.trim()) {
      setError('Please provide data to analyze')
      return
    }

    setIsAnalyzing(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch('/api/tools/ai-threat-intelligence', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          analysisType,
          data: data.trim()
        }),
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

  const getRiskColor = (riskLevel: string) => {
    switch (riskLevel.toUpperCase()) {
      case 'CRITICAL': return 'text-red-500'
      case 'HIGH': return 'text-orange-500'
      case 'MEDIUM': return 'text-yellow-500'
      case 'LOW': return 'text-green-500'
      default: return 'text-gray-500'
    }
  }

  const getRiskBgColor = (riskLevel: string) => {
    switch (riskLevel.toUpperCase()) {
      case 'CRITICAL': return 'bg-red-500/10'
      case 'HIGH': return 'bg-orange-500/10'
      case 'MEDIUM': return 'bg-yellow-500/10'
      case 'LOW': return 'bg-green-500/10'
      default: return 'bg-gray-500/10'
    }
  }

  const getPlaceholderText = () => {
    switch (analysisType) {
      case 'ioc':
        return `Enter Indicators of Compromise (IoCs) - one per line:
192.168.1.100
malware-site.com
http://suspicious-url.org/payload.exe
e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`
      case 'attack-patterns':
        return `Enter attack patterns or TTPs to analyze:
Spear phishing campaign
PowerShell execution
Credential dumping
Lateral movement
Data exfiltration`
      case 'vulnerabilities':
        return `Enter vulnerabilities to analyze:
CVE-2021-44228
CVE-2020-1472
Log4Shell
Zerologon
PrintNightmare`
      case 'comprehensive':
        return `Enter mixed threat intelligence data:
192.168.1.100
CVE-2021-44228
Spear phishing
malware-domain.com
PowerShell execution`
      default:
        return 'Enter threat intelligence data...'
    }
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-red-500/10 rounded-lg">
              <Eye className="w-8 h-8 text-red-500" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">AI Threat Intelligence</h1>
              <p className="text-gray-600 dark:text-gray-400">
                Automated threat intelligence gathering and analysis
              </p>
            </div>
          </div>
        </div>

        {/* Analysis Form */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Search className="w-5 h-5 text-red-500" />
            Threat Intelligence Analysis
          </h2>

          {/* Analysis Type Selection */}
          <div className="mb-6">
            <label className="block text-sm font-medium mb-2">Analysis Type</label>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <label className="flex items-center gap-2 p-3 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700">
                <input
                  type="radio"
                  value="ioc"
                  checked={analysisType === 'ioc'}
                  onChange={(e) => setAnalysisType(e.target.value as any)}
                  className="w-4 h-4 text-red-600"
                />
                <Target className="w-4 h-4" />
                <span className="text-sm font-medium">IoCs</span>
              </label>
              <label className="flex items-center gap-2 p-3 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700">
                <input
                  type="radio"
                  value="attack-patterns"
                  checked={analysisType === 'attack-patterns'}
                  onChange={(e) => setAnalysisType(e.target.value as any)}
                  className="w-4 h-4 text-red-600"
                />
                <AlertTriangle className="w-4 h-4" />
                <span className="text-sm font-medium">Attack Patterns</span>
              </label>
              <label className="flex items-center gap-2 p-3 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700">
                <input
                  type="radio"
                  value="vulnerabilities"
                  checked={analysisType === 'vulnerabilities'}
                  onChange={(e) => setAnalysisType(e.target.value as any)}
                  className="w-4 h-4 text-red-600"
                />
                <Shield className="w-4 h-4" />
                <span className="text-sm font-medium">Vulnerabilities</span>
              </label>
              <label className="flex items-center gap-2 p-3 border rounded-lg cursor-pointer hover:bg-gray-50 dark:hover:bg-gray-700">
                <input
                  type="radio"
                  value="comprehensive"
                  checked={analysisType === 'comprehensive'}
                  onChange={(e) => setAnalysisType(e.target.value as any)}
                  className="w-4 h-4 text-red-600"
                />
                <Globe className="w-4 h-4" />
                <span className="text-sm font-medium">Comprehensive</span>
              </label>
            </div>
          </div>

          {/* Data Input */}
          <div className="mb-4">
            <label className="block text-sm font-medium mb-2">Threat Data</label>
            <textarea
              value={data}
              onChange={(e) => setData(e.target.value)}
              placeholder={getPlaceholderText()}
              rows={8}
              className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
            />
          </div>

          {/* Analyze Button */}
          <button
            onClick={analyzeThreats}
            disabled={isAnalyzing || !data.trim()}
            className="w-full bg-red-600 hover:bg-red-700 disabled:bg-gray-400 text-white font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {isAnalyzing ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                Analyzing Threat Intelligence...
              </>
            ) : (
              <>
                <Eye className="w-5 h-5" />
                Analyze Threats
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
            <div className={`rounded-lg border p-6 ${getRiskBgColor(result.threatLandscape.overallRiskLevel)}`}>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold">Threat Assessment</h2>
                <div className={`flex items-center gap-2 ${getRiskColor(result.threatLandscape.overallRiskLevel)}`}>
                  <AlertTriangle className="w-6 h-6" />
                  <span className="font-bold">
                    {result.threatLandscape.overallRiskLevel} RISK
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Analysis Type</p>
                  <p className="text-lg font-bold capitalize">{result.analysisType}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Processing Time</p>
                  <p className="text-lg font-bold">{result.analysisMetrics.processingTime}ms</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Indicators Analyzed</p>
                  <p className="text-lg font-bold">{result.analysisMetrics.indicatorsAnalyzed}</p>
                </div>
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Confidence Level</p>
                  <p className="text-lg font-bold">{result.analysisMetrics.confidenceLevel}%</p>
                </div>
              </div>
            </div>

            {/* Key Threats */}
            {result.threatLandscape.keyThreats.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-red-600">
                  <Target className="w-5 h-5" />
                  Key Threats Identified
                </h3>
                <div className="flex flex-wrap gap-2">
                  {result.threatLandscape.keyThreats.map((threat, index) => (
                    <span
                      key={index}
                      className="px-3 py-1 bg-red-100 dark:bg-red-900/20 text-red-800 dark:text-red-400 rounded-full text-sm font-medium"
                    >
                      {threat}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* IoC Intelligence */}
            {result.threatIntelligence.iocIntelligence && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4">Indicators of Compromise (IoCs)</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                  <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Malicious IPs</p>
                    <p className="text-2xl font-bold text-red-600">
                      {result.threatIntelligence.iocIntelligence.maliciousIPs.length}
                    </p>
                  </div>
                  <div className="bg-orange-50 dark:bg-orange-900/20 p-4 rounded-lg">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Malicious Domains</p>
                    <p className="text-2xl font-bold text-orange-600">
                      {result.threatIntelligence.iocIntelligence.maliciousDomains.length}
                    </p>
                  </div>
                  <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Malicious URLs</p>
                    <p className="text-2xl font-bold text-yellow-600">
                      {result.threatIntelligence.iocIntelligence.maliciousURLs.length}
                    </p>
                  </div>
                  <div className="bg-purple-50 dark:bg-purple-900/20 p-4 rounded-lg">
                    <p className="text-sm text-gray-600 dark:text-gray-400">Malicious Hashes</p>
                    <p className="text-2xl font-bold text-purple-600">
                      {result.threatIntelligence.iocIntelligence.maliciousHashes.length}
                    </p>
                  </div>
                </div>

                {/* Malicious IPs Details */}
                {result.threatIntelligence.iocIntelligence.maliciousIPs.length > 0 && (
                  <div className="mt-6">
                    <h4 className="font-medium mb-3 text-red-600">Malicious IP Details</h4>
                    <div className="space-y-2">
                      {result.threatIntelligence.iocIntelligence.maliciousIPs.slice(0, 5).map((ip: any, index: number) => (
                        <div key={index} className="p-3 bg-red-50 dark:bg-red-900/20 rounded-lg">
                          <div className="flex justify-between items-start">
                            <div>
                              <p className="font-mono font-bold">{ip.indicator}</p>
                              <p className="text-sm text-gray-600">{ip.reputation} • {ip.geolocation}</p>
                            </div>
                            <div className="text-right">
                              <p className="text-sm font-medium">Threat Types:</p>
                              <p className="text-xs text-gray-600">{ip.threatTypes.join(', ')}</p>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Attack Patterns */}
            {result.threatIntelligence.attackPatterns && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4">Attack Patterns Analysis</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  
                  {/* MITRE Mapping */}
                  {result.threatIntelligence.attackPatterns.mitreMapping.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-3 text-blue-600">MITRE ATT&CK Techniques</h4>
                      <div className="space-y-2">
                        {result.threatIntelligence.attackPatterns.mitreMapping.map((mitre: any, index: number) => (
                          <div key={index} className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded">
                            <p className="font-mono text-sm font-bold">{mitre.id}</p>
                            <p className="text-xs text-gray-600">{mitre.name}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Threat Groups */}
                  {result.threatIntelligence.attackPatterns.threatGroups.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-3 text-purple-600">Threat Groups</h4>
                      <div className="space-y-2">
                        {result.threatIntelligence.attackPatterns.threatGroups.map((group: any, index: number) => (
                          <div key={index} className="p-2 bg-purple-50 dark:bg-purple-900/20 rounded">
                            <p className="font-bold text-sm">{group.group}</p>
                            <p className="text-xs text-gray-600">{group.description}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Malware Families */}
                  {result.threatIntelligence.attackPatterns.malwareFamilies.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-3 text-green-600">Malware Families</h4>
                      <div className="space-y-2">
                        {result.threatIntelligence.attackPatterns.malwareFamilies.map((malware: any, index: number) => (
                          <div key={index} className="p-2 bg-green-50 dark:bg-green-900/20 rounded">
                            <p className="font-bold text-sm">{malware.family}</p>
                            <p className="text-xs text-gray-600">{malware.description}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Vulnerability Intelligence */}
            {result.threatIntelligence.vulnerabilityIntel && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4">Vulnerability Intelligence</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                  
                  {/* Critical CVEs */}
                  {result.threatIntelligence.vulnerabilityIntel.criticalCVEs.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-3 text-red-600">Critical CVEs</h4>
                      <div className="space-y-2">
                        {result.threatIntelligence.vulnerabilityIntel.criticalCVEs.map((cve: any, index: number) => (
                          <div key={index} className="p-3 bg-red-50 dark:bg-red-900/20 rounded">
                            <p className="font-mono font-bold">{cve.cve}</p>
                            <div className="flex justify-between text-sm">
                              <span className="text-red-600 font-medium">{cve.severity}</span>
                              <span className={cve.exploited ? 'text-red-600' : 'text-green-600'}>
                                {cve.exploited ? 'Actively Exploited' : 'Not Exploited'}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Exploit Kits */}
                  {result.threatIntelligence.vulnerabilityIntel.exploitKits.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-3 text-orange-600">Exploit Kits</h4>
                      <div className="space-y-2">
                        {result.threatIntelligence.vulnerabilityIntel.exploitKits.map((kit: any, index: number) => (
                          <div key={index} className="p-3 bg-orange-50 dark:bg-orange-900/20 rounded">
                            <p className="font-bold">{kit.kit}</p>
                            <div className="text-sm">
                              <p className={kit.active ? 'text-red-600' : 'text-gray-600'}>
                                Status: {kit.active ? 'Active' : 'Inactive'}
                              </p>
                              <p className="text-gray-600">Targeting: {kit.targetingVuln}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Threat Hunting Queries */}
            {result.threatHuntingQueries.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Search className="w-5 h-5 text-blue-500" />
                  Threat Hunting Queries
                </h3>
                <div className="space-y-3">
                  {result.threatHuntingQueries.map((query, index) => (
                    <div key={index} className="p-3 bg-gray-50 dark:bg-gray-700 rounded-lg font-mono text-sm">
                      {query}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Threat Landscape */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Industry Trends */}
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 text-blue-600">Industry Trends</h3>
                <div className="space-y-2">
                  {result.threatLandscape.industryTrends.map((trend, index) => (
                    <div key={index} className="p-2 bg-blue-50 dark:bg-blue-900/20 rounded text-sm">
                      {trend}
                    </div>
                  ))}
                </div>
              </div>

              {/* Emerging Threats */}
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 text-purple-600">Emerging Threats</h3>
                <div className="space-y-2">
                  {result.threatLandscape.emergingThreats.map((threat, index) => (
                    <div key={index} className="p-2 bg-purple-50 dark:bg-purple-900/20 rounded text-sm">
                      {threat}
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* Recommendations */}
            {result.recommendations.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Shield className="w-5 h-5 text-green-500" />
                  Security Recommendations
                </h3>
                <div className="space-y-2">
                  {result.recommendations.map((recommendation, index) => (
                    <div key={index} className="flex items-start gap-2 p-3 bg-green-50 dark:bg-green-900/20 rounded">
                      <div className="w-6 h-6 bg-green-500 text-white rounded-full flex items-center justify-center text-sm font-bold mt-0.5">
                        {index + 1}
                      </div>
                      <span className="text-sm">{recommendation}</span>
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