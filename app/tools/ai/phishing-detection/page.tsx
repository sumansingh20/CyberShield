'use client'

import { useState } from 'react'
import { Shield, Mail, Globe, AlertTriangle, CheckCircle, XCircle } from 'lucide-react'

interface PhishingResult {
  isPhishing: boolean
  confidence: number
  riskFactors: string[]
  legitimateIndicators: string[]
  recommendations: string[]
  analysis: {
    suspiciousPatterns: string[]
    urlAnalysis: {
      suspicious: boolean
      riskFactors: string[]
    }
    domainAnalysis: {
      reputation: string
      riskLevel: string
    }
  }
}

export default function AIPhishingDetection() {
  const [analysisType, setAnalysisType] = useState<'email' | 'url'>('email')
  const [content, setContent] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<PhishingResult | null>(null)
  const [error, setError] = useState('')

  const analyzeContent = async () => {
    if (!content.trim()) {
      setError('Please provide content to analyze')
      return
    }

    setIsAnalyzing(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch('/api/tools/ai-phishing-detector', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          type: analysisType,
          content: content.trim()
        }),
      })

      if (!response.ok) {
        throw new Error(`Analysis failed: ${response.statusText}`)
      }

      const data = await response.json()
      setResult(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Analysis failed')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const getRiskColor = (confidence: number) => {
    if (confidence >= 80) return 'text-red-500'
    if (confidence >= 60) return 'text-orange-500'
    if (confidence >= 40) return 'text-yellow-500'
    return 'text-green-500'
  }

  const getRiskBgColor = (confidence: number) => {
    if (confidence >= 80) return 'bg-red-500/10'
    if (confidence >= 60) return 'bg-orange-500/10'
    if (confidence >= 40) return 'bg-yellow-500/10'
    return 'bg-green-500/10'
  }

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-purple-500/10 rounded-lg">
              <Shield className="w-8 h-8 text-purple-500" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">AI Phishing Detection</h1>
              <p className="text-gray-600 dark:text-gray-400">
                Advanced AI-powered phishing and scam detection
              </p>
            </div>
          </div>
        </div>

        {/* Analysis Form */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <AlertTriangle className="w-5 h-5 text-purple-500" />
            Content Analysis
          </h2>

          {/* Analysis Type Selection */}
          <div className="mb-4">
            <label className="block text-sm font-medium mb-2">Analysis Type</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  value="email"
                  checked={analysisType === 'email'}
                  onChange={(e) => setAnalysisType(e.target.value as 'email' | 'url')}
                  className="w-4 h-4 text-purple-600"
                />
                <Mail className="w-4 h-4" />
                Email Content
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  value="url"
                  checked={analysisType === 'url'}
                  onChange={(e) => setAnalysisType(e.target.value as 'email' | 'url')}
                  className="w-4 h-4 text-purple-600"
                />
                <Globe className="w-4 h-4" />
                URL/Website
              </label>
            </div>
          </div>

          {/* Content Input */}
          <div className="mb-4">
            <label className="block text-sm font-medium mb-2">
              {analysisType === 'email' ? 'Email Content' : 'URL to Analyze'}
            </label>
            <textarea
              value={content}
              onChange={(e) => setContent(e.target.value)}
              placeholder={
                analysisType === 'email'
                  ? 'Paste the email content, headers, and body here...'
                  : 'Enter the URL to analyze (e.g., https://example.com)'
              }
              rows={analysisType === 'email' ? 8 : 3}
              className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-purple-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
            />
          </div>

          {/* Analyze Button */}
          <button
            onClick={analyzeContent}
            disabled={isAnalyzing || !content.trim()}
            className="w-full bg-purple-600 hover:bg-purple-700 disabled:bg-gray-400 text-white font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {isAnalyzing ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                Analyzing with AI...
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                Analyze Content
              </>
            )}
          </button>
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
            <div className="flex items-center gap-2 text-red-800 dark:text-red-400">
              <XCircle className="w-5 h-5" />
              <span className="font-medium">Analysis Error</span>
            </div>
            <p className="text-red-700 dark:text-red-300 mt-1">{error}</p>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="space-y-6">
            {/* Overall Assessment */}
            <div className={`rounded-lg border p-6 ${getRiskBgColor(result.confidence)}`}>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold">Overall Assessment</h2>
                <div className={`flex items-center gap-2 ${getRiskColor(result.confidence)}`}>
                  {result.isPhishing ? (
                    <XCircle className="w-6 h-6" />
                  ) : (
                    <CheckCircle className="w-6 h-6" />
                  )}
                  <span className="font-bold">
                    {result.isPhishing ? 'PHISHING DETECTED' : 'APPEARS LEGITIMATE'}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Confidence Level</p>
                  <p className={`text-2xl font-bold ${getRiskColor(result.confidence)}`}>
                    {result.confidence}%
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Risk Assessment</p>
                  <p className={`text-lg font-semibold ${getRiskColor(result.confidence)}`}>
                    {result.confidence >= 80 ? 'Critical Risk' :
                     result.confidence >= 60 ? 'High Risk' :
                     result.confidence >= 40 ? 'Medium Risk' : 'Low Risk'}
                  </p>
                </div>
              </div>
            </div>

            {/* Risk Factors */}
            {result.riskFactors && result.riskFactors.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-red-600">
                  <AlertTriangle className="w-5 h-5" />
                  Risk Factors Identified
                </h3>
                <div className="space-y-2">
                  {result.riskFactors.map((factor, index) => (
                    <div key={index} className="flex items-start gap-2 p-2 bg-red-50 dark:bg-red-900/20 rounded">
                      <XCircle className="w-4 h-4 text-red-500 mt-0.5 flex-shrink-0" />
                      <span className="text-sm">{factor}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Legitimate Indicators */}
            {result.legitimateIndicators && result.legitimateIndicators.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-green-600">
                  <CheckCircle className="w-5 h-5" />
                  Legitimate Indicators
                </h3>
                <div className="space-y-2">
                  {result.legitimateIndicators.map((indicator, index) => (
                    <div key={index} className="flex items-start gap-2 p-2 bg-green-50 dark:bg-green-900/20 rounded">
                      <CheckCircle className="w-4 h-4 text-green-500 mt-0.5 flex-shrink-0" />
                      <span className="text-sm">{indicator}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Detailed Analysis */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
              <h3 className="text-lg font-semibold mb-4">Detailed Analysis</h3>
              <div className="space-y-4">
                {/* Suspicious Patterns */}
                {result.analysis?.suspiciousPatterns && result.analysis.suspiciousPatterns.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-2 text-orange-600">Suspicious Patterns</h4>
                    <div className="space-y-1">
                      {result.analysis.suspiciousPatterns.map((pattern, index) => (
                        <div key={index} className="text-sm p-2 bg-orange-50 dark:bg-orange-900/20 rounded">
                          {pattern}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* URL Analysis */}
                {analysisType === 'url' && result.analysis?.urlAnalysis && (
                  <div>
                    <h4 className="font-medium mb-2">URL Analysis</h4>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div>
                        <p className="text-sm text-gray-600 dark:text-gray-400">Status</p>
                        <p className={`font-medium ${result.analysis.urlAnalysis.suspicious ? 'text-red-600' : 'text-green-600'}`}>
                          {result.analysis.urlAnalysis.suspicious ? 'Suspicious' : 'Clean'}
                        </p>
                      </div>
                      <div>
                        <p className="text-sm text-gray-600 dark:text-gray-400">Domain Reputation</p>
                        <p className="font-medium">{result.analysis.domainAnalysis?.reputation || 'Unknown'}</p>
                      </div>
                    </div>
                  </div>
                )}
              </div>
            </div>

            {/* Recommendations */}
            {result.recommendations && result.recommendations.length > 0 && (
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
          </div>
        )}
      </div>
    </div>
  )
}