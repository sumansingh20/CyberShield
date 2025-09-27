'use client'

import { useState } from 'react'
import { Shield, CreditCard, AlertTriangle, CheckCircle, XCircle, MapPin, Clock, User } from 'lucide-react'

interface FraudResult {
  isFraud: boolean
  riskLevel: string
  confidence: number
  reasons: string[]
  analysis: {
    suspiciousFactors: string[]
    behavioralPatterns: string[]
    transactionAnomalies: string[]
    locationAnalysis: {
      isUnusualLocation: boolean
      riskFactors: string[]
    }
    timeAnalysis: {
      isUnusualTime: boolean
      riskFactors: string[]
    }
  }
  recommendations: string[]
}

export default function AIFraudDetection() {
  const [analysisType, setAnalysisType] = useState<'transaction' | 'profile'>('transaction')
  const [formData, setFormData] = useState({
    // Transaction data
    amount: '',
    currency: 'USD',
    merchantCategory: '',
    location: '',
    deviceInfo: '',
    // Profile data
    accountAge: '',
    transactionHistory: '',
    behaviorData: ''
  })
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<FraudResult | null>(null)
  const [error, setError] = useState('')

  const analyzeFraud = async () => {
    const requiredFields = analysisType === 'transaction' 
      ? ['amount', 'merchantCategory'] 
      : ['accountAge', 'transactionHistory']
    
    const missingFields = requiredFields.filter(field => !formData[field as keyof typeof formData])
    if (missingFields.length > 0) {
      setError(`Please fill in required fields: ${missingFields.join(', ')}`)
      return
    }

    setIsAnalyzing(true)
    setError('')
    setResult(null)

    try {
      const requestData = analysisType === 'transaction' ? {
        type: 'transaction',
        data: {
          amount: parseFloat(formData.amount),
          currency: formData.currency,
          merchantCategory: formData.merchantCategory,
          location: formData.location,
          deviceInfo: formData.deviceInfo,
          timestamp: new Date().toISOString()
        }
      } : {
        type: 'profile',
        data: formData.behaviorData || `Account age: ${formData.accountAge}, Transaction history: ${formData.transactionHistory}`
      }

      const response = await fetch('/api/tools/ai-fraud-detector', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(requestData),
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

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-4xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-blue-500/10 rounded-lg">
              <CreditCard className="w-8 h-8 text-blue-500" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">AI Fraud Detection</h1>
              <p className="text-gray-600 dark:text-gray-400">
                Machine learning fraud detection for financial systems
              </p>
            </div>
          </div>
        </div>

        {/* Analysis Form */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Shield className="w-5 h-5 text-blue-500" />
            Fraud Analysis
          </h2>

          {/* Analysis Type Selection */}
          <div className="mb-6">
            <label className="block text-sm font-medium mb-2">Analysis Type</label>
            <div className="flex gap-4">
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  value="transaction"
                  checked={analysisType === 'transaction'}
                  onChange={(e) => setAnalysisType(e.target.value as 'transaction' | 'profile')}
                  className="w-4 h-4 text-blue-600"
                />
                <CreditCard className="w-4 h-4" />
                Transaction Analysis
              </label>
              <label className="flex items-center gap-2">
                <input
                  type="radio"
                  value="profile"
                  checked={analysisType === 'profile'}
                  onChange={(e) => setAnalysisType(e.target.value as 'transaction' | 'profile')}
                  className="w-4 h-4 text-blue-600"
                />
                <User className="w-4 h-4" />
                Profile Analysis
              </label>
            </div>
          </div>

          {/* Transaction Analysis Form */}
          {analysisType === 'transaction' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Transaction Amount *
                  </label>
                  <input
                    type="number"
                    value={formData.amount}
                    onChange={(e) => setFormData({...formData, amount: e.target.value})}
                    placeholder="1000.00"
                    step="0.01"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">Currency</label>
                  <select
                    value={formData.currency}
                    onChange={(e) => setFormData({...formData, currency: e.target.value})}
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  >
                    <option value="USD">USD</option>
                    <option value="EUR">EUR</option>
                    <option value="GBP">GBP</option>
                    <option value="JPY">JPY</option>
                    <option value="CAD">CAD</option>
                  </select>
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">
                  Merchant Category *
                </label>
                <input
                  type="text"
                  value={formData.merchantCategory}
                  onChange={(e) => setFormData({...formData, merchantCategory: e.target.value})}
                  placeholder="e.g., Online Retail, Gas Station, Restaurant"
                  className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">
                  <MapPin className="w-4 h-4 inline mr-1" />
                  Location
                </label>
                <input
                  type="text"
                  value={formData.location}
                  onChange={(e) => setFormData({...formData, location: e.target.value})}
                  placeholder="e.g., New York, USA or Unknown"
                  className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                />
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">Device Info</label>
                <input
                  type="text"
                  value={formData.deviceInfo}
                  onChange={(e) => setFormData({...formData, deviceInfo: e.target.value})}
                  placeholder="e.g., iPhone 15, Chrome Browser, Known Device"
                  className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                />
              </div>
            </div>
          )}

          {/* Profile Analysis Form */}
          {analysisType === 'profile' && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Account Age (years) *
                  </label>
                  <input
                    type="number"
                    value={formData.accountAge}
                    onChange={(e) => setFormData({...formData, accountAge: e.target.value})}
                    placeholder="2.5"
                    step="0.1"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium mb-2">
                    Transaction History *
                  </label>
                  <input
                    type="text"
                    value={formData.transactionHistory}
                    onChange={(e) => setFormData({...formData, transactionHistory: e.target.value})}
                    placeholder="e.g., Regular small purchases, Monthly large transfers"
                    className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                  />
                </div>
              </div>
              
              <div>
                <label className="block text-sm font-medium mb-2">Behavioral Data</label>
                <textarea
                  value={formData.behaviorData}
                  onChange={(e) => setFormData({...formData, behaviorData: e.target.value})}
                  placeholder="Additional behavioral patterns, login times, device usage patterns, etc."
                  rows={4}
                  className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
                />
              </div>
            </div>
          )}

          {/* Analyze Button */}
          <button
            onClick={analyzeFraud}
            disabled={isAnalyzing}
            className="w-full mt-6 bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {isAnalyzing ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                Analyzing with AI...
              </>
            ) : (
              <>
                <Shield className="w-5 h-5" />
                Analyze for Fraud
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
            <div className={`rounded-lg border p-6 ${getRiskBgColor(result.riskLevel)}`}>
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold">Fraud Assessment</h2>
                <div className={`flex items-center gap-2 ${getRiskColor(result.riskLevel)}`}>
                  {result.isFraud ? (
                    <XCircle className="w-6 h-6" />
                  ) : (
                    <CheckCircle className="w-6 h-6" />
                  )}
                  <span className="font-bold">
                    {result.isFraud ? 'FRAUD DETECTED' : 'APPEARS LEGITIMATE'}
                  </span>
                </div>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Risk Level</p>
                  <p className={`text-2xl font-bold ${getRiskColor(result.riskLevel)}`}>
                    {result.riskLevel}
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Confidence</p>
                  <p className={`text-2xl font-bold ${getRiskColor(result.riskLevel)}`}>
                    {result.confidence}%
                  </p>
                </div>
                <div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Risk Factors</p>
                  <p className={`text-2xl font-bold ${getRiskColor(result.riskLevel)}`}>
                    {result.analysis.suspiciousFactors.length}
                  </p>
                </div>
              </div>
            </div>

            {/* Analysis Reasons */}
            {result.reasons.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4">Analysis Summary</h3>
                <div className="space-y-2">
                  {result.reasons.map((reason, index) => (
                    <div key={index} className="flex items-start gap-2 p-2 bg-gray-50 dark:bg-gray-700 rounded">
                      <div className="w-6 h-6 bg-blue-500 text-white rounded-full flex items-center justify-center text-sm font-bold mt-0.5">
                        {index + 1}
                      </div>
                      <span className="text-sm">{reason}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Detailed Analysis */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
              <h3 className="text-lg font-semibold mb-4">Detailed Analysis</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                
                {/* Suspicious Factors */}
                {result.analysis.suspiciousFactors.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-3 flex items-center gap-2 text-red-600">
                      <AlertTriangle className="w-4 h-4" />
                      Suspicious Factors
                    </h4>
                    <div className="space-y-2">
                      {result.analysis.suspiciousFactors.map((factor, index) => (
                        <div key={index} className="text-sm p-2 bg-red-50 dark:bg-red-900/20 rounded">
                          {factor}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Behavioral Patterns */}
                {result.analysis.behavioralPatterns.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-3 flex items-center gap-2 text-orange-600">
                      <User className="w-4 h-4" />
                      Behavioral Patterns
                    </h4>
                    <div className="space-y-2">
                      {result.analysis.behavioralPatterns.map((pattern, index) => (
                        <div key={index} className="text-sm p-2 bg-orange-50 dark:bg-orange-900/20 rounded">
                          {pattern}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Location Analysis */}
                {result.analysis.locationAnalysis.riskFactors.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-3 flex items-center gap-2 text-purple-600">
                      <MapPin className="w-4 h-4" />
                      Location Analysis
                    </h4>
                    <div className="space-y-2">
                      <div className="text-sm">
                        <span className="font-medium">Unusual Location: </span>
                        <span className={result.analysis.locationAnalysis.isUnusualLocation ? 'text-red-600' : 'text-green-600'}>
                          {result.analysis.locationAnalysis.isUnusualLocation ? 'Yes' : 'No'}
                        </span>
                      </div>
                      {result.analysis.locationAnalysis.riskFactors.map((factor, index) => (
                        <div key={index} className="text-sm p-2 bg-purple-50 dark:bg-purple-900/20 rounded">
                          {factor}
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* Time Analysis */}
                {result.analysis.timeAnalysis.riskFactors.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-3 flex items-center gap-2 text-indigo-600">
                      <Clock className="w-4 h-4" />
                      Time Analysis
                    </h4>
                    <div className="space-y-2">
                      <div className="text-sm">
                        <span className="font-medium">Unusual Time: </span>
                        <span className={result.analysis.timeAnalysis.isUnusualTime ? 'text-red-600' : 'text-green-600'}>
                          {result.analysis.timeAnalysis.isUnusualTime ? 'Yes' : 'No'}
                        </span>
                      </div>
                      {result.analysis.timeAnalysis.riskFactors.map((factor, index) => (
                        <div key={index} className="text-sm p-2 bg-indigo-50 dark:bg-indigo-900/20 rounded">
                          {factor}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
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