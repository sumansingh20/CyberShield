"use client"

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Input } from '@/src/ui/components/ui/input'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Badge } from '@/src/ui/components/ui/badge'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { CreditCard, DollarSign, AlertTriangle, CheckCircle, Eye, Brain, TrendingUp, Users } from 'lucide-react'
import { TerminalOutput } from '@/components/TerminalOutput'

interface FraudResult {
  isFraudulent: boolean
  riskScore: number
  riskLevel: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL'
  confidence: number
  reasons: string[]
  aiAnalysis: {
    behavioralPatterns: string[]
    transactionAnomalies: string[]
    locationAnalysis: {
      isUnusualLocation: boolean
      riskFactors: string[]
    }
    timeAnalysis: {
      isUnusualTime: boolean
      patterns: string[]
    }
    deviceAnalysis: {
      isNewDevice: boolean
      riskIndicators: string[]
    }
    amountAnalysis: {
      isUnusualAmount: boolean
      comparedToHistory: string
    }
  }
  recommendations: string[]
}

export default function AIFraudDetector() {
  const [analysisType, setAnalysisType] = useState<'transaction' | 'profile'>('transaction')
  const [transactionData, setTransactionData] = useState({
    amount: '',
    merchant: '',
    location: '',
    time: '',
    paymentMethod: '',
    description: ''
  })
  const [profileData, setProfileData] = useState('')
  const [result, setResult] = useState<FraudResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [terminalOutput, setTerminalOutput] = useState<string[]>([])

  const handleAnalyze = async () => {
    const hasTransactionData = analysisType === 'transaction' && 
      (transactionData.amount || transactionData.merchant || transactionData.location)
    const hasProfileData = analysisType === 'profile' && profileData.trim()

    if (!hasTransactionData && !hasProfileData) {
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
      addToTerminal('🤖 Initializing AI Fraud Detection System...')
      addToTerminal(`💳 Analysis Type: ${analysisType.toUpperCase()}`)
      
      const payload = analysisType === 'transaction' 
        ? { type: 'transaction', data: transactionData }
        : { type: 'profile', data: profileData }

      addToTerminal('🔍 Analyzing behavioral patterns...')
      addToTerminal('📊 Processing transaction anomalies...')
      addToTerminal('🌍 Checking location intelligence...')
      addToTerminal('⏰ Analyzing temporal patterns...')
      addToTerminal('📱 Examining device fingerprints...')
      
      const response = await fetch('/api/tools/ai-fraud-detector', {
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
      addToTerminal(`🎯 Risk Score: ${data.riskScore}/100`)
      addToTerminal(`⚠️ Risk Level: ${data.riskLevel}`)
      addToTerminal(`📈 Confidence: ${data.confidence}%`)
      
      setResult(data)
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Analysis failed'
      setError(errorMessage)
      addToTerminal(`❌ Error: ${errorMessage}`)
    } finally {
      setLoading(false)
    }
  }

  const getRiskColor = (level: string) => {
    switch (level) {
      case 'LOW': return 'bg-green-500'
      case 'MEDIUM': return 'bg-yellow-500'
      case 'HIGH': return 'bg-orange-500'
      case 'CRITICAL': return 'bg-red-500'
      default: return 'bg-gray-500'
    }
  }

  const getRiskIcon = (level: string) => {
    switch (level) {
      case 'LOW': return <CheckCircle className="h-4 w-4" />
      case 'MEDIUM': return <Eye className="h-4 w-4" />
      case 'HIGH': return <AlertTriangle className="h-4 w-4" />
      case 'CRITICAL': return <CreditCard className="h-4 w-4" />
      default: return <CreditCard className="h-4 w-4" />
    }
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <Brain className="h-8 w-8 text-primary" />
          <h1 className="text-3xl font-bold">AI Fraud Detection System</h1>
        </div>
        <p className="text-muted-foreground">
          Advanced machine learning system to detect fraudulent transactions and suspicious user behavior patterns
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Input Section */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CreditCard className="h-5 w-5" />
              Fraud Analysis Input
            </CardTitle>
            <CardDescription>
              Analyze transactions or user profiles for fraudulent activity
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Tabs value={analysisType} onValueChange={(value) => setAnalysisType(value as 'transaction' | 'profile')}>
              <TabsList className="grid w-full grid-cols-2">
                <TabsTrigger value="transaction" className="flex items-center gap-2">
                  <DollarSign className="h-4 w-4" />
                  Transaction Analysis
                </TabsTrigger>
                <TabsTrigger value="profile" className="flex items-center gap-2">
                  <Users className="h-4 w-4" />
                  Profile Analysis
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="transaction" className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Amount ($)</label>
                    <Input
                      placeholder="1500.00"
                      value={transactionData.amount}
                      onChange={(e) => setTransactionData(prev => ({ ...prev, amount: e.target.value }))}
                      type="number"
                      step="0.01"
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Payment Method</label>
                    <Input
                      placeholder="Credit Card, Debit, PayPal, etc."
                      value={transactionData.paymentMethod}
                      onChange={(e) => setTransactionData(prev => ({ ...prev, paymentMethod: e.target.value }))}
                    />
                  </div>
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium">Merchant/Recipient</label>
                  <Input
                    placeholder="Amazon, Local Store, John Doe, etc."
                    value={transactionData.merchant}
                    onChange={(e) => setTransactionData(prev => ({ ...prev, merchant: e.target.value }))}
                  />
                </div>
                
                <div className="grid grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Location</label>
                    <Input
                      placeholder="New York, NY"
                      value={transactionData.location}
                      onChange={(e) => setTransactionData(prev => ({ ...prev, location: e.target.value }))}
                    />
                  </div>
                  <div className="space-y-2">
                    <label className="text-sm font-medium">Time</label>
                    <Input
                      placeholder="2:30 AM"
                      value={transactionData.time}
                      onChange={(e) => setTransactionData(prev => ({ ...prev, time: e.target.value }))}
                    />
                  </div>
                </div>
                
                <div className="space-y-2">
                  <label className="text-sm font-medium">Description</label>
                  <Textarea
                    placeholder="Additional transaction details..."
                    value={transactionData.description}
                    onChange={(e) => setTransactionData(prev => ({ ...prev, description: e.target.value }))}
                    rows={3}
                  />
                </div>
              </TabsContent>
              
              <TabsContent value="profile" className="space-y-4">
                <div className="space-y-2">
                  <label className="text-sm font-medium">User Profile Data</label>
                  <Textarea
                    placeholder="Paste user activity logs, transaction history, behavioral data, or profile information..."
                    value={profileData}
                    onChange={(e) => setProfileData(e.target.value)}
                    rows={8}
                    className="min-h-[200px]"
                  />
                </div>
                <Alert>
                  <AlertTriangle className="h-4 w-4" />
                  <AlertDescription>
                    Ensure all personal data is anonymized or has proper consent before analysis.
                  </AlertDescription>
                </Alert>
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
                  Analyze for Fraud
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Terminal Output */}
        <Card>
          <CardHeader>
            <CardTitle>AI Analysis Process</CardTitle>
            <CardDescription>Real-time fraud detection analysis</CardDescription>
          </CardHeader>
          <CardContent>
            <TerminalOutput 
              output={terminalOutput.join('\n')} 
              isLoading={loading}
              title="AI Analysis Process"
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
                {getRiskIcon(result.riskLevel)}
                Fraud Detection Results
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold mb-2">
                    {result.isFraudulent ? '🚨 FRAUD' : '✅ LEGITIMATE'}
                  </div>
                  <p className="text-sm text-muted-foreground">Classification</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold mb-2">{result.riskScore}/100</div>
                  <p className="text-sm text-muted-foreground">Risk Score</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <div className="text-2xl font-bold mb-2">{result.confidence}%</div>
                  <p className="text-sm text-muted-foreground">Confidence</p>
                </div>
                <div className="text-center p-4 border rounded-lg">
                  <Badge className={`${getRiskColor(result.riskLevel)} text-white`}>
                    {result.riskLevel} RISK
                  </Badge>
                  <p className="text-sm text-muted-foreground mt-2">Risk Level</p>
                </div>
              </div>

              <div className="space-y-4">
                <div>
                  <h4 className="font-semibold mb-2">Key Risk Factors:</h4>
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
                <CardTitle className="flex items-center gap-2">
                  <TrendingUp className="h-5 w-5" />
                  Behavioral Patterns
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {result.aiAnalysis.behavioralPatterns.map((pattern, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 text-orange-500 mt-0.5" />
                      <span className="text-sm">{pattern}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <DollarSign className="h-5 w-5" />
                  Transaction Anomalies
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {result.aiAnalysis.transactionAnomalies.map((anomaly, index) => (
                    <div key={index} className="flex items-start gap-2">
                      <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
                      <span className="text-sm">{anomaly}</span>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Recommendations */}
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
        </div>
      )}
    </div>
  )
}
