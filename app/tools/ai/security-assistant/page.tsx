'use client'

import { useState } from 'react'
import { Bot, MessageCircle, Lightbulb, Shield, CheckCircle, Clock, Users, BarChart } from 'lucide-react'

interface SecurityAssistantResult {
  question: string
  analysis: {
    category: string
    confidence: number
    relevantFrameworks: string[]
    applicableControls: string[]
    complianceImpact: string[]
    threatRelevance: string[]
  }
  recommendations: {
    immediate: string[]
    strategic: string[]
    allRecommendations: string[]
  }
  implementationRoadmap: {
    immediate: string[]
    shortTerm: string[]
    mediumTerm: string[]
    longTerm: string[]
  }
  securityAssessment: {
    currentState: string
    riskLevel: string
    priorityAreas: string[]
    quickWins: string[]
    resourceRequirements: {
      budget: string
      timeline: string
      personnel: string
    }
  }
  securityMetrics: {
    technical: string[]
    operational: string[]
    strategic: string[]
  }
  knowledgeBase: {
    relevantFrameworks: any[]
    relevantThreats: any[]
    complianceDetails: any[]
  }
  performance: {
    analysisTime: number
    confidenceScore: number
    knowledgeBaseMatches: number
    recommendationCount: number
  }
}

export default function AISecurityAssistant() {
  const [question, setQuestion] = useState('')
  const [context, setContext] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<SecurityAssistantResult | null>(null)
  const [error, setError] = useState('')

  // Sample questions for inspiration
  const sampleQuestions = [
    "How do I implement NIST Cybersecurity Framework in my organization?",
    "What are the key requirements for GDPR compliance?",
    "How can I protect against ransomware attacks?",
    "What security controls should I implement for remote work?",
    "How do I conduct a security risk assessment?",
    "What are the best practices for incident response?",
    "How do I achieve SOC 2 Type II compliance?",
    "What security measures are required for PCI DSS compliance?"
  ]

  const askAssistant = async () => {
    if (!question.trim()) {
      setError('Please ask a security question')
      return
    }

    setIsAnalyzing(true)
    setError('')
    setResult(null)

    try {
      const response = await fetch('/api/tools/ai-security-assistant', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          question: question.trim(),
          context: context.trim()
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

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 80) return 'text-green-500'
    if (confidence >= 60) return 'text-blue-500'
    if (confidence >= 40) return 'text-yellow-500'
    return 'text-gray-500'
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

  return (
    <div className="container mx-auto px-4 py-8">
      <div className="max-w-5xl mx-auto">
        {/* Header */}
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-4">
            <div className="p-3 bg-blue-500/10 rounded-lg">
              <Bot className="w-8 h-8 text-blue-500" />
            </div>
            <div>
              <h1 className="text-3xl font-bold">AI Security Assistant</h1>
              <p className="text-gray-600 dark:text-gray-400">
                Intelligent security advisory with automated recommendations
              </p>
            </div>
          </div>
        </div>

        {/* Question Form */}
        <div className="bg-white dark:bg-gray-800 rounded-lg border shadow-lg p-6 mb-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <MessageCircle className="w-5 h-5 text-blue-500" />
            Ask Your Security Question
          </h2>

          {/* Sample Questions */}
          <div className="mb-4">
            <p className="text-sm font-medium mb-2 text-gray-600 dark:text-gray-400">Popular Questions:</p>
            <div className="flex flex-wrap gap-2">
              {sampleQuestions.slice(0, 4).map((sample, index) => (
                <button
                  key={index}
                  onClick={() => setQuestion(sample)}
                  className="text-xs px-3 py-1 bg-blue-50 dark:bg-blue-900/20 text-blue-700 dark:text-blue-300 rounded-full hover:bg-blue-100 dark:hover:bg-blue-900/40 transition-colors"
                >
                  {sample.length > 50 ? sample.substring(0, 47) + '...' : sample}
                </button>
              ))}
            </div>
          </div>

          {/* Question Input */}
          <div className="mb-4">
            <label className="block text-sm font-medium mb-2">Your Security Question</label>
            <textarea
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              placeholder="Ask anything about cybersecurity frameworks, compliance, threats, controls, risk management, incident response, etc."
              rows={3}
              className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
            />
          </div>

          {/* Context Input */}
          <div className="mb-4">
            <label className="block text-sm font-medium mb-2">Additional Context (Optional)</label>
            <textarea
              value={context}
              onChange={(e) => setContext(e.target.value)}
              placeholder="Provide additional context about your organization, industry, current security posture, specific requirements, etc."
              rows={2}
              className="w-full p-3 border rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent dark:bg-gray-700 dark:border-gray-600"
            />
          </div>

          {/* Ask Button */}
          <button
            onClick={askAssistant}
            disabled={isAnalyzing || !question.trim()}
            className="w-full bg-blue-600 hover:bg-blue-700 disabled:bg-gray-400 text-white font-medium py-3 px-4 rounded-lg transition-colors flex items-center justify-center gap-2"
          >
            {isAnalyzing ? (
              <>
                <div className="animate-spin rounded-full h-5 w-5 border-b-2 border-white"></div>
                AI is analyzing your question...
              </>
            ) : (
              <>
                <Bot className="w-5 h-5" />
                Ask AI Security Assistant
              </>
            )}
          </button>
        </div>

        {/* Error Display */}
        {error && (
          <div className="bg-red-50 dark:bg-red-900/20 border border-red-200 dark:border-red-800 rounded-lg p-4 mb-6">
            <div className="flex items-center gap-2 text-red-800 dark:text-red-400">
              <MessageCircle className="w-5 h-5" />
              <span className="font-medium">Assistant Error</span>
            </div>
            <p className="text-red-700 dark:text-red-300 mt-1">{error}</p>
          </div>
        )}

        {/* Results */}
        {result && (
          <div className="space-y-6">
            {/* Analysis Overview */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
              <h2 className="text-xl font-semibold mb-4">Analysis Overview</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Category</p>
                  <p className="text-lg font-bold text-blue-600">{result.analysis.category}</p>
                </div>
                <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Confidence</p>
                  <p className={`text-lg font-bold ${getConfidenceColor(result.analysis.confidence)}`}>
                    {result.analysis.confidence}%
                  </p>
                </div>
                <div className="bg-purple-50 dark:bg-purple-900/20 p-4 rounded-lg">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Processing Time</p>
                  <p className="text-lg font-bold text-purple-600">{result.performance.analysisTime}ms</p>
                </div>
                <div className="bg-orange-50 dark:bg-orange-900/20 p-4 rounded-lg">
                  <p className="text-sm text-gray-600 dark:text-gray-400">Recommendations</p>
                  <p className="text-lg font-bold text-orange-600">{result.performance.recommendationCount}</p>
                </div>
              </div>
            </div>

            {/* Security Assessment */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Shield className="w-5 h-5 text-red-500" />
                Security Assessment
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <div>
                  <h4 className="font-medium mb-3">Current State & Risk Level</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Current State:</span>
                      <span className="font-medium">{result.securityAssessment.currentState}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Risk Level:</span>
                      <span className={`font-medium ${getRiskColor(result.securityAssessment.riskLevel)}`}>
                        {result.securityAssessment.riskLevel}
                      </span>
                    </div>
                  </div>
                </div>
                <div>
                  <h4 className="font-medium mb-3">Resource Requirements</h4>
                  <div className="space-y-2">
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Budget:</span>
                      <span className="font-medium">{result.securityAssessment.resourceRequirements.budget}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Timeline:</span>
                      <span className="font-medium">{result.securityAssessment.resourceRequirements.timeline}</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-sm text-gray-600">Personnel:</span>
                      <span className="font-medium text-xs">{result.securityAssessment.resourceRequirements.personnel}</span>
                    </div>
                  </div>
                </div>
              </div>
            </div>

            {/* Immediate Recommendations */}
            {result.recommendations.immediate.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Lightbulb className="w-5 h-5 text-yellow-500" />
                  Immediate Recommendations
                </h3>
                <div className="space-y-2">
                  {result.recommendations.immediate.map((recommendation, index) => (
                    <div key={index} className="flex items-start gap-2 p-3 bg-yellow-50 dark:bg-yellow-900/20 rounded">
                      <div className="w-6 h-6 bg-yellow-500 text-white rounded-full flex items-center justify-center text-sm font-bold mt-0.5">
                        {index + 1}
                      </div>
                      <span className="text-sm">{recommendation}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Priority Areas & Quick Wins */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              {/* Priority Areas */}
              {result.securityAssessment.priorityAreas.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-red-600">
                    <Shield className="w-5 h-5" />
                    Priority Areas
                  </h3>
                  <div className="space-y-2">
                    {result.securityAssessment.priorityAreas.map((area, index) => (
                      <div key={index} className="p-2 bg-red-50 dark:bg-red-900/20 rounded text-sm font-medium">
                        {area}
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Quick Wins */}
              {result.securityAssessment.quickWins.length > 0 && (
                <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                  <h3 className="text-lg font-semibold mb-4 flex items-center gap-2 text-green-600">
                    <CheckCircle className="w-5 h-5" />
                    Quick Wins
                  </h3>
                  <div className="space-y-2">
                    {result.securityAssessment.quickWins.map((win, index) => (
                      <div key={index} className="p-2 bg-green-50 dark:bg-green-900/20 rounded text-sm">
                        {win}
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>

            {/* Implementation Roadmap */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <Clock className="w-5 h-5 text-blue-500" />
                Implementation Roadmap
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                
                {/* Immediate */}
                <div className="bg-red-50 dark:bg-red-900/20 p-4 rounded-lg">
                  <h4 className="font-medium mb-3 text-red-600">Immediate (0-30 days)</h4>
                  <div className="space-y-2">
                    {result.implementationRoadmap.immediate.map((item, index) => (
                      <div key={index} className="text-xs p-2 bg-white dark:bg-gray-800 rounded">
                        {item}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Short Term */}
                <div className="bg-orange-50 dark:bg-orange-900/20 p-4 rounded-lg">
                  <h4 className="font-medium mb-3 text-orange-600">Short Term (1-3 months)</h4>
                  <div className="space-y-2">
                    {result.implementationRoadmap.shortTerm.map((item, index) => (
                      <div key={index} className="text-xs p-2 bg-white dark:bg-gray-800 rounded">
                        {item}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Medium Term */}
                <div className="bg-yellow-50 dark:bg-yellow-900/20 p-4 rounded-lg">
                  <h4 className="font-medium mb-3 text-yellow-600">Medium Term (3-12 months)</h4>
                  <div className="space-y-2">
                    {result.implementationRoadmap.mediumTerm.map((item, index) => (
                      <div key={index} className="text-xs p-2 bg-white dark:bg-gray-800 rounded">
                        {item}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Long Term */}
                <div className="bg-green-50 dark:bg-green-900/20 p-4 rounded-lg">
                  <h4 className="font-medium mb-3 text-green-600">Long Term (1-2 years)</h4>
                  <div className="space-y-2">
                    {result.implementationRoadmap.longTerm.map((item, index) => (
                      <div key={index} className="text-xs p-2 bg-white dark:bg-gray-800 rounded">
                        {item}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Security Metrics */}
            <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
              <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                <BarChart className="w-5 h-5 text-purple-500" />
                Recommended Security Metrics
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                
                {/* Technical Metrics */}
                <div>
                  <h4 className="font-medium mb-3 text-blue-600">Technical Metrics</h4>
                  <div className="space-y-2">
                    {result.securityMetrics.technical.map((metric, index) => (
                      <div key={index} className="text-sm p-2 bg-blue-50 dark:bg-blue-900/20 rounded">
                        {metric}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Operational Metrics */}
                <div>
                  <h4 className="font-medium mb-3 text-green-600">Operational Metrics</h4>
                  <div className="space-y-2">
                    {result.securityMetrics.operational.map((metric, index) => (
                      <div key={index} className="text-sm p-2 bg-green-50 dark:bg-green-900/20 rounded">
                        {metric}
                      </div>
                    ))}
                  </div>
                </div>

                {/* Strategic Metrics */}
                <div>
                  <h4 className="font-medium mb-3 text-purple-600">Strategic Metrics</h4>
                  <div className="space-y-2">
                    {result.securityMetrics.strategic.map((metric, index) => (
                      <div key={index} className="text-sm p-2 bg-purple-50 dark:bg-purple-900/20 rounded">
                        {metric}
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>

            {/* Knowledge Base References */}
            {(result.knowledgeBase.relevantFrameworks.length > 0 || 
              result.knowledgeBase.complianceDetails.length > 0 || 
              result.knowledgeBase.relevantThreats.length > 0) && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4">Knowledge Base References</h3>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  
                  {/* Relevant Frameworks */}
                  {result.knowledgeBase.relevantFrameworks.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-3 text-blue-600">Security Frameworks</h4>
                      <div className="space-y-2">
                        {result.knowledgeBase.relevantFrameworks.map((framework: any, index: number) => (
                          <div key={index} className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded">
                            <p className="font-bold text-sm">{framework.name}</p>
                            <p className="text-xs text-gray-600">{framework.details?.description}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Compliance Details */}
                  {result.knowledgeBase.complianceDetails.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-3 text-green-600">Compliance Standards</h4>
                      <div className="space-y-2">
                        {result.knowledgeBase.complianceDetails.map((compliance: any, index: number) => (
                          <div key={index} className="p-3 bg-green-50 dark:bg-green-900/20 rounded">
                            <p className="font-bold text-sm">{compliance.name}</p>
                            <p className="text-xs text-gray-600">{compliance.details?.scope}</p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Relevant Threats */}
                  {result.knowledgeBase.relevantThreats.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-3 text-red-600">Related Threats</h4>
                      <div className="space-y-2">
                        {result.knowledgeBase.relevantThreats.map((threat: any, index: number) => (
                          <div key={index} className="p-3 bg-red-50 dark:bg-red-900/20 rounded">
                            <p className="font-bold text-sm">{threat.name.replace('_', ' ')}</p>
                            <p className="text-xs text-gray-600">
                              Impact: {threat.details?.impact} | Prevalence: {threat.details?.prevalence}
                            </p>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Strategic Recommendations */}
            {result.recommendations.strategic.length > 0 && (
              <div className="bg-white dark:bg-gray-800 rounded-lg border p-6">
                <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
                  <Users className="w-5 h-5 text-indigo-500" />
                  Strategic Recommendations
                </h3>
                <div className="space-y-2">
                  {result.recommendations.strategic.map((recommendation, index) => (
                    <div key={index} className="flex items-start gap-2 p-3 bg-indigo-50 dark:bg-indigo-900/20 rounded">
                      <div className="w-6 h-6 bg-indigo-500 text-white rounded-full flex items-center justify-center text-sm font-bold mt-0.5">
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