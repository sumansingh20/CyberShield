'use client'

import { useState } from 'react'
import { Button } from '@/src/ui/components/ui/button'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Label } from '@/src/ui/components/ui/label'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Search, Brain, BookOpen, FileText, Globe, Lightbulb, Download, Copy, ExternalLink } from 'lucide-react'
import { Badge } from '@/src/ui/components/ui/badge'
import { Progress } from '@/src/ui/components/ui/progress'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select'

interface ResearchResult {
  query: string
  summary: string
  keyFindings: string[]
  sources: {
    title: string
    url: string
    relevance: number
    type: string
    publishDate: string
    snippet: string
    credibilityScore: number
  }[]
  citations: {
    apa: string
    mla: string
    chicago: string
    ieee: string
  }[]
  relatedTopics: string[]
  expertInsights: string[]
  methodology: string
  confidence: number
  timestamp: string
}

interface CodingAssistResult {
  task: string
  solution: string
  explanation: string
  codeSnippets: {
    language: string
    code: string
    description: string
  }[]
  bestPractices: string[]
  alternativeApproaches: string[]
  testing: {
    testCases: string[]
    framework: string
    coverage: string
  }
  performance: {
    timeComplexity: string
    spaceComplexity: string
    optimizations: string[]
  }
  documentation: string
  timestamp: string
}

export default function AgenticAIPage() {
  const [selectedTab, setSelectedTab] = useState<'research' | 'coding' | 'workflow'>('research')
  const [researchQuery, setResearchQuery] = useState('')
  const [researchType, setResearchType] = useState('')
  const [codingTask, setCodingTask] = useState('')
  const [programmingLanguage, setProgrammingLanguage] = useState('')
  const [workflowDescription, setWorkflowDescription] = useState('')
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [researchResult, setResearchResult] = useState<ResearchResult | null>(null)
  const [codingResult, setCodingResult] = useState<CodingAssistResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [analysisProgress, setAnalysisProgress] = useState(0)

  const researchTypes = [
    { value: 'academic', label: 'Academic Research' },
    { value: 'market', label: 'Market Research' },
    { value: 'technical', label: 'Technical Research' },
    { value: 'scientific', label: 'Scientific Literature' },
    { value: 'news', label: 'News & Current Events' },
    { value: 'patents', label: 'Patents & IP' },
    { value: 'legal', label: 'Legal Research' },
    { value: 'medical', label: 'Medical Research' }
  ]

  const programmingLanguages = [
    { value: 'javascript', label: 'JavaScript' },
    { value: 'python', label: 'Python' },
    { value: 'typescript', label: 'TypeScript' },
    { value: 'java', label: 'Java' },
    { value: 'csharp', label: 'C#' },
    { value: 'cpp', label: 'C++' },
    { value: 'rust', label: 'Rust' },
    { value: 'go', label: 'Go' },
    { value: 'swift', label: 'Swift' },
    { value: 'kotlin', label: 'Kotlin' }
  ]

  const simulateProgress = (type: string) => {
    let intervals: { delay: number; progress: number; message: string }[]
    
    if (type === 'research') {
      intervals = [
        { delay: 500, progress: 15, message: 'Analyzing research query...' },
        { delay: 1000, progress: 30, message: 'Searching academic databases...' },
        { delay: 1500, progress: 45, message: 'Retrieving relevant sources...' },
        { delay: 2000, progress: 60, message: 'Analyzing source credibility...' },
        { delay: 2500, progress: 75, message: 'Generating citations...' },
        { delay: 3000, progress: 90, message: 'Synthesizing findings...' },
        { delay: 3500, progress: 100, message: 'Research complete!' }
      ]
    } else if (type === 'coding') {
      intervals = [
        { delay: 500, progress: 15, message: 'Understanding coding requirements...' },
        { delay: 1000, progress: 30, message: 'Generating solution architecture...' },
        { delay: 1500, progress: 45, message: 'Writing optimized code...' },
        { delay: 2000, progress: 60, message: 'Creating test cases...' },
        { delay: 2500, progress: 75, message: 'Analyzing performance...' },
        { delay: 3000, progress: 90, message: 'Generating documentation...' },
        { delay: 3500, progress: 100, message: 'Code solution ready!' }
      ]
    } else {
      intervals = [
        { delay: 500, progress: 20, message: 'Analyzing workflow requirements...' },
        { delay: 1000, progress: 40, message: 'Identifying automation opportunities...' },
        { delay: 1500, progress: 60, message: 'Designing process flow...' },
        { delay: 2000, progress: 80, message: 'Generating implementation plan...' },
        { delay: 2500, progress: 100, message: 'Workflow optimization complete!' }
      ]
    }

    intervals.forEach(({ delay, progress }) => {
      setTimeout(() => setAnalysisProgress(progress), delay)
    })
  }

  const performResearch = async () => {
    if (!researchQuery || !researchType) {
      setError('Please enter a research query and select research type')
      return
    }

    setIsAnalyzing(true)
    setError(null)
    setResearchResult(null)
    setAnalysisProgress(0)

    simulateProgress('research')

    try {
      const response = await fetch('/api/tools/ai-research-assistant', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          type: 'research',
          query: researchQuery,
          researchType: researchType
        })
      })

      if (!response.ok) {
        throw new Error(`Research failed: ${response.statusText}`)
      }

      const result = await response.json()
      setResearchResult(result)

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Research failed')
    } finally {
      setIsAnalyzing(false)
      setAnalysisProgress(0)
    }
  }

  const performCodingAssist = async () => {
    if (!codingTask || !programmingLanguage) {
      setError('Please describe the coding task and select programming language')
      return
    }

    setIsAnalyzing(true)
    setError(null)
    setCodingResult(null)
    setAnalysisProgress(0)

    simulateProgress('coding')

    try {
      const response = await fetch('/api/tools/ai-coding-copilot', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          type: 'coding',
          task: codingTask,
          language: programmingLanguage
        })
      })

      if (!response.ok) {
        throw new Error(`Coding assistance failed: ${response.statusText}`)
      }

      const result = await response.json()
      setCodingResult(result)

    } catch (err) {
      setError(err instanceof Error ? err.message : 'Coding assistance failed')
    } finally {
      setIsAnalyzing(false)
      setAnalysisProgress(0)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const downloadAsFile = (content: string, filename: string) => {
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  return (
    <div className="container mx-auto p-6 space-y-6">
      <div className="flex items-center gap-2 mb-6">
        <Brain className="h-6 w-6 text-purple-600" />
        <h1 className="text-3xl font-bold">Agentic AI Assistant</h1>
      </div>

      <Alert className="border-purple-200 bg-purple-50">
        <Lightbulb className="h-4 w-4 text-purple-600" />
        <AlertDescription className="text-purple-800">
          <strong>Autonomous AI Agent:</strong> This AI can reason, plan, and act independently to help with research, 
          coding, and workflow automation. It provides comprehensive analysis with citations and actionable insights.
        </AlertDescription>
      </Alert>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              AI Agent Tasks
            </CardTitle>
            <CardDescription>
              Choose your task type and let the AI agent work autonomously
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <Tabs value={selectedTab} onValueChange={(value) => setSelectedTab(value as any)}>
              <TabsList className="grid w-full grid-cols-3">
                <TabsTrigger value="research" className="flex items-center gap-2">
                  <BookOpen className="h-4 w-4" />
                  Research
                </TabsTrigger>
                <TabsTrigger value="coding" className="flex items-center gap-2">
                  <FileText className="h-4 w-4" />
                  Coding
                </TabsTrigger>
                <TabsTrigger value="workflow" className="flex items-center gap-2">
                  <Globe className="h-4 w-4" />
                  Workflow
                </TabsTrigger>
              </TabsList>
              
              <TabsContent value="research" className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="research-type">Research Type</Label>
                  <Select value={researchType} onValueChange={setResearchType}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select research type" />
                    </SelectTrigger>
                    <SelectContent>
                      {researchTypes.map((type) => (
                        <SelectItem key={type.value} value={type.value}>
                          {type.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="research-query">Research Query</Label>
                  <textarea
                    id="research-query"
                    value={researchQuery}
                    onChange={(e) => setResearchQuery(e.target.value)}
                    placeholder="Enter your research question or topic... (e.g., 'Latest advancements in quantum computing for cryptography')"
                    className="w-full h-32 p-3 border rounded-lg resize-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  />
                </div>

                <Button 
                  onClick={performResearch} 
                  disabled={isAnalyzing || !researchQuery || !researchType}
                  className="w-full bg-purple-600 hover:bg-purple-700"
                >
                  {isAnalyzing ? 'Researching...' : 'Start AI Research'}
                </Button>
              </TabsContent>

              <TabsContent value="coding" className="space-y-4">
                <div className="space-y-2">
                  <Label htmlfor="programming-language">Programming Language</Label>
                  <Select value={programmingLanguage} onValueChange={setProgrammingLanguage}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select programming language" />
                    </SelectTrigger>
                    <SelectContent>
                      {programmingLanguages.map((lang) => (
                        <SelectItem key={lang.value} value={lang.value}>
                          {lang.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="coding-task">Coding Task</Label>
                  <textarea
                    id="coding-task"
                    value={codingTask}
                    onChange={(e) => setCodingTask(e.target.value)}
                    placeholder="Describe your coding task... (e.g., 'Create a REST API with authentication and rate limiting')"
                    className="w-full h-32 p-3 border rounded-lg resize-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  />
                </div>

                <Button 
                  onClick={performCodingAssist} 
                  disabled={isAnalyzing || !codingTask || !programmingLanguage}
                  className="w-full bg-purple-600 hover:bg-purple-700"
                >
                  {isAnalyzing ? 'Generating Code...' : 'Start AI Coding'}
                </Button>
              </TabsContent>

              <TabsContent value="workflow" className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="workflow-description">Workflow Description</Label>
                  <textarea
                    id="workflow-description"
                    value={workflowDescription}
                    onChange={(e) => setWorkflowDescription(e.target.value)}
                    placeholder="Describe the workflow you want to automate... (e.g., 'Automate daily report generation from multiple data sources')"
                    className="w-full h-32 p-3 border rounded-lg resize-none focus:ring-2 focus:ring-purple-500 focus:border-transparent"
                  />
                </div>

                <Button 
                  disabled={isAnalyzing || !workflowDescription}
                  className="w-full bg-purple-600 hover:bg-purple-700"
                >
                  {isAnalyzing ? 'Analyzing Workflow...' : 'Optimize Workflow'}
                </Button>
              </TabsContent>
            </Tabs>

            {error && (
              <Alert className="border-red-200 bg-red-50">
                <AlertDescription className="text-red-800">
                  {error}
                </AlertDescription>
              </Alert>
            )}

            {isAnalyzing && (
              <div className="space-y-2">
                <div className="flex items-center justify-between text-sm">
                  <span>AI Agent working...</span>
                  <span>{analysisProgress}%</span>
                </div>
                <Progress value={analysisProgress} className="w-full" />
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Brain className="h-5 w-5" />
              AI Agent Results
            </CardTitle>
            <CardDescription>
              Autonomous AI analysis and recommendations
            </CardDescription>
          </CardHeader>
          <CardContent>
            {!researchResult && !codingResult && (
              <div className="text-center py-8 text-gray-500">
                <Brain className="h-16 w-16 mx-auto mb-4 opacity-50" />
                <p>Start an AI agent task to see autonomous results</p>
              </div>
            )}

            {researchResult && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <Badge className="px-3 py-1 bg-purple-100 text-purple-800">
                    Research Complete
                  </Badge>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => copyToClipboard(researchResult.summary)}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                    <Button
                      size="sm" 
                      variant="outline"
                      onClick={() => downloadAsFile(
                        `Research Summary: ${researchResult.query}\n\n${researchResult.summary}\n\nKey Findings:\n${researchResult.keyFindings.join('\n')}\n\nSources:\n${researchResult.sources.map(s => s.title + ' - ' + s.url).join('\n')}`,
                        'research-report.txt'
                      )}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold text-sm mb-2">Research Summary</h4>
                  <p className="text-sm text-gray-700 bg-gray-50 p-3 rounded-lg">
                    {researchResult.summary}
                  </p>
                </div>

                <div>
                  <h4 className="font-semibold text-sm mb-2">Key Findings</h4>
                  <ul className="space-y-1">
                    {researchResult.keyFindings.map((finding, index) => (
                      <li key={index} className="text-sm flex items-start gap-2">
                        <Lightbulb className="h-3 w-3 mt-1 text-purple-600 flex-shrink-0" />
                        {finding}
                      </li>
                    ))}
                  </ul>
                </div>

                <div>
                  <h4 className="font-semibold text-sm mb-2">Sources ({researchResult.sources.length})</h4>
                  <div className="space-y-2 max-h-48 overflow-y-auto">
                    {researchResult.sources.slice(0, 5).map((source, index) => (
                      <div key={index} className="p-2 border rounded-lg text-xs">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-medium truncate">{source.title}</span>
                          <div className="flex items-center gap-1">
                            <Badge variant="outline" className="text-xs">
                              {source.credibilityScore}% credible
                            </Badge>
                            <ExternalLink className="h-3 w-3 text-gray-400" />
                          </div>
                        </div>
                        <p className="text-gray-600 line-clamp-2">{source.snippet}</p>
                        <div className="flex items-center justify-between mt-1">
                          <span className="text-gray-500">{source.type}</span>
                          <span className="text-gray-500">{source.publishDate}</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold text-sm mb-2">Citations</h4>
                  <div className="space-y-2">
                    {researchResult.citations.slice(0, 3).map((citation, index) => (
                      <div key={index} className="text-xs">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge variant="outline">APA</Badge>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => copyToClipboard(citation.apa)}
                            className="h-4 p-1"
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                        <p className="text-gray-700 bg-gray-50 p-2 rounded text-xs">
                          {citation.apa}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold text-sm mb-2">Related Topics</h4>
                  <div className="flex flex-wrap gap-1">
                    {researchResult.relatedTopics.map((topic, index) => (
                      <Badge key={index} variant="outline" className="text-xs">
                        {topic}
                      </Badge>
                    ))}
                  </div>
                </div>
              </div>
            )}

            {codingResult && (
              <div className="space-y-6">
                <div className="flex items-center justify-between">
                  <Badge className="px-3 py-1 bg-green-100 text-green-800">
                    Code Solution Ready
                  </Badge>
                  <div className="flex gap-2">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => copyToClipboard(codingResult.solution)}
                    >
                      <Copy className="h-4 w-4" />
                    </Button>
                    <Button
                      size="sm"
                      variant="outline" 
                      onClick={() => downloadAsFile(
                        `Task: ${codingResult.task}\n\nSolution:\n${codingResult.solution}\n\nExplanation:\n${codingResult.explanation}\n\nCode Snippets:\n${codingResult.codeSnippets.map(c => `${c.language}:\n${c.code}`).join('\n\n')}`,
                        'code-solution.txt'
                      )}
                    >
                      <Download className="h-4 w-4" />
                    </Button>
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold text-sm mb-2">Solution Overview</h4>
                  <p className="text-sm text-gray-700 bg-gray-50 p-3 rounded-lg">
                    {codingResult.solution}
                  </p>
                </div>

                <div>
                  <h4 className="font-semibold text-sm mb-2">Code Implementation</h4>
                  <div className="space-y-3">
                    {codingResult.codeSnippets.slice(0, 2).map((snippet, index) => (
                      <div key={index} className="border rounded-lg">
                        <div className="flex items-center justify-between p-2 bg-gray-50 border-b">
                          <Badge variant="outline">{snippet.language}</Badge>
                          <Button
                            size="sm"
                            variant="ghost"
                            onClick={() => copyToClipboard(snippet.code)}
                            className="h-6 p-1"
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                        <pre className="p-3 text-xs overflow-x-auto bg-gray-900 text-green-400 rounded-b-lg">
                          <code>{snippet.code}</code>
                        </pre>
                        <p className="p-2 text-xs text-gray-600 border-t bg-gray-50">
                          {snippet.description}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>

                <div>
                  <h4 className="font-semibold text-sm mb-2">Best Practices</h4>
                  <ul className="space-y-1">
                    {codingResult.bestPractices.slice(0, 4).map((practice, index) => (
                      <li key={index} className="text-sm flex items-start gap-2">
                        <Lightbulb className="h-3 w-3 mt-1 text-green-600 flex-shrink-0" />
                        {practice}
                      </li>
                    ))}
                  </ul>
                </div>

                <div className="grid grid-cols-2 gap-4 text-xs">
                  <div>
                    <h5 className="font-medium mb-1">Performance</h5>
                    <div className="space-y-1 text-gray-600">
                      <div>Time: {codingResult.performance.timeComplexity}</div>
                      <div>Space: {codingResult.performance.spaceComplexity}</div>
                    </div>
                  </div>
                  <div>
                    <h5 className="font-medium mb-1">Testing</h5>
                    <div className="space-y-1 text-gray-600">
                      <div>Framework: {codingResult.testing.framework}</div>
                      <div>Coverage: {codingResult.testing.coverage}</div>
                    </div>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
