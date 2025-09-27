"use client"

import { useState } from "react"
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { ArrowLeft, Shield, Target, CheckCircle, Clock, AlertTriangle } from "lucide-react"
import Link from "next/link"
import { useApi } from "@/src/ui/hooks/useApi"

interface AssessmentResult {
  toolName: string
  status: "pending" | "running" | "completed" | "error"
  output?: string
  executionTime?: number
}

export default function SecurityAssessmentPage() {
  const [target, setTarget] = useState("")
  const [selectedTools, setSelectedTools] = useState<string[]>([
    "network-scan",
    "port-scanner", 
    "vuln-scanner",
    "subdomain-enum"
  ])
  const [isRunning, setIsRunning] = useState(false)
  const [results, setResults] = useState<Record<string, AssessmentResult>>({})
  const [progress, setProgress] = useState(0)
  const { apiCall } = useApi()

  const availableTools = [
    { id: "network-scan", name: "Network Discovery", description: "Scan for live hosts and services", endpoint: "/api/tools/network-scan" },
    { id: "port-scanner", name: "Port Scanner", description: "Identify open ports and services", endpoint: "/api/tools/port-scanner" },
    { id: "vuln-scanner", name: "Vulnerability Scanner", description: "Scan for known vulnerabilities", endpoint: "/api/tools/vuln-scanner" },
    { id: "subdomain-enum", name: "Subdomain Enumeration", description: "Discover subdomains", endpoint: "/api/tools/subdomain-enum" },
    { id: "whois", name: "WHOIS Lookup", description: "Domain registration information", endpoint: "/api/tools/whois" },
    { id: "dns-lookup", name: "DNS Analysis", description: "DNS records and configuration", endpoint: "/api/tools/dns-lookup" },
    { id: "http-headers", name: "HTTP Headers", description: "Web server security headers", endpoint: "/api/tools/http-headers" }
  ]

  const handleToolToggle = (toolId: string) => {
    setSelectedTools(prev => 
      prev.includes(toolId) 
        ? prev.filter(id => id !== toolId)
        : [...prev, toolId]
    )
  }

  const runAssessment = async () => {
    if (!target.trim() || selectedTools.length === 0) return

    setIsRunning(true)
    setProgress(0)
    
    // Initialize results
    const initialResults: Record<string, AssessmentResult> = {}
    selectedTools.forEach(toolId => {
      initialResults[toolId] = { toolName: toolId, status: "pending" }
    })
    setResults(initialResults)

    let completedTools = 0
    const totalTools = selectedTools.length

    // Run tools sequentially
    for (const toolId of selectedTools) {
      const tool = availableTools.find(t => t.id === toolId)
      if (!tool) continue

      // Update status to running
      setResults(prev => ({
        ...prev,
        [toolId]: { ...prev[toolId], status: "running" }
      }))

      try {
        let requestBody: any = {}
        
        // Prepare request body based on tool type
        switch (toolId) {
          case "network-scan":
          case "port-scanner":
          case "vuln-scanner":
          case "whois":
            requestBody = { target }
            break
          case "subdomain-enum":
            requestBody = { domain: target }
            break
          case "dns-lookup":
            requestBody = { domain: target }
            break
          case "http-headers":
            requestBody = { url: target.startsWith('http') ? target : `https://${target}` }
            break
        }

        const response = await apiCall(tool.endpoint, {
          method: "POST",
          body: requestBody,
        })

        if (response?.success) {
          setResults(prev => ({
            ...prev,
            [toolId]: {
              ...prev[toolId],
              status: "completed",
              output: response.result.output,
              executionTime: response.result.executionTime
            }
          }))
        } else {
          setResults(prev => ({
            ...prev,
            [toolId]: { ...prev[toolId], status: "error" }
          }))
        }
      } catch (error) {
        console.error(`Error running ${toolId}:`, error)
        setResults(prev => ({
          ...prev,
          [toolId]: { ...prev[toolId], status: "error" }
        }))
      }

      completedTools++
      setProgress((completedTools / totalTools) * 100)
      
      // Add small delay between tools
      await new Promise(resolve => setTimeout(resolve, 500))
    }

    setIsRunning(false)
  }

  const getStatusIcon = (status: AssessmentResult["status"]) => {
    switch (status) {
      case "completed":
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case "running":
        return <Clock className="h-4 w-4 text-blue-500 animate-spin" />
      case "error":
        return <AlertTriangle className="h-4 w-4 text-red-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-400" />
    }
  }

  const getStatusBadge = (status: AssessmentResult["status"]) => {
    switch (status) {
      case "completed":
        return <Badge className="bg-green-500/10 text-green-500">Completed</Badge>
      case "running":
        return <Badge className="bg-blue-500/10 text-blue-500">Running</Badge>
      case "error":
        return <Badge className="bg-red-500/10 text-red-500">Error</Badge>
      default:
        return <Badge variant="outline">Pending</Badge>
    }
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      <div className="flex items-center gap-4">
        <Link href="/dashboard">
          <Button variant="outline" size="sm">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Dashboard
          </Button>
        </Link>
        <div className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-primary" />
          <h1 className="text-3xl font-bold">Security Assessment</h1>
        </div>
      </div>

      <div className="grid gap-8 lg:grid-cols-2">
        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Target className="h-5 w-5" />
                Assessment Configuration
              </CardTitle>
              <CardDescription>
                Configure your comprehensive security assessment
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="target">Target (Domain/IP)</Label>
                <Input
                  id="target"
                  type="text"
                  placeholder="example.com or 192.168.1.1"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  disabled={isRunning}
                />
              </div>

                <div className="space-y-4">
                <Label>Select Assessment Tools</Label>
                <div className="grid gap-3">
                  {availableTools.map((tool) => (
                    <button
                      key={tool.id}
                      type="button"
                      className={`p-3 rounded-lg border transition-colors text-left ${
                        selectedTools.includes(tool.id) 
                          ? 'bg-primary/10 border-primary' 
                          : 'hover:bg-accent/50'
                      }`}
                      onClick={() => !isRunning && handleToolToggle(tool.id)}
                      disabled={isRunning}
                    >
                      <div className="flex items-center space-x-3">
                        <div className={`w-4 h-4 rounded border-2 flex items-center justify-center ${
                          selectedTools.includes(tool.id)
                            ? 'bg-primary border-primary'
                            : 'border-muted-foreground'
                        }`}>
                          {selectedTools.includes(tool.id) && (
                            <CheckCircle className="h-3 w-3 text-primary-foreground" />
                          )}
                        </div>
                        <div className="flex-1">
                          <div className="font-medium">{tool.name}</div>
                          <p className="text-sm text-muted-foreground mt-1">
                            {tool.description}
                          </p>
                        </div>
                      </div>
                    </button>
                  ))}
                </div>
              </div>              <Button 
                onClick={runAssessment} 
                disabled={isRunning || !target.trim() || selectedTools.length === 0}
                className="w-full"
              >
                {isRunning ? "Running Assessment..." : "Start Security Assessment"}
              </Button>

              {isRunning && (
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span>Progress</span>
                    <span>{Math.round(progress)}%</span>
                  </div>
                  <Progress value={progress} className="w-full" />
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        <div className="space-y-6">
          <Card>
            <CardHeader>
              <CardTitle>Assessment Results</CardTitle>
              <CardDescription>
                Real-time security assessment progress and findings
              </CardDescription>
            </CardHeader>
            <CardContent>
              {Object.keys(results).length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <Shield className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Configure and start your security assessment to see results here.</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {selectedTools.map((toolId) => {
                    const tool = availableTools.find(t => t.id === toolId)
                    const result = results[toolId]
                    if (!tool || !result) return null

                    return (
                      <div key={toolId} className="border rounded-lg p-4 space-y-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            {getStatusIcon(result.status)}
                            <div>
                              <h4 className="font-medium">{tool.name}</h4>
                              <p className="text-sm text-muted-foreground">{tool.description}</p>
                            </div>
                          </div>
                          {getStatusBadge(result.status)}
                        </div>
                        
                        {result.executionTime && (
                          <p className="text-xs text-muted-foreground">
                            Completed in {result.executionTime}ms
                          </p>
                        )}
                        
                        {result.output && (
                          <div className="bg-muted/50 rounded p-3 text-sm font-mono max-h-32 overflow-y-auto">
                            {result.output.split('\n').slice(0, 5).join('\n')}
                            {result.output.split('\n').length > 5 && '...'}
                          </div>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>About Security Assessment</CardTitle>
          <CardDescription>
            Comprehensive automated security testing workflow
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="font-semibold mb-2">Assessment Features:</h3>
            <div className="grid gap-2 md:grid-cols-2">
              <div className="text-sm">
                <div className="font-medium">Multi-Tool Scanning</div>
                <div className="text-muted-foreground">Run multiple security tools in sequence</div>
              </div>
              <div className="text-sm">
                <div className="font-medium">Real-time Progress</div>
                <div className="text-muted-foreground">Monitor assessment progress and results</div>
              </div>
              <div className="text-sm">
                <div className="font-medium">Customizable Scope</div>
                <div className="text-muted-foreground">Select specific tools for your assessment</div>
              </div>
              <div className="text-sm">
                <div className="font-medium">Comprehensive Coverage</div>
                <div className="text-muted-foreground">Network, web, and infrastructure analysis</div>
              </div>
            </div>
          </div>
          
          <div>
            <h3 className="font-semibold mb-2">Professional Use:</h3>
            <p className="text-sm text-muted-foreground">
              This automated security assessment tool is designed for authorized testing only. 
              Ensure you have proper permission before scanning any systems. Use responsibly 
              and in compliance with applicable laws and regulations.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
