"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Smartphone, Shield, AlertTriangle, FileText, Lock, Unlock, Upload, Clock, Zap } from "lucide-react"

interface SecurityFinding {
  severity: "Critical" | "High" | "Medium" | "Low" | "Info"
  category: string
  title: string
  description: string
  remediation: string
}

export default function MobileSecurityPage() {
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [progress, setProgress] = useState(0)
  const [findings, setFindings] = useState<SecurityFinding[]>([])
  const [appInfo, setAppInfo] = useState<any>(null)

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file && file.name.endsWith('.apk')) {
      setSelectedFile(file)
    } else {
      alert('Please select a valid APK file')
    }
  }

  const handleAnalysis = async () => {
    if (!selectedFile) return

    setIsAnalyzing(true)
    setProgress(0)
    setFindings([])
    setAppInfo(null)

    // Simulate analysis progress
    const stages = [
      "Extracting APK...",
      "Analyzing manifest...",
      "Scanning permissions...",
      "Checking security...",
      "Generating report..."
    ]

    for (let i = 0; i < stages.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 1000))
      setProgress(((i + 1) / stages.length) * 100)
    }

    // Mock analysis results
    setAppInfo({
      name: "Sample App",
      package: "com.example.sampleapp",
      version: "1.0.0",
      minSdk: 21,
      targetSdk: 30,
      permissions: [
        "android.permission.INTERNET",
        "android.permission.ACCESS_FINE_LOCATION",
        "android.permission.CAMERA",
        "android.permission.READ_CONTACTS"
      ]
    })

    const mockFindings: SecurityFinding[] = [
      {
        severity: "Critical",
        category: "Data Protection",
        title: "Sensitive Data in Logs",
        description: "Application logs contain sensitive user information including passwords and personal data.",
        remediation: "Remove sensitive data from log statements and implement proper logging practices."
      },
      {
        severity: "High",
        category: "Network Security",
        title: "Insecure HTTP Communication",
        description: "Application uses HTTP instead of HTTPS for sensitive data transmission.",
        remediation: "Implement HTTPS for all network communications and enable certificate pinning."
      },
      {
        severity: "Medium",
        category: "Permissions",
        title: "Excessive Permissions",
        description: "Application requests more permissions than necessary for its functionality.",
        remediation: "Review and remove unnecessary permissions from the manifest file."
      },
      {
        severity: "Low",
        category: "Code Quality",
        title: "Debug Information Exposed",
        description: "Debug information is present in the production build.",
        remediation: "Disable debug mode and remove debug symbols from production builds."
      }
    ]

    setFindings(mockFindings)
    setIsAnalyzing(false)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "Critical": return "text-red-700 bg-red-100 border-red-200"
      case "High": return "text-orange-700 bg-orange-100 border-orange-200"
      case "Medium": return "text-yellow-700 bg-yellow-100 border-yellow-200"
      case "Low": return "text-blue-700 bg-blue-100 border-blue-200"
      default: return "text-gray-700 bg-gray-100 border-gray-200"
    }
  }

  const getSeverityCount = (severity: string) => {
    return findings.filter(f => f.severity === severity).length
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 p-4">
      <div className="container mx-auto max-w-6xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-3">
            <div className="p-3 rounded-xl bg-gradient-to-br from-emerald-600 to-teal-600 text-white shadow-xl">
              <Smartphone className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-emerald-600 to-teal-600 bg-clip-text text-transparent">
                Mobile Security Analyzer
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Android APK security analysis with MobSF framework
              </p>
            </div>
          </div>
          
          <div className="flex items-center justify-center space-x-4">
            <Badge className="bg-emerald-500/10 text-emerald-600 border-emerald-200 dark:border-emerald-800">
              <Smartphone className="w-3 h-3 mr-1" />
              Advanced
            </Badge>
            <Badge className="bg-teal-500/10 text-teal-600 border-teal-200 dark:border-teal-800">
              <Shield className="w-3 h-3 mr-1" />
              Mobile Security
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Upload Panel */}
          <div className="lg:col-span-1">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Upload className="h-5 w-5" />
                  APK Analysis
                </CardTitle>
                <CardDescription>
                  Upload Android APK for security analysis
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="apk-file">Select APK File</Label>
                  <Input
                    id="apk-file"
                    type="file"
                    accept=".apk"
                    onChange={handleFileSelect}
                    disabled={isAnalyzing}
                  />
                  {selectedFile && (
                    <p className="text-sm text-green-600">
                      Selected: {selectedFile.name}
                    </p>
                  )}
                </div>

                <Button 
                  onClick={handleAnalysis} 
                  disabled={!selectedFile || isAnalyzing}
                  className="w-full"
                >
                  {isAnalyzing ? (
                    <>
                      <Clock className="mr-2 h-4 w-4 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Shield className="mr-2 h-4 w-4" />
                      Start Security Analysis
                    </>
                  )}
                </Button>

                {isAnalyzing && (
                  <div className="space-y-2">
                    <Progress value={progress} className="w-full" />
                    <p className="text-sm text-center">{Math.round(progress)}%</p>
                  </div>
                )}

                {findings.length > 0 && (
                  <div className="space-y-2">
                    <h3 className="font-semibold">Security Summary</h3>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div className="text-center p-2 bg-red-100 rounded">
                        <div className="font-bold text-red-700">{getSeverityCount("Critical")}</div>
                        <div className="text-red-600">Critical</div>
                      </div>
                      <div className="text-center p-2 bg-orange-100 rounded">
                        <div className="font-bold text-orange-700">{getSeverityCount("High")}</div>
                        <div className="text-orange-600">High</div>
                      </div>
                      <div className="text-center p-2 bg-yellow-100 rounded">
                        <div className="font-bold text-yellow-700">{getSeverityCount("Medium")}</div>
                        <div className="text-yellow-600">Medium</div>
                      </div>
                      <div className="text-center p-2 bg-blue-100 rounded">
                        <div className="font-bold text-blue-700">{getSeverityCount("Low")}</div>
                        <div className="text-blue-600">Low</div>
                      </div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-2">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Analysis Results
                </CardTitle>
                <CardDescription>
                  Security findings and app information
                </CardDescription>
              </CardHeader>
              <CardContent>
                {appInfo ? (
                  <Tabs defaultValue="findings" className="w-full">
                    <TabsList className="grid w-full grid-cols-2">
                      <TabsTrigger value="findings">Security Findings</TabsTrigger>
                      <TabsTrigger value="info">App Information</TabsTrigger>
                    </TabsList>
                    
                    <TabsContent value="findings" className="space-y-4">
                      <div className="space-y-4 max-h-96 overflow-y-auto">
                        {findings.map((finding, index) => (
                          <div key={index} className="p-4 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-center space-x-2">
                                <AlertTriangle className="h-4 w-4 text-red-500" />
                                <span className="font-semibold">{finding.title}</span>
                              </div>
                              <Badge className={getSeverityColor(finding.severity)}>
                                {finding.severity}
                              </Badge>
                            </div>
                            <div className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                              <strong>Category:</strong> {finding.category}
                            </div>
                            <div className="text-sm text-gray-700 dark:text-gray-300 mb-3">
                              {finding.description}
                            </div>
                            <div className="text-sm bg-blue-50 dark:bg-blue-900/20 p-2 rounded">
                              <strong className="text-blue-700 dark:text-blue-300">Remediation:</strong>
                              <p className="text-blue-600 dark:text-blue-400 mt-1">{finding.remediation}</p>
                            </div>
                          </div>
                        ))}
                      </div>
                    </TabsContent>
                    
                    <TabsContent value="info" className="space-y-4">
                      <div className="space-y-4">
                        <div className="grid grid-cols-2 gap-4 text-sm">
                          <div>
                            <span className="text-gray-500">App Name:</span>
                            <div className="font-semibold">{appInfo.name}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">Package:</span>
                            <div className="font-semibold font-mono text-xs">{appInfo.package}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">Version:</span>
                            <div className="font-semibold">{appInfo.version}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">Target SDK:</span>
                            <div className="font-semibold">{appInfo.targetSdk}</div>
                          </div>
                        </div>
                        
                        <div>
                          <h3 className="font-semibold mb-2">Permissions</h3>
                          <div className="space-y-1">
                            {appInfo.permissions.map((permission: string, index: number) => (
                              <div key={index} className="flex items-center space-x-2 text-sm">
                                {permission.includes("INTERNET") || permission.includes("LOCATION") ? 
                                  <Unlock className="h-3 w-3 text-orange-500" /> :
                                  <Lock className="h-3 w-3 text-green-500" />
                                }
                                <span className="font-mono text-xs">{permission}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      </div>
                    </TabsContent>
                  </Tabs>
                ) : (
                  <div className="text-center py-12 text-gray-500">
                    <Smartphone className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No analysis results yet.</p>
                    <p className="text-sm">Upload an APK file to start security analysis.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}