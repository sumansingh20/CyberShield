"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Terminal, Folder, Globe, Search, AlertTriangle, CheckCircle, XCircle, Clock, Shield, Zap } from "lucide-react"

interface DirectoryResult {
  path: string
  status: number
  size: number
  found: boolean
}

export default function DirBusterPage() {
  const [target, setTarget] = useState("")
  const [wordlist, setWordlist] = useState("common.txt")
  const [threads, setThreads] = useState("10")
  const [extensions, setExtensions] = useState("php,html,txt,js")
  const [isScanning, setIsScanning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [results, setResults] = useState<DirectoryResult[]>([])
  const [logs, setLogs] = useState<string[]>([])

  const handleScan = async () => {
    if (!target) return

    setIsScanning(true)
    setProgress(0)
    setResults([])
    setLogs([])

    try {
      // Simulate directory busting process
      const testPaths = [
        "admin", "login", "dashboard", "api", "config", "backup", "uploads", 
        "images", "js", "css", "test", "dev", "tmp", "cache", "logs", "private"
      ]

      for (let i = 0; i < testPaths.length; i++) {
        const path = testPaths[i]
        const progress = ((i + 1) / testPaths.length) * 100
        setProgress(progress)

        // Simulate finding directories
        const found = Math.random() > 0.7
        const status = found ? (Math.random() > 0.5 ? 200 : 403) : 404
        const size = found ? Math.floor(Math.random() * 50000) : 0

        const result: DirectoryResult = {
          path: `/${path}`,
          status,
          size,
          found: status !== 404
        }

        setResults(prev => [...prev, result])
        setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Testing: ${target}/${path} - Status: ${status}`])

        await new Promise(resolve => setTimeout(resolve, 300))
      }

      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Directory enumeration completed`])
    } catch (error) {
      setLogs(prev => [...prev, `[${new Date().toLocaleTimeString()}] Error: ${error}`])
    } finally {
      setIsScanning(false)
    }
  }

  const foundDirectories = results.filter(r => r.found)
  const accessibleDirectories = foundDirectories.filter(r => r.status === 200)
  const forbiddenDirectories = foundDirectories.filter(r => r.status === 403)

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 p-4">
      <div className="container mx-auto max-w-6xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-3">
            <div className="p-3 rounded-xl bg-gradient-to-br from-orange-600 to-red-600 text-white shadow-xl">
              <Folder className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-orange-600 to-red-600 bg-clip-text text-transparent">
                Directory Buster
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Advanced directory and file enumeration tool
              </p>
            </div>
          </div>
          
          <div className="flex items-center justify-center space-x-4">
            <Badge className="bg-orange-500/10 text-orange-600 border-orange-200 dark:border-orange-800">
              <Terminal className="w-3 h-3 mr-1" />
              Advanced Tool
            </Badge>
            <Badge className="bg-blue-500/10 text-blue-600 border-blue-200 dark:border-blue-800">
              <Globe className="w-3 h-3 mr-1" />
              Web Security
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Configuration Panel */}
          <div className="lg:col-span-1 space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="h-5 w-5" />
                  Configuration
                </CardTitle>
                <CardDescription>
                  Configure directory enumeration settings
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="target">Target URL</Label>
                  <Input
                    id="target"
                    placeholder="https://example.com"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={isScanning}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="wordlist">Wordlist</Label>
                  <Select value={wordlist} onValueChange={setWordlist} disabled={isScanning}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="common.txt">Common (1000 entries)</SelectItem>
                      <SelectItem value="medium.txt">Medium (5000 entries)</SelectItem>
                      <SelectItem value="large.txt">Large (10000 entries)</SelectItem>
                      <SelectItem value="custom.txt">Custom Wordlist</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="extensions">File Extensions</Label>
                  <Input
                    id="extensions"
                    placeholder="php,html,txt,js"
                    value={extensions}
                    onChange={(e) => setExtensions(e.target.value)}
                    disabled={isScanning}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="threads">Threads</Label>
                  <Select value={threads} onValueChange={setThreads} disabled={isScanning}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="1">1 Thread</SelectItem>
                      <SelectItem value="5">5 Threads</SelectItem>
                      <SelectItem value="10">10 Threads</SelectItem>
                      <SelectItem value="20">20 Threads</SelectItem>
                      <SelectItem value="50">50 Threads</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Button 
                  onClick={handleScan} 
                  disabled={!target || isScanning}
                  className="w-full"
                >
                  {isScanning ? (
                    <>
                      <Clock className="mr-2 h-4 w-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Search className="mr-2 h-4 w-4" />
                      Start Directory Bust
                    </>
                  )}
                </Button>

                {isScanning && (
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

            {/* Statistics */}
            {results.length > 0 && (
              <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Statistics
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-3 rounded-lg bg-green-500/10">
                      <div className="text-2xl font-bold text-green-600">{accessibleDirectories.length}</div>
                      <div className="text-sm text-green-600">Accessible</div>
                    </div>
                    <div className="text-center p-3 rounded-lg bg-red-500/10">
                      <div className="text-2xl font-bold text-red-600">{forbiddenDirectories.length}</div>
                      <div className="text-sm text-red-600">Forbidden</div>
                    </div>
                  </div>
                  <div className="text-center p-3 rounded-lg bg-blue-500/10">
                    <div className="text-2xl font-bold text-blue-600">{results.length}</div>
                    <div className="text-sm text-blue-600">Total Tested</div>
                  </div>
                </CardContent>
              </Card>
            )}
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-2">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border h-fit">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Results
                </CardTitle>
                <CardDescription>
                  Directory enumeration results and logs
                </CardDescription>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="directories" className="w-full">
                  <TabsList className="grid w-full grid-cols-2">
                    <TabsTrigger value="directories">Found Directories</TabsTrigger>
                    <TabsTrigger value="logs">Scan Logs</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="directories" className="space-y-4">
                    {foundDirectories.length > 0 ? (
                      <div className="space-y-2 max-h-96 overflow-y-auto">
                        {foundDirectories.map((result, index) => (
                          <div key={index} className="flex items-center justify-between p-3 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                            <div className="flex items-center space-x-3">
                              {result.status === 200 ? (
                                <CheckCircle className="h-4 w-4 text-green-500" />
                              ) : (
                                <XCircle className="h-4 w-4 text-red-500" />
                              )}
                              <span className="font-mono text-sm">{target}{result.path}</span>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Badge variant={result.status === 200 ? "default" : "destructive"}>
                                {result.status}
                              </Badge>
                              {result.size > 0 && (
                                <span className="text-xs text-gray-500">
                                  {(result.size / 1024).toFixed(1)}KB
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-8 text-gray-500">
                        <Folder className="h-12 w-12 mx-auto mb-4 opacity-50" />
                        <p>No directories found yet. Start a scan to see results.</p>
                      </div>
                    )}
                  </TabsContent>
                  
                  <TabsContent value="logs" className="space-y-4">
                    <div className="bg-slate-900 text-green-400 p-4 rounded-lg font-mono text-sm max-h-96 overflow-y-auto">
                      {logs.length > 0 ? (
                        logs.map((log, index) => (
                          <div key={index} className="mb-1">
                            {log}
                          </div>
                        ))
                      ) : (
                        <div className="text-gray-500">
                          Scan logs will appear here...
                        </div>
                      )}
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}