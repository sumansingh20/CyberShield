"use client"

import React, { useState } from 'react'
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Alert, AlertDescription } from "@/src/ui/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { 
  FolderOpen, 
  File,
  Search,
  AlertTriangle, 
  Zap, 
  Eye,
  Terminal,
  FileSearch,
  ArrowLeft,
  Play,
  RefreshCw,
  CheckCircle,
  XCircle,
  Globe,
  Target,
  HardDrive,
  Clock
} from 'lucide-react'
import Link from 'next/link'

interface DirectoryBruteForceResult {
  targetUrl: string;
  directoriesFound: {
    path: string;
    status: number;
    size: number;
    lastModified?: string;
    contentType?: string;
  }[];
  filesFound: {
    path: string;
    status: number;
    size: number;
    extension: string;
    contentType?: string;
    lastModified?: string;
  }[];
  hiddenDirectories: string[];
  backupFiles: string[];
  configFiles: string[];
  interestingFindings: {
    path: string;
    reason: string;
    severity: 'High' | 'Medium' | 'Low';
    description: string;
  }[];
  wordlistUsed: string;
  totalRequests: number;
  successfulRequests: number;
  timeElapsed: string;
  statusCodes: { [key: string]: number };
  recommendations: string[];
  summary: string;
}

export default function DirectoryBruteForcePage() {
  const [targetUrl, setTargetUrl] = useState('')
  const [wordlist, setWordlist] = useState('common')
  const [customWordlist, setCustomWordlist] = useState('')
  const [fileExtensions, setFileExtensions] = useState('txt,php,html,js,css,xml,json')
  const [threads, setThreads] = useState('10')
  const [maxDepth, setMaxDepth] = useState('3')
  const [includeStatus, setIncludeStatus] = useState(['200', '301', '302', '403'])
  const [results, setResults] = useState<DirectoryBruteForceResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const handleScan = async () => {
    if (!targetUrl.trim()) {
      setError('Please enter a target URL')
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)
    setProgress(0)

    // Simulate progress
    const progressInterval = setInterval(() => {
      setProgress(prev => Math.min(prev + Math.random() * 5, 90))
    }, 1500)

    try {
      const response = await fetch('/api/tools/directory-bruteforce', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetUrl: targetUrl.trim(),
          wordlist,
          customWordlist: customWordlist.trim(),
          fileExtensions: fileExtensions.trim(),
          threads: parseInt(threads),
          maxDepth: parseInt(maxDepth),
          includeStatus,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to perform directory brute force')
      }

      const data = await response.json()
      setResults(data)
      setProgress(100)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      clearInterval(progressInterval)
      setLoading(false)
    }
  }

  const handleStatusToggle = (status: string) => {
    setIncludeStatus(prev => 
      prev.includes(status) 
        ? prev.filter(s => s !== status)
        : [...prev, status]
    )
  }

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'bg-green-500 text-white'
    if (status >= 300 && status < 400) return 'bg-blue-500 text-white'
    if (status >= 400 && status < 500) return 'bg-yellow-500 text-black'
    if (status >= 500) return 'bg-red-500 text-white'
    return 'bg-gray-500 text-white'
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'High': return 'bg-red-500 text-white'
      case 'Medium': return 'bg-yellow-500 text-black'
      case 'Low': return 'bg-blue-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 Bytes'
    const k = 1024
    const sizes = ['Bytes', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-yellow-900 to-slate-900 p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/tools" className="p-2 hover:bg-white/10 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-white" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Directory Brute Force</h1>
            <p className="text-gray-300">
              Advanced directory and file discovery with custom wordlists
            </p>
          </div>
        </div>

        {/* Configuration Form */}
        <Card className="mb-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <FolderOpen className="w-5 h-5" />
              Directory Brute Force Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure directory and file discovery parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="targetUrl" className="text-gray-200">Target URL</Label>
                <Input
                  id="targetUrl"
                  placeholder="https://example.com"
                  value={targetUrl}
                  onChange={(e) => setTargetUrl(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="wordlist" className="text-gray-200">Wordlist Type</Label>
                <Select value={wordlist} onValueChange={setWordlist}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="common">Common Directories</SelectItem>
                    <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
                    <SelectItem value="small">Small & Fast</SelectItem>
                    <SelectItem value="medium">Medium Coverage</SelectItem>
                    <SelectItem value="large">Large & Thorough</SelectItem>
                    <SelectItem value="admin">Admin Panels</SelectItem>
                    <SelectItem value="backup">Backup Files</SelectItem>
                    <SelectItem value="config">Configuration Files</SelectItem>
                    <SelectItem value="custom">Custom Wordlist</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {wordlist === 'custom' && (
              <div>
                <Label htmlFor="customWordlist" className="text-gray-200">Custom Wordlist</Label>
                <Textarea
                  id="customWordlist"
                  placeholder="admin&#10;backup&#10;config&#10;test&#10;dev&#10;uploads&#10;images&#10;css&#10;js"
                  value={customWordlist}
                  onChange={(e) => setCustomWordlist(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                  rows={6}
                />
              </div>
            )}

            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="fileExtensions" className="text-gray-200">File Extensions</Label>
                <Input
                  id="fileExtensions"
                  placeholder="txt,php,html,js,css,xml,json"
                  value={fileExtensions}
                  onChange={(e) => setFileExtensions(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="threads" className="text-gray-200">Threads</Label>
                <Select value={threads} onValueChange={setThreads}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="5">5 (Conservative)</SelectItem>
                    <SelectItem value="10">10 (Balanced)</SelectItem>
                    <SelectItem value="20">20 (Aggressive)</SelectItem>
                    <SelectItem value="50">50 (Very Aggressive)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="maxDepth" className="text-gray-200">Maximum Depth</Label>
              <Select value={maxDepth} onValueChange={setMaxDepth}>
                <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent className="bg-slate-700 border-slate-600">
                  <SelectItem value="1">1 Level</SelectItem>
                  <SelectItem value="2">2 Levels</SelectItem>
                  <SelectItem value="3">3 Levels</SelectItem>
                  <SelectItem value="5">5 Levels</SelectItem>
                  <SelectItem value="10">10 Levels (Deep)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label className="text-gray-200 mb-2 block">Include Status Codes</Label>
              <div className="grid grid-cols-4 md:grid-cols-8 gap-2">
                {['200', '201', '204', '301', '302', '307', '401', '403', '405', '500', '503'].map((status) => (
                  <div key={status} className="flex items-center space-x-1">
                    <input
                      type="checkbox"
                      id={`status-${status}`}
                      checked={includeStatus.includes(status)}
                      onChange={() => handleStatusToggle(status)}
                      className="rounded"
                      aria-label={`Include status ${status}`}
                    />
                    <Label 
                      htmlFor={`status-${status}`} 
                      className="text-gray-300 text-sm cursor-pointer"
                    >
                      {status}
                    </Label>
                  </div>
                ))}
              </div>
            </div>

            <Button 
              onClick={handleScan}
              disabled={loading}
              className="w-full bg-yellow-600 hover:bg-yellow-700"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Brute Forcing Directories...
                </>
              ) : (
                <>
                  <Search className="w-4 h-4 mr-2" />
                  Start Directory Brute Force
                </>
              )}
            </Button>

            {loading && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm text-gray-300">
                  <span>Scanning directories and files...</span>
                  <span>{Math.round(progress)}%</span>
                </div>
                <Progress value={progress} className="bg-slate-600" />
              </div>
            )}
          </CardContent>
        </Card>

        {/* Error Display */}
        {error && (
          <Alert className="mb-6 bg-red-900/50 border-red-500 text-red-200">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Results */}
        {results && (
          <div className="space-y-6">
            {/* Summary Card */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-white">
                  <Target className="w-5 h-5" />
                  Directory Brute Force Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">
                      {results.directoriesFound.length}
                    </div>
                    <div className="text-sm text-gray-300">Directories</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-green-400">
                      {results.filesFound.length}
                    </div>
                    <div className="text-sm text-gray-300">Files</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-orange-400">
                      {results.totalRequests}
                    </div>
                    <div className="text-sm text-gray-300">Total Requests</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-400">
                      {results.timeElapsed}
                    </div>
                    <div className="text-sm text-gray-300">Time Elapsed</div>
                  </div>
                </div>

                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-white mb-2">Scan Summary</h3>
                  <p className="text-gray-300">{results.summary}</p>
                </div>

                {/* Status Code Distribution */}
                <div className="bg-slate-700/30 rounded-lg p-4">
                  <h4 className="font-medium text-white mb-3">Status Code Distribution</h4>
                  <div className="flex flex-wrap gap-2">
                    {Object.entries(results.statusCodes).map(([code, count]) => (
                      <Badge key={code} className={getStatusColor(parseInt(code))}>
                        {code}: {count}
                      </Badge>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Discovery Results</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="directories" className="space-y-4">
                  <TabsList className="bg-slate-700">
                    <TabsTrigger value="directories">Directories</TabsTrigger>
                    <TabsTrigger value="files">Files</TabsTrigger>
                    <TabsTrigger value="findings">Interesting Findings</TabsTrigger>
                    <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                  </TabsList>

                  <TabsContent value="directories" className="space-y-4">
                    {results.directoriesFound.length > 0 ? (
                      <div className="space-y-2">
                        {results.directoriesFound.map((dir, index) => (
                          <div key={index} className="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg">
                            <div className="flex items-center gap-2">
                              <FolderOpen className="w-4 h-4 text-blue-400" />
                              <code className="text-blue-400">{dir.path}</code>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge className={getStatusColor(dir.status)}>
                                {dir.status}
                              </Badge>
                              <span className="text-gray-400 text-sm">
                                {formatFileSize(dir.size)}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-8 text-gray-400">
                        <FolderOpen className="w-12 h-12 mx-auto mb-4 text-gray-500" />
                        <p>No directories discovered</p>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="files" className="space-y-4">
                    {results.filesFound.length > 0 ? (
                      <div className="space-y-2">
                        {results.filesFound.map((file, index) => (
                          <div key={index} className="flex items-center justify-between p-3 bg-slate-700/30 rounded-lg">
                            <div className="flex items-center gap-2">
                              <File className="w-4 h-4 text-green-400" />
                              <code className="text-green-400">{file.path}</code>
                              <Badge variant="outline" className="text-purple-400 border-purple-400">
                                {file.extension}
                              </Badge>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge className={getStatusColor(file.status)}>
                                {file.status}
                              </Badge>
                              <span className="text-gray-400 text-sm">
                                {formatFileSize(file.size)}
                              </span>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <div className="text-center py-8 text-gray-400">
                        <File className="w-12 h-12 mx-auto mb-4 text-gray-500" />
                        <p>No files discovered</p>
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="findings" className="space-y-4">
                    {results.interestingFindings.length > 0 ? (
                      results.interestingFindings.map((finding, index) => (
                        <Card key={index} className="bg-slate-700/30">
                          <CardHeader className="pb-3">
                            <div className="flex items-center justify-between">
                              <CardTitle className="text-lg text-white">{finding.reason}</CardTitle>
                              <Badge className={getSeverityColor(finding.severity)}>
                                {finding.severity}
                              </Badge>
                            </div>
                          </CardHeader>
                          <CardContent className="space-y-2">
                            <div>
                              <span className="text-sm font-medium text-gray-200">Path:</span>
                              <code className="ml-2 text-yellow-400 bg-slate-800 px-2 py-1 rounded text-sm">
                                {finding.path}
                              </code>
                            </div>
                            <div>
                              <span className="text-sm font-medium text-gray-200">Description:</span>
                              <p className="text-gray-300 text-sm mt-1">{finding.description}</p>
                            </div>
                          </CardContent>
                        </Card>
                      ))
                    ) : (
                      <div className="text-center py-8 text-gray-400">
                        <Eye className="w-12 h-12 mx-auto mb-4 text-gray-500" />
                        <p>No interesting findings detected</p>
                      </div>
                    )}

                    {/* Special Categories */}
                    {(results.backupFiles.length > 0 || results.configFiles.length > 0 || results.hiddenDirectories.length > 0) && (
                      <div className="space-y-4 mt-6">
                        {results.backupFiles.length > 0 && (
                          <div>
                            <h4 className="font-medium mb-2 text-orange-400">⚠️ Backup Files:</h4>
                            <div className="space-y-1">
                              {results.backupFiles.map((file, index) => (
                                <div key={index} className="text-sm bg-orange-50 dark:bg-orange-900/20 p-2 rounded border-l-4 border-orange-400 font-mono text-orange-600 dark:text-orange-400">
                                  {file}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {results.configFiles.length > 0 && (
                          <div>
                            <h4 className="font-medium mb-2 text-red-400">🔥 Configuration Files:</h4>
                            <div className="space-y-1">
                              {results.configFiles.map((file, index) => (
                                <div key={index} className="text-sm bg-red-50 dark:bg-red-900/20 p-2 rounded border-l-4 border-red-400 font-mono text-red-600 dark:text-red-400">
                                  {file}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {results.hiddenDirectories.length > 0 && (
                          <div>
                            <h4 className="font-medium mb-2 text-purple-400">👁️ Hidden Directories:</h4>
                            <div className="space-y-1">
                              {results.hiddenDirectories.map((dir, index) => (
                                <div key={index} className="text-sm bg-purple-50 dark:bg-purple-900/20 p-2 rounded border-l-4 border-purple-400 font-mono text-purple-600 dark:text-purple-400">
                                  {dir}
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}
                  </TabsContent>

                  <TabsContent value="recommendations" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Security Recommendations</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="space-y-3">
                          {results.recommendations.map((rec, index) => (
                            <li key={index} className="flex items-start gap-2">
                              <HardDrive className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
                              <span className="text-gray-300">{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Educational Information */}
        <Card className="mt-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Terminal className="w-5 h-5" />
              About Directory Brute Force
            </CardTitle>
          </CardHeader>
          <CardContent className="text-gray-300 space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2 text-white">Common Targets:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• <strong>/admin:</strong> Administrative interfaces</li>
                  <li>• <strong>/backup:</strong> Backup files and archives</li>
                  <li>• <strong>/config:</strong> Configuration files</li>
                  <li>• <strong>/test:</strong> Test environments</li>
                  <li>• <strong>/uploads:</strong> Upload directories</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-white">Protection Methods:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Implement proper access controls</li>
                  <li>• Use .htaccess or web.config restrictions</li>
                  <li>• Hide sensitive directories</li>
                  <li>• Implement rate limiting</li>
                  <li>• Monitor for brute force attempts</li>
                </ul>
              </div>
            </div>

            <Alert className="bg-amber-900/20 border-amber-500/50 text-amber-200">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Ethical Use Only:</strong> Directory brute force should only be performed on systems you own 
                or have explicit written permission to test. Unauthorized scanning is illegal and unethical.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}