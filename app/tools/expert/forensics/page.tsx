"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { FileSearch, HardDrive, Image, Clock, Hash, Eye, Upload, Zap, AlertTriangle } from "lucide-react"

interface ForensicEvidence {
  type: "file" | "registry" | "network" | "memory"
  name: string
  hash: string
  timestamp: string
  size: string
  location: string
  suspicious: boolean
}

interface HashResult {
  algorithm: string
  hash: string
  verified: boolean
}

interface TimelineEvent {
  timestamp: string
  event: string
  source: string
  details: string
  severity: "High" | "Medium" | "Low"
}

export default function ForensicsPage() {
  const [selectedImage, setSelectedImage] = useState<File | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [progress, setProgress] = useState(0)
  const [evidence, setEvidence] = useState<ForensicEvidence[]>([])
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [hashResults, setHashResults] = useState<HashResult[]>([])
  const [searchQuery, setSearchQuery] = useState("")
  const [activeTab, setActiveTab] = useState("analysis")

  const handleImageSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]
    if (file) {
      setSelectedImage(file)
    }
  }

  const handleAnalysis = async () => {
    if (!selectedImage) return

    setIsAnalyzing(true)
    setProgress(0)
    setEvidence([])
    setTimeline([])
    setHashResults([])

    // Simulate forensic analysis stages
    const stages = [
      "Mounting disk image...",
      "Scanning file system...",
      "Extracting metadata...",
      "Analyzing artifacts...",
      "Building timeline...",
      "Generating report..."
    ]

    for (let i = 0; i < stages.length; i++) {
      await new Promise(resolve => setTimeout(resolve, 1500))
      setProgress(((i + 1) / stages.length) * 100)
    }

    // Mock forensic results
    const mockEvidence: ForensicEvidence[] = [
      {
        type: "file",
        name: "suspicious_payload.exe",
        hash: "a4b2c5d7e8f9a1b2c3d4e5f6a7b8c9d0",
        timestamp: "2024-01-15 14:23:17",
        size: "2.3 MB",
        location: "C:\\Windows\\Temp\\",
        suspicious: true
      },
      {
        type: "registry",
        name: "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
        hash: "b5c6d8e9f0a2b3c4d5e6f7a8b9c0d1e2",
        timestamp: "2024-01-15 14:25:33",
        size: "1.2 KB",
        location: "Registry Hive",
        suspicious: true
      },
      {
        type: "network",
        name: "Outbound Connection",
        hash: "c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2",
        timestamp: "2024-01-15 14:30:45",
        size: "N/A",
        location: "192.168.1.100:4444",
        suspicious: true
      },
      {
        type: "file",
        name: "system_backup.zip",
        hash: "d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3",
        timestamp: "2024-01-14 09:15:22",
        size: "45.7 MB",
        location: "C:\\Users\\Admin\\Documents\\",
        suspicious: false
      }
    ]

    const mockTimeline: TimelineEvent[] = [
      {
        timestamp: "2024-01-15 14:20:00",
        event: "USB Device Connected",
        source: "System Event Log",
        details: "Unknown USB device connected to system",
        severity: "Medium"
      },
      {
        timestamp: "2024-01-15 14:23:17",
        event: "Malicious File Created",
        source: "File System",
        details: "suspicious_payload.exe created in Windows Temp directory",
        severity: "High"
      },
      {
        timestamp: "2024-01-15 14:25:33",
        event: "Registry Modification",
        source: "Registry",
        details: "Persistence mechanism added to startup registry",
        severity: "High"
      },
      {
        timestamp: "2024-01-15 14:30:45",
        event: "Network Connection",
        source: "Network Log",
        details: "Outbound connection to suspicious IP address",
        severity: "High"
      }
    ]

    const mockHashes: HashResult[] = [
      { algorithm: "MD5", hash: "5d41402abc4b2a76b9719d911017c592", verified: true },
      { algorithm: "SHA1", hash: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", verified: true },
      { algorithm: "SHA256", hash: "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae", verified: false }
    ]

    setEvidence(mockEvidence)
    setTimeline(mockTimeline)
    setHashResults(mockHashes)
    setIsAnalyzing(false)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case "High": return "text-red-700 bg-red-100 border-red-200"
      case "Medium": return "text-yellow-700 bg-yellow-100 border-yellow-200"
      case "Low": return "text-blue-700 bg-blue-100 border-blue-200"
      default: return "text-gray-700 bg-gray-100 border-gray-200"
    }
  }

  const getEvidenceIcon = (type: string) => {
    switch (type) {
      case "file": return <FileSearch className="h-4 w-4" />
      case "registry": return <HardDrive className="h-4 w-4" />
      case "network": return <Zap className="h-4 w-4" />
      case "memory": return <Image className="h-4 w-4" />
      default: return <FileSearch className="h-4 w-4" />
    }
  }

  const filteredEvidence = evidence.filter(item =>
    item.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
    item.location.toLowerCase().includes(searchQuery.toLowerCase())
  )

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-purple-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 p-4">
      <div className="container mx-auto max-w-7xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-3">
            <div className="p-3 rounded-xl bg-gradient-to-br from-purple-600 to-indigo-600 text-white shadow-xl">
              <FileSearch className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-purple-600 to-indigo-600 bg-clip-text text-transparent">
                Digital Forensics Suite
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Professional digital evidence analysis and investigation platform
              </p>
            </div>
          </div>
          
          <div className="flex items-center justify-center space-x-4">
            <Badge className="bg-purple-500/10 text-purple-600 border-purple-200 dark:border-purple-800">
              <Eye className="w-3 h-3 mr-1" />
              Expert Level
            </Badge>
            <Badge className="bg-indigo-500/10 text-indigo-600 border-indigo-200 dark:border-indigo-800">
              <FileSearch className="w-3 h-3 mr-1" />
              Digital Forensics
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Analysis Control Panel */}
          <div className="lg:col-span-1">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Upload className="h-5 w-5" />
                  Forensic Analysis
                </CardTitle>
                <CardDescription>
                  Upload disk image for analysis
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="disk-image">Disk Image File</Label>
                  <Input
                    id="disk-image"
                    type="file"
                    accept=".img,.dd,.raw,.e01,.ex01"
                    onChange={handleImageSelect}
                    disabled={isAnalyzing}
                  />
                  {selectedImage && (
                    <p className="text-sm text-green-600">
                      Selected: {selectedImage.name}
                    </p>
                  )}
                </div>

                <Button 
                  onClick={handleAnalysis} 
                  disabled={!selectedImage || isAnalyzing}
                  className="w-full"
                >
                  {isAnalyzing ? (
                    <>
                      <Clock className="mr-2 h-4 w-4 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <FileSearch className="mr-2 h-4 w-4" />
                      Start Forensic Analysis
                    </>
                  )}
                </Button>

                {isAnalyzing && (
                  <div className="space-y-2">
                    <Progress value={progress} className="w-full" />
                    <p className="text-sm text-center">{Math.round(progress)}%</p>
                  </div>
                )}

                {evidence.length > 0 && (
                  <div className="space-y-2">
                    <h3 className="font-semibold">Analysis Summary</h3>
                    <div className="grid grid-cols-2 gap-2 text-sm">
                      <div className="text-center p-2 bg-red-100 rounded">
                        <div className="font-bold text-red-700">
                          {evidence.filter(e => e.suspicious).length}
                        </div>
                        <div className="text-red-600">Suspicious</div>
                      </div>
                      <div className="text-center p-2 bg-green-100 rounded">
                        <div className="font-bold text-green-700">
                          {evidence.filter(e => !e.suspicious).length}
                        </div>
                        <div className="text-green-600">Clean</div>
                      </div>
                    </div>
                  </div>
                )}

                <div className="space-y-2">
                  <Label htmlFor="search">Search Evidence</Label>
                  <Input
                    id="search"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    placeholder="Search files, paths..."
                    disabled={isAnalyzing || evidence.length === 0}
                  />
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-2">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Forensic Results
                </CardTitle>
                <CardDescription>
                  Digital evidence and analysis findings
                </CardDescription>
              </CardHeader>
              <CardContent>
                {evidence.length > 0 ? (
                  <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
                    <TabsList className="grid w-full grid-cols-3">
                      <TabsTrigger value="analysis">Evidence</TabsTrigger>
                      <TabsTrigger value="timeline">Timeline</TabsTrigger>
                      <TabsTrigger value="hashes">Hash Analysis</TabsTrigger>
                    </TabsList>
                    
                    <TabsContent value="analysis" className="space-y-4">
                      <div className="space-y-3 max-h-96 overflow-y-auto">
                        {filteredEvidence.map((item, index) => (
                          <div 
                            key={index} 
                            className={`p-4 rounded-lg border ${
                              item.suspicious 
                                ? 'bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800' 
                                : 'bg-green-50 border-green-200 dark:bg-green-900/20 dark:border-green-800'
                            }`}
                          >
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-center space-x-2">
                                {getEvidenceIcon(item.type)}
                                <span className="font-semibold">{item.name}</span>
                              </div>
                              <div className="flex space-x-2">
                                <Badge variant="outline" className="text-xs">
                                  {item.type}
                                </Badge>
                                {item.suspicious && (
                                  <Badge className="bg-red-100 text-red-700 border-red-200">
                                    <AlertTriangle className="w-3 h-3 mr-1" />
                                    Suspicious
                                  </Badge>
                                )}
                              </div>
                            </div>
                            <div className="grid grid-cols-2 gap-4 text-sm text-gray-600 dark:text-gray-400">
                              <div>
                                <strong>Location:</strong> {item.location}
                              </div>
                              <div>
                                <strong>Size:</strong> {item.size}
                              </div>
                              <div>
                                <strong>Timestamp:</strong> {item.timestamp}
                              </div>
                              <div>
                                <strong>Hash:</strong> 
                                <span className="font-mono text-xs ml-1">{item.hash}</span>
                              </div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </TabsContent>
                    
                    <TabsContent value="timeline" className="space-y-4">
                      <div className="space-y-3 max-h-96 overflow-y-auto">
                        {timeline.map((event, index) => (
                          <div key={index} className="p-4 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                            <div className="flex items-start justify-between mb-2">
                              <div className="flex items-center space-x-2">
                                <Clock className="h-4 w-4 text-blue-500" />
                                <span className="font-semibold">{event.event}</span>
                              </div>
                              <Badge className={getSeverityColor(event.severity)}>
                                {event.severity}
                              </Badge>
                            </div>
                            <div className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                              <strong>Time:</strong> {event.timestamp} | <strong>Source:</strong> {event.source}
                            </div>
                            <div className="text-sm text-gray-700 dark:text-gray-300">
                              {event.details}
                            </div>
                          </div>
                        ))}
                      </div>
                    </TabsContent>
                    
                    <TabsContent value="hashes" className="space-y-4">
                      <div className="space-y-3">
                        {hashResults.map((hash, index) => (
                          <div key={index} className="p-4 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-2">
                                <Hash className="h-4 w-4" />
                                <span className="font-semibold">{hash.algorithm}</span>
                              </div>
                              <Badge className={hash.verified ? "bg-green-100 text-green-700" : "bg-red-100 text-red-700"}>
                                {hash.verified ? "Verified" : "Unknown"}
                              </Badge>
                            </div>
                            <div className="mt-2 font-mono text-xs bg-gray-100 dark:bg-gray-800 p-2 rounded">
                              {hash.hash}
                            </div>
                          </div>
                        ))}
                      </div>
                    </TabsContent>
                  </Tabs>
                ) : (
                  <div className="text-center py-12 text-gray-500">
                    <FileSearch className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No forensic analysis results yet.</p>
                    <p className="text-sm">Upload a disk image to start digital forensic analysis.</p>
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