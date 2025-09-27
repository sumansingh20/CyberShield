"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Badge } from "@/src/ui/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Eye, Search, Globe, Mail, User, MapPin, Phone, Building, Camera, Clock } from "lucide-react"

interface OSINTResult {
  type: string
  source: string
  data: string
  confidence: number
  timestamp: string
}

export default function OSINTPage() {
  const [target, setTarget] = useState("")
  const [searchType, setSearchType] = useState("domain")
  const [isSearching, setIsSearching] = useState(false)
  const [results, setResults] = useState<OSINTResult[]>([])

  const handleSearch = async () => {
    if (!target) return

    setIsSearching(true)
    setResults([])

    try {
      // Simulate OSINT data gathering
      const mockResults: OSINTResult[] = [
        {
          type: "Email",
          source: "Hunter.io",
          data: `contact@${target}`,
          confidence: 85,
          timestamp: new Date().toLocaleString()
        },
        {
          type: "Social Media",
          source: "LinkedIn",
          data: `Company profile found for ${target}`,
          confidence: 92,
          timestamp: new Date().toLocaleString()
        },
        {
          type: "DNS",
          source: "DNS Records",
          data: `MX: mail.${target}, NS: ns1.${target}`,
          confidence: 100,
          timestamp: new Date().toLocaleString()
        },
        {
          type: "Subdomain",
          source: "Certificate Transparency",
          data: `www.${target}, api.${target}, mail.${target}`,
          confidence: 78,
          timestamp: new Date().toLocaleString()
        },
        {
          type: "Technology",
          source: "Wappalyzer",
          data: "Apache, PHP, MySQL, CloudFlare",
          confidence: 95,
          timestamp: new Date().toLocaleString()
        }
      ]

      // Simulate progressive loading
      for (const result of mockResults) {
        await new Promise(resolve => setTimeout(resolve, 800))
        setResults(prev => [...prev, result])
      }
    } catch (error) {
      console.error("OSINT search error:", error)
    } finally {
      setIsSearching(false)
    }
  }

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 90) return "text-green-600 bg-green-100"
    if (confidence >= 70) return "text-yellow-600 bg-yellow-100"
    return "text-red-600 bg-red-100"
  }

  const getTypeIcon = (type: string) => {
    switch (type.toLowerCase()) {
      case "email": return Mail
      case "social media": return User
      case "dns": return Globe
      case "subdomain": return Globe
      case "technology": return Building
      case "location": return MapPin
      case "phone": return Phone
      default: return Search
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 p-4">
      <div className="container mx-auto max-w-6xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-3">
            <div className="p-3 rounded-xl bg-gradient-to-br from-indigo-600 to-purple-600 text-white shadow-xl">
              <Eye className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-indigo-600 to-purple-600 bg-clip-text text-transparent">
                OSINT Toolkit
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Open Source Intelligence Gathering Platform
              </p>
            </div>
          </div>
          
          <div className="flex items-center justify-center space-x-4">
            <Badge className="bg-indigo-500/10 text-indigo-600 border-indigo-200 dark:border-indigo-800">
              <Eye className="w-3 h-3 mr-1" />
              OSINT
            </Badge>
            <Badge className="bg-purple-500/10 text-purple-600 border-purple-200 dark:border-purple-800">
              <Search className="w-3 h-3 mr-1" />
              Intelligence
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Search Panel */}
          <div className="lg:col-span-1">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Search className="h-5 w-5" />
                  Intelligence Search
                </CardTitle>
                <CardDescription>
                  Gather open source intelligence
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="target">Target</Label>
                  <Input
                    id="target"
                    placeholder="example.com or @username"
                    value={target}
                    onChange={(e) => setTarget(e.target.value)}
                    disabled={isSearching}
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="searchType">Search Type</Label>
                  <Select value={searchType} onValueChange={setSearchType} disabled={isSearching}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="domain">Domain/Website</SelectItem>
                      <SelectItem value="email">Email Address</SelectItem>
                      <SelectItem value="username">Username</SelectItem>
                      <SelectItem value="phone">Phone Number</SelectItem>
                      <SelectItem value="company">Company</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Button 
                  onClick={handleSearch} 
                  disabled={!target || isSearching}
                  className="w-full"
                >
                  {isSearching ? (
                    <>
                      <Clock className="mr-2 h-4 w-4 animate-spin" />
                      Gathering Intel...
                    </>
                  ) : (
                    <>
                      <Search className="mr-2 h-4 w-4" />
                      Start OSINT Search
                    </>
                  )}
                </Button>

                <div className="text-xs text-gray-500 space-y-2">
                  <p><strong>Sources:</strong></p>
                  <ul className="list-disc list-inside space-y-1">
                    <li>DNS & WHOIS Records</li>
                    <li>Certificate Transparency</li>
                    <li>Social Media Platforms</li>
                    <li>Search Engine Results</li>
                    <li>Public Databases</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-2">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Camera className="h-5 w-5" />
                  Intelligence Results
                </CardTitle>
                <CardDescription>
                  Open source intelligence findings
                </CardDescription>
              </CardHeader>
              <CardContent>
                {results.length > 0 ? (
                  <div className="space-y-4 max-h-96 overflow-y-auto">
                    {results.map((result, index) => {
                      const IconComponent = getTypeIcon(result.type)
                      return (
                        <div key={index} className="p-4 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                          <div className="flex items-start justify-between mb-2">
                            <div className="flex items-center space-x-2">
                              <IconComponent className="h-4 w-4 text-indigo-600" />
                              <span className="font-semibold">{result.type}</span>
                              <Badge variant="outline" className="text-xs">
                                {result.source}
                              </Badge>
                            </div>
                            <div className="flex items-center space-x-2">
                              <Badge className={`text-xs ${getConfidenceColor(result.confidence)}`}>
                                {result.confidence}% confidence
                              </Badge>
                            </div>
                          </div>
                          <div className="text-sm text-gray-700 dark:text-gray-300 mb-2">
                            {result.data}
                          </div>
                          <div className="text-xs text-gray-500 flex items-center">
                            <Clock className="h-3 w-3 mr-1" />
                            {result.timestamp}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="text-center py-12 text-gray-500">
                    <Eye className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No intelligence gathered yet.</p>
                    <p className="text-sm">Enter a target and start your OSINT search.</p>
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