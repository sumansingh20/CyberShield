"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { FileText, CheckCircle, AlertCircle, Loader2, Shield } from "lucide-react"
import { useApi } from "@/src/ui/hooks/useApi"
import { useToast } from "@/src/ui/hooks/use-toast"

export default function HttpHeadersPage() {
  const [url, setUrl] = useState("")
  const [results, setResults] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(false)
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleAnalyze = async () => {
    if (!url.trim()) {
      toast({
        title: "Error",
        description: "Please enter a URL to analyze",
        variant: "destructive"
      })
      return
    }

    setIsLoading(true)
    setResults(null)

    try {
      const response = await apiCall("/api/tools/http-headers", {
        method: "POST",
        body: { url: url.trim() },
        requiresAuth: false
      })

      if (response) {
        setResults(response)
        toast({
          title: "Success",
          description: "HTTP headers analyzed successfully"
        })
      }
    } catch (error) {
      toast({
        title: "Error", 
        description: "Failed to analyze HTTP headers",
        variant: "destructive"
      })
    } finally {
      setIsLoading(false)
    }
  }

  const getSecurityRating = (header: string, value: string) => {
    const securityHeaders = {
      'strict-transport-security': 'good',
      'content-security-policy': 'good', 
      'x-frame-options': 'good',
      'x-content-type-options': 'good',
      'x-xss-protection': 'good',
      'referrer-policy': 'good'
    }
    
    return securityHeaders[header.toLowerCase() as keyof typeof securityHeaders] || 'neutral'
  }

  const getRatingColor = (rating: string) => {
    switch (rating) {
      case 'good': return 'text-green-600 bg-green-100 dark:bg-green-900'
      case 'warning': return 'text-yellow-600 bg-yellow-100 dark:bg-yellow-900'
      case 'danger': return 'text-red-600 bg-red-100 dark:bg-red-900'
      default: return 'text-gray-600 bg-gray-100 dark:bg-gray-900'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <div className="container mx-auto max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <FileText className="h-12 w-12 text-blue-500 mr-4" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              HTTP Headers Analyzer
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-300 text-lg">
            Analyze HTTP security headers and configuration
          </p>
          <Badge className="mt-2" variant="outline">Beginner</Badge>
        </div>

        {/* Input Form */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center">
              <FileText className="h-5 w-5 mr-2" />
              URL Input
            </CardTitle>
            <CardDescription>
              Enter the URL to analyze HTTP headers
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <Label htmlFor="url">Target URL</Label>
                <Input
                  id="url"
                  placeholder="https://example.com"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  className="mt-1"
                />
              </div>
              <Button 
                onClick={handleAnalyze}
                disabled={isLoading}
                className="w-full"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <FileText className="h-4 w-4 mr-2" />
                    Analyze Headers
                  </>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        {results && (
          <>
            {/* Security Score */}
            <Card className="mb-6">
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Shield className="h-5 w-5 mr-2" />
                  Security Analysis
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <div className="text-center p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                    <div className="text-2xl font-bold text-blue-600">{results.securityScore || 'N/A'}</div>
                    <div className="text-sm text-gray-600 dark:text-gray-300">Security Score</div>
                  </div>
                  <div className="text-center p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                    <div className="text-2xl font-bold text-green-600">{results.securityHeaders || 0}</div>
                    <div className="text-sm text-gray-600 dark:text-gray-300">Security Headers</div>
                  </div>
                  <div className="text-center p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                    <div className="text-2xl font-bold text-gray-600">{results.totalHeaders || 0}</div>
                    <div className="text-sm text-gray-600 dark:text-gray-300">Total Headers</div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Headers List */}
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center">
                  <CheckCircle className="h-5 w-5 mr-2 text-green-500" />
                  HTTP Headers
                </CardTitle>
                <CardDescription>
                  Complete list of HTTP response headers
                </CardDescription>
              </CardHeader>
              <CardContent>
                {results.headers && Object.keys(results.headers).length > 0 ? (
                  <div className="space-y-3">
                    {Object.entries(results.headers).map(([header, value], index) => {
                      const rating = getSecurityRating(header, value as string)
                      return (
                        <div key={index} className="p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-semibold text-sm uppercase tracking-wide">
                              {header}
                            </span>
                            <Badge className={getRatingColor(rating)}>
                              {rating}
                            </Badge>
                          </div>
                          <code className="text-sm font-mono text-gray-700 dark:text-gray-300 block">
                            {value as string}
                          </code>
                        </div>
                      )
                    })}
                  </div>
                ) : (
                  <div className="text-center py-8 text-gray-500">
                    <AlertCircle className="h-8 w-8 mx-auto mb-2" />
                    <p>No headers found</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </>
        )}

        {/* Info */}
        <Card className="mt-8">
          <CardHeader>
            <CardTitle>About HTTP Headers</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="prose dark:prose-invert max-w-none">
              <p>
                HTTP headers provide important security information about web applications. 
                Analyzing these headers helps identify potential security vulnerabilities 
                and misconfigurations.
              </p>
              <h4>Important security headers:</h4>
              <ul>
                <li><strong>Strict-Transport-Security:</strong> Enforces HTTPS connections</li>
                <li><strong>Content-Security-Policy:</strong> Prevents XSS attacks</li>
                <li><strong>X-Frame-Options:</strong> Prevents clickjacking</li>
                <li><strong>X-Content-Type-Options:</strong> Prevents MIME type sniffing</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}