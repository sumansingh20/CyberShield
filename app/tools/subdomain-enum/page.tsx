"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Network, Search, AlertCircle, CheckCircle, Loader2 } from "lucide-react"
import { useApi } from "@/src/ui/hooks/useApi"
import { useToast } from "@/src/ui/hooks/use-toast"

export default function SubdomainEnumPage() {
  const [domain, setDomain] = useState("")
  const [results, setResults] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(false)
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleScan = async () => {
    if (!domain.trim()) {
      toast({
        title: "Error",
        description: "Please enter a domain to scan",
        variant: "destructive"
      })
      return
    }

    setIsLoading(true)
    setResults(null)

    try {
      const response = await apiCall("/api/tools/subdomain-enum", {
        method: "POST",
        body: { domain: domain.trim() },
        requiresAuth: false
      })

      if (response) {
        setResults(response)
        toast({
          title: "Success",
          description: `Found ${response.subdomains?.length || 0} subdomains`
        })
      }
    } catch (error) {
      toast({
        title: "Error", 
        description: "Failed to enumerate subdomains",
        variant: "destructive"
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <div className="container mx-auto max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Network className="h-12 w-12 text-blue-500 mr-4" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              Subdomain Enumeration
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-300 text-lg">
            Discover subdomains and map your attack surface
          </p>
          <Badge className="mt-2" variant="outline">Intermediate</Badge>
        </div>

        {/* Input Form */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center">
              <Search className="h-5 w-5 mr-2" />
              Domain Input
            </CardTitle>
            <CardDescription>
              Enter the target domain to enumerate subdomains
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <Label htmlFor="domain">Target Domain</Label>
                <Input
                  id="domain"
                  placeholder="example.com"
                  value={domain}
                  onChange={(e) => setDomain(e.target.value)}
                  className="mt-1"
                />
              </div>
              <Button 
                onClick={handleScan}
                disabled={isLoading}
                className="w-full"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Enumerating...
                  </>
                ) : (
                  <>
                    <Network className="h-4 w-4 mr-2" />
                    Start Enumeration
                  </>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        {results && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <CheckCircle className="h-5 w-5 mr-2 text-green-500" />
                Enumeration Results
              </CardTitle>
              <CardDescription>
                Found {results.subdomains?.length || 0} subdomains for {results.domain}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {results.subdomains && results.subdomains.length > 0 ? (
                <div className="space-y-2">
                  {results.subdomains.map((subdomain: string, index: number) => (
                    <div key={index} className="flex items-center p-3 bg-gray-50 dark:bg-gray-700 rounded-lg">
                      <div className="flex-1">
                        <code className="text-sm font-mono">{subdomain}</code>
                      </div>
                      <Badge variant="outline" className="ml-2">Active</Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <AlertCircle className="h-8 w-8 mx-auto mb-2" />
                  <p>No subdomains found for this domain</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Info */}
        <Card className="mt-8">
          <CardHeader>
            <CardTitle>About Subdomain Enumeration</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="prose dark:prose-invert max-w-none">
              <p>
                Subdomain enumeration is a reconnaissance technique used to discover subdomains 
                associated with a target domain. This helps map the attack surface and identify 
                potential entry points.
              </p>
              <h4>Common techniques include:</h4>
              <ul>
                <li>DNS brute forcing</li>
                <li>Certificate transparency logs</li>
                <li>Search engine reconnaissance</li>
                <li>Passive DNS analysis</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}