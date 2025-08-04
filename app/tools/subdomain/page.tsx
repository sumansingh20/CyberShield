"use client"

import { useState } from "react"
import { useAuth } from "@/contexts/AuthContext"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { ArrowLeft, Search, Loader2 } from "lucide-react"
import Link from "next/link"
import { TerminalOutput } from "@/components/TerminalOutput"

export default function SubdomainPage() {
  const { user } = useAuth()
  const [domain, setDomain] = useState("")
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const handleScan = async () => {
    if (!domain.trim()) {
      alert("Please enter a domain")
      return
    }

    setLoading(true)
    setResult(null)

    try {
      const response = await fetch("/api/tools/subdomain", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
        body: JSON.stringify({
          domain: domain.trim(),
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || "Subdomain enumeration failed")
      }

      setResult(data.result)
    } catch (error: any) {
      setResult({
        output: `Error: ${error.message}`,
        status: "error",
        executionTime: 0,
      })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-4xl">
      <div className="mb-8">
        <Link href="/tools" className="inline-flex items-center text-sm text-muted-foreground hover:text-foreground mb-4">
          <ArrowLeft className="mr-2 h-4 w-4" />
          Back to Tools
        </Link>
        <div className="flex items-center gap-3 mb-4">
          <Search className="h-8 w-8 text-purple-500" />
          <div>
            <h1 className="text-3xl font-bold">Subdomain Discovery</h1>
            <p className="text-muted-foreground">Discover subdomains using multiple techniques</p>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Target Configuration</CardTitle>
            <CardDescription>
              Configure subdomain enumeration for your target domain
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="domain">Target Domain *</Label>
              <Input
                id="domain"
                placeholder="e.g., example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={loading}
                onKeyPress={(e) => e.key === "Enter" && handleScan()}
              />
              <p className="text-sm text-muted-foreground">
                Enter the domain to discover subdomains (without www or protocols)
              </p>
            </div>

            <Button 
              onClick={handleScan} 
              disabled={loading || !domain.trim()}
              className="w-full"
            >
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {loading ? "Enumerating..." : "Start Subdomain Discovery"}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Discovered Subdomains</CardTitle>
            <CardDescription>
              Found subdomains and their status
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TerminalOutput 
              output={result?.output || "No subdomains discovered yet. Enter a domain to start enumeration."}
              isLoading={loading}
              title={result?.executionTime ? `Subdomain Results (${result.executionTime}ms)` : "Subdomain Results"}
              executionTime={result?.executionTime}
              status={result?.status}
            />
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>About Subdomain Enumeration</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="prose prose-sm max-w-none dark:prose-invert">
            <p>
              Subdomain enumeration is the process of discovering subdomains for a given domain. 
              This is a crucial step in reconnaissance that helps identify attack surfaces and potential entry points.
            </p>
            <h4>Enumeration Techniques:</h4>
            <ul>
              <li><strong>DNS Bruteforcing</strong> - Testing common subdomain names</li>
              <li><strong>Certificate Transparency</strong> - Analyzing SSL certificates</li>
              <li><strong>Search Engine Queries</strong> - Using search operators</li>
              <li><strong>DNS Zone Transfers</strong> - Attempting zone transfer attacks</li>
            </ul>
            <h4>Common Tools Used:</h4>
            <ul>
              <li><strong>Sublist3r</strong> - Python-based subdomain enumeration</li>
              <li><strong>Assetfinder</strong> - Fast subdomain discovery</li>
              <li><strong>Amass</strong> - Advanced subdomain enumeration</li>
              <li><strong>Subfinder</strong> - Passive subdomain discovery</li>
            </ul>
            <h4>Security Applications:</h4>
            <ul>
              <li>Expanding attack surface during penetration testing</li>
              <li>Asset discovery and inventory management</li>
              <li>Identifying forgotten or misconfigured subdomains</li>
              <li>Finding development and staging environments</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
