"use client"

import { useState } from "react"
import { useApi } from "@/src/ui/hooks/useApi"
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { ArrowLeft, Globe, Loader2 } from "lucide-react"
import Link from "next/link"
import { TerminalOutput } from "@/components/TerminalOutput"

export default function DNSPage() {
  const { apiCall, loading } = useApi()
  const [domain, setDomain] = useState("")
  const [result, setResult] = useState<any>(null)

  const handleLookup = async () => {
    if (!domain.trim()) {
      alert("Please enter a domain")
      return
    }

    setResult(null)

    try {
      const data = await apiCall("/api/tools/dns", {
        method: "POST",
        body: {
          domain: domain.trim(),
        },
      })

      if (data) {
        setResult(data.result)
      }
    } catch (error: any) {
      setResult({
        output: `Error: ${error.message}`,
        status: "error",
        executionTime: 0,
      })
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
          <Globe className="h-8 w-8 text-blue-500" />
          <div>
            <h1 className="text-3xl font-bold">DNS Resolver</h1>
            <p className="text-muted-foreground">Advanced DNS record lookup and analysis</p>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>DNS Query</CardTitle>
            <CardDescription>
              Perform comprehensive DNS record lookups
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="domain">Domain Name *</Label>
              <Input
                id="domain"
                placeholder="e.g., example.com"
                value={domain}
                onChange={(e) => setDomain(e.target.value)}
                disabled={loading}
                onKeyDown={(e) => e.key === "Enter" && handleLookup()}
              />
            </div>

            <Button 
              onClick={handleLookup} 
              disabled={loading || !domain.trim()}
              className="w-full"
            >
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {loading ? "Resolving..." : "Lookup DNS Records"}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>DNS Results</CardTitle>
            <CardDescription>
              Comprehensive DNS record information
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TerminalOutput 
              output={result?.output || "No DNS results yet. Enter a domain to see DNS records here."}
              isLoading={loading}
              title={result?.executionTime ? `DNS Results (${result.executionTime}ms)` : "DNS Results"}
              executionTime={result?.executionTime}
              status={result?.status}
            />
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>About DNS Resolution</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="prose prose-sm max-w-none dark:prose-invert">
            <p>
              The Domain Name System (DNS) is a hierarchical naming system that translates human-readable 
              domain names into IP addresses that computers use to identify each other on the network.
            </p>
            <h4>Record Types Retrieved:</h4>
            <ul>
              <li><strong>A Records</strong> - IPv4 addresses</li>
              <li><strong>AAAA Records</strong> - IPv6 addresses</li>
              <li><strong>MX Records</strong> - Mail exchange servers</li>
              <li><strong>NS Records</strong> - Name servers</li>
              <li><strong>TXT Records</strong> - Text records (SPF, DKIM, etc.)</li>
            </ul>
            <h4>Security Applications:</h4>
            <ul>
              <li>Reconnaissance and information gathering</li>
              <li>Identifying subdomains and infrastructure</li>
              <li>Analyzing DNS security configurations</li>
              <li>Detecting DNS spoofing or cache poisoning</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
