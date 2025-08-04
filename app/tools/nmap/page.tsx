"use client"

import { useState } from "react"
import { useAuth } from "@/contexts/AuthContext"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Textarea } from "@/components/ui/textarea"
import { ArrowLeft, Target, Loader2 } from "lucide-react"
import Link from "next/link"
import { TerminalOutput } from "@/components/TerminalOutput"

export default function NmapPage() {
  const { user } = useAuth()
  const [target, setTarget] = useState("")
  const [ports, setPorts] = useState("")
  const [result, setResult] = useState<any>(null)
  const [loading, setLoading] = useState(false)

  const handleScan = async () => {
    if (!target.trim()) {
      alert("Please enter a target")
      return
    }

    setLoading(true)
    setResult(null)

    try {
      const response = await fetch("/api/tools/nmap", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${localStorage.getItem("token")}`,
        },
        body: JSON.stringify({
          target: target.trim(),
          ports: ports.trim() || undefined,
        }),
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || "Scan failed")
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
          <Target className="h-8 w-8 text-blue-500" />
          <div>
            <h1 className="text-3xl font-bold">Nmap Scanner</h1>
            <p className="text-muted-foreground">Network exploration and port scanning</p>
          </div>
        </div>
      </div>

      <div className="grid gap-6 lg:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Scan Configuration</CardTitle>
            <CardDescription>
              Configure your Nmap scan parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="target">Target (IP/Domain) *</Label>
              <Input
                id="target"
                placeholder="e.g., 192.168.1.1 or example.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                disabled={loading}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="ports">Ports (optional)</Label>
              <Input
                id="ports"
                placeholder="e.g., 80,443,22 or 1-1000"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
                disabled={loading}
              />
              <p className="text-sm text-muted-foreground">
                Leave empty for default port scan (-F flag)
              </p>
            </div>

            <Button 
              onClick={handleScan} 
              disabled={loading || !target.trim()}
              className="w-full"
            >
              {loading && <Loader2 className="mr-2 h-4 w-4 animate-spin" />}
              {loading ? "Scanning..." : "Start Nmap Scan"}
            </Button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scan Results</CardTitle>
            <CardDescription>
              Nmap scan output and discovered services
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TerminalOutput 
              output={result?.output || "No scan results yet. Configure and run a scan to see results here."}
              isLoading={loading}
              title={result?.executionTime ? `Nmap Scan Results (${result.executionTime}ms)` : "Nmap Scan Results"}
              executionTime={result?.executionTime}
              status={result?.status}
            />
          </CardContent>
        </Card>
      </div>

      <Card className="mt-6">
        <CardHeader>
          <CardTitle>About Nmap</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="prose prose-sm max-w-none dark:prose-invert">
            <p>
              Nmap (Network Mapper) is a free and open-source network discovery and security auditing tool. 
              It uses raw IP packets to determine what hosts are available on the network, what services 
              those hosts are offering, what operating systems they are running, and what type of firewalls are in use.
            </p>
            <h4>Common Use Cases:</h4>
            <ul>
              <li>Network inventory and asset discovery</li>
              <li>Managing service upgrade schedules</li>
              <li>Monitoring host or service uptime</li>
              <li>Security auditing and penetration testing</li>
            </ul>
            <h4>Example Commands:</h4>
            <ul>
              <li><code>nmap -F target</code> - Fast scan (most common ports)</li>
              <li><code>nmap -p 80,443 target</code> - Scan specific ports</li>
              <li><code>nmap -p 1-1000 target</code> - Scan port range</li>
            </ul>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
