"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Badge } from "@/components/ui/badge"
import { ArrowLeft, Shield, Users, Mail, MessageSquare } from "lucide-react"
import Link from "next/link"
import { TerminalOutput } from "@/components/TerminalOutput"
import { useApi } from "@/hooks/useApi"

interface ScanResult {
  output: string
  error?: string
  executionTime: number
  status: "success" | "error" | "timeout"
}

export default function SocialEngineeringPage() {
  const [target, setTarget] = useState("")
  const [method, setMethod] = useState("phishing")
  const [result, setResult] = useState<ScanResult | null>(null)
  const { apiCall, loading } = useApi()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return

    try {
      const response = await apiCall("/api/tools/advanced/social-engineering", {
        method: "POST",
        body: {
          target: target.trim(),
          method,
        },
      })

      if (response && response.success) {
        setResult(response.result)
      }
    } catch (error) {
      // Error handled by useApi hook
    }
  }

  return (
    <div className="container mx-auto py-8 space-y-8">
      <div className="flex items-center gap-4">
        <Link href="/tools">
          <Button variant="outline" size="sm">
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back to Tools
          </Button>
        </Link>
        <div className="flex items-center gap-2">
          <Shield className="h-6 w-6 text-primary" />
          <h1 className="text-3xl font-bold">Social Engineering Toolkit</h1>
        </div>
      </div>

      <div className="grid gap-8 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5" />
              Social Engineering Analysis
            </CardTitle>
            <CardDescription>
              Analyze social engineering vectors and security awareness
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target">Target Organization or Domain</Label>
                <Input
                  id="target"
                  type="text"
                  placeholder="example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  required
                />
              </div>

              <div className="space-y-3">
                <Label>Social Engineering Method</Label>
                <RadioGroup value={method} onValueChange={setMethod}>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="phishing" id="phishing" />
                    <Label htmlFor="phishing" className="flex items-center gap-2">
                      <Mail className="h-4 w-4" />
                      Phishing Analysis
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="pretexting" id="pretexting" />
                    <Label htmlFor="pretexting" className="flex items-center gap-2">
                      <MessageSquare className="h-4 w-4" />
                      Pretexting Scenarios
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="osint" id="osint" />
                    <Label htmlFor="osint" className="flex items-center gap-2">
                      <Shield className="h-4 w-4" />
                      OSINT Gathering
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="awareness" id="awareness" />
                    <Label htmlFor="awareness" className="flex items-center gap-2">
                      <Users className="h-4 w-4" />
                      Security Awareness
                    </Label>
                  </div>
                </RadioGroup>
              </div>

              <Button type="submit" disabled={loading} className="w-full">
                {loading ? "Analyzing..." : "Run Social Engineering Analysis"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Output</CardTitle>
            <CardDescription>
              Social engineering analysis results and recommendations
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TerminalOutput 
              output={result?.output || ""}
              isLoading={loading}
              title="Social Engineering Analysis"
              executionTime={result?.executionTime}
              status={result?.status}
            />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>About Social Engineering Toolkit</CardTitle>
          <CardDescription>
            Professional social engineering testing and security awareness assessment
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="font-semibold mb-2">Analysis Methods:</h3>
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">Phishing Simulation</Badge>
              <Badge variant="secondary">Pretexting Assessment</Badge>
              <Badge variant="secondary">OSINT Collection</Badge>
              <Badge variant="secondary">Security Awareness</Badge>
              <Badge variant="secondary">Email Security</Badge>
              <Badge variant="secondary">Social Media Analysis</Badge>
            </div>
          </div>
          
          <div>
            <h3 className="font-semibold mb-2">Key Features:</h3>
            <ul className="list-disc pl-6 space-y-1 text-sm text-muted-foreground">
              <li>Comprehensive phishing campaign simulation</li>
              <li>Pretexting scenario development and testing</li>
              <li>Open source intelligence (OSINT) gathering</li>
              <li>Security awareness training assessment</li>
              <li>Social media footprint analysis</li>
              <li>Employee security posture evaluation</li>
            </ul>
          </div>

          <div>
            <h3 className="font-semibold mb-2">Educational Purpose:</h3>
            <p className="text-sm text-muted-foreground">
              This tool is designed for authorized security testing and educational purposes only. 
              Always ensure you have proper authorization before conducting social engineering assessments. 
              Use responsibly to improve organizational security awareness and defenses.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
