"use client"

import { useState } from "react"
import { useAuth } from "@/src/auth/utils/AuthContext"
import { useApi } from "@/src/ui/hooks/useApi"
import { ToolForm } from "@/components/ToolForm"
import { TerminalOutput } from "@/components/TerminalOutput"
import { Button } from "@/src/ui/components/ui/button"
import { ArrowLeft } from "lucide-react"
import Link from "next/link"

interface ScanResult {
  output: string
  error?: string
  executionTime: number
  status: "success" | "error" | "timeout"
}

export default function VulnScannerPage() {
  const [result, setResult] = useState<ScanResult | null>(null)
  const { apiCall, loading } = useApi()
  const { isAuthenticated } = useAuth()

  const handleScan = async (target: string) => {
    try {
      const response = await apiCall("/api/tools/vuln-scan", {
        method: "POST",
        body: { target },
      })

      if (response && response.success) {
        setResult(response.result)
      }
    } catch (error) {
      // Error handled by useApi hook
    }
  }

  if (!isAuthenticated) {
    return null
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-4">
      <div className="container mx-auto max-w-4xl">
        {/* Header */}
        <div className="mb-6 flex items-center space-x-4">
          <Link href="/dashboard">
            <Button variant="outline" size="sm">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Back to Dashboard
            </Button>
          </Link>
          <h1 className="text-3xl font-bold text-white">Vulnerability Scanner</h1>
        </div>

        {/* Tool Form */}
        <ToolForm
          title="Web Vulnerability Scanner"
          description="Scan web applications for vulnerabilities using Nikto and Nuclei. Enter a full URL including protocol."
          inputLabel="Target URL"
          inputPlaceholder="e.g., https://example.com"
          onSubmit={handleScan}
          isLoading={loading}
          inputType="url"
        />

        {/* Terminal Output */}
        <TerminalOutput
          output={result?.output || ""}
          isLoading={loading}
          title="Vulnerability Scan"
          executionTime={result?.executionTime}
          status={result?.status}
        />
      </div>
    </div>
  )
}
