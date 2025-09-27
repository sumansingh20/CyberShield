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

export default function HTTPHeadersPage() {
  const [result, setResult] = useState<ScanResult | null>(null)
  const { apiCall, loading } = useApi()
  const { isAuthenticated } = useAuth()

  const handleAnalyze = async (url: string) => {
    try {
      const response = await apiCall("/api/tools/http-headers", {
        method: "POST",
        body: { url },
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
          <h1 className="text-3xl font-bold text-white">HTTP Headers</h1>
        </div>

        {/* Tool Form */}
        <ToolForm
          title="HTTP Header Analysis"
          description="Analyze HTTP response headers to identify server information, security headers, and potential vulnerabilities."
          inputLabel="URL"
          inputPlaceholder="e.g., https://example.com"
          onSubmit={handleAnalyze}
          isLoading={loading}
          inputType="url"
        />

        {/* Terminal Output */}
        <TerminalOutput
          output={result?.output || ""}
          isLoading={loading}
          title="HTTP Headers"
          executionTime={result?.executionTime}
          status={result?.status}
        />
      </div>
    </div>
  )
}
