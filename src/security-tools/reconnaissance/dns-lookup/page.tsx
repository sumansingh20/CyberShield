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

export default function DNSLookupPage() {
  const [result, setResult] = useState<ScanResult | null>(null)
  const { apiCall, loading } = useApi()

  const handleLookup = async (domain: string) => {
    try {
      const response = await apiCall("/api/tools/dns", {
        method: "POST",
        body: { domain },
      })

      if (response && response.success) {
        setResult(response.result)
      }
    } catch (error) {
      // Error handled by useApi hook
    }
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
          <h1 className="text-3xl font-bold text-white">DNS Lookup</h1>
        </div>

        {/* Tool Form */}
        <ToolForm
          title="DNS Information"
          description="Retrieve DNS records and zone information for a domain using dig command."
          inputLabel="Domain"
          inputPlaceholder="e.g., example.com"
          onSubmit={handleLookup}
          isLoading={loading}
        />

        {/* Terminal Output */}
        <TerminalOutput
          output={result?.output || ""}
          isLoading={loading}
          title="DNS Lookup"
          executionTime={result?.executionTime}
          status={result?.status}
        />
      </div>
    </div>
  )
}
