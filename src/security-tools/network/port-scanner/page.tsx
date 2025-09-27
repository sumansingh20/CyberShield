"use client"

import { useState } from "react"
import { useAuth } from "@/src/auth/utils/AuthContext"
import { useApi } from "@/src/ui/hooks/useApi"
import { ThemeToggle } from "@/src/ui/components/ThemeToggle"
import { ToolForm } from "@/components/ToolForm"
import { TerminalOutput } from "@/components/TerminalOutput"
import { Button } from "@/src/ui/components/ui/button"
import { ArrowLeft, Shield, Activity } from "lucide-react"
import Link from "next/link"

interface ScanResult {
  output: string
  error?: string
  executionTime: number
  status: "success" | "error" | "timeout"
}

export default function PortScannerPage() {
  const [result, setResult] = useState<ScanResult | null>(null)
  const { apiCall, loading } = useApi()

  const handleScan = async (target: string) => {
    try {
      const response = await apiCall("/api/tools/nmap", {
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

  return (
    <div className="min-h-screen gradient-bg">
      {/* Header */}
      <header className="border-b border-border/50 glass backdrop-blur-xl sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Link href="/dashboard">
              <Button variant="outline" size="sm" className="glass hover:glow-hover bg-transparent">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Dashboard
              </Button>
            </Link>
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-blue-500/10">
                <Shield className="h-5 w-5 text-blue-500" />
              </div>
              <div>
                <h1 className="text-xl font-bold">Port Scanner</h1>
                <p className="text-xs text-muted-foreground">Nmap Integration</p>
              </div>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <div className="flex items-center gap-2 px-3 py-1 rounded-full bg-success/10 text-success text-sm">
              <Activity className="h-3 w-3" />
              <span>Ready</span>
            </div>
            <ThemeToggle />
          </div>
        </div>
      </header>

      <div className="container mx-auto max-w-4xl p-4">
        {/* Tool Form */}
        <div className="animate-slide-up">
          <ToolForm
            title="Nmap Port Scanner"
            description="Scan for open ports and services on target systems. Enter an IP address or domain name to discover running services and potential entry points."
            inputLabel="Target (IP/Domain)"
            inputPlaceholder="e.g., 192.168.1.1 or example.com"
            onSubmit={handleScan}
            isLoading={loading}
          />
        </div>

        {/* Terminal Output */}
        <TerminalOutput
          output={result?.output || ""}
          isLoading={loading}
          title="Nmap Scan"
          executionTime={result?.executionTime}
          status={result?.status}
        />
      </div>
    </div>
  )
}
