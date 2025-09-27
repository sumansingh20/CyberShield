"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Copy, Download, Terminal, CheckCircle, XCircle, Clock } from "lucide-react"
import { toast } from "@/src/ui/hooks/use-toast"

interface TerminalOutputProps {
  output: string
  isLoading: boolean
  title: string
  executionTime?: number
  status?: "success" | "error" | "timeout"
}

export function TerminalOutput({ output, isLoading, title, executionTime, status }: TerminalOutputProps) {
  const [displayedOutput, setDisplayedOutput] = useState("")
  const [currentIndex, setCurrentIndex] = useState(0)

  useEffect(() => {
    if (!isLoading && output) {
      setDisplayedOutput("")
      setCurrentIndex(0)

      const timer = setInterval(() => {
        setCurrentIndex((prevIndex) => {
          if (prevIndex < output.length) {
            setDisplayedOutput(output.slice(0, prevIndex + 1))
            return prevIndex + 1
          } else {
            clearInterval(timer)
            return prevIndex
          }
        })
      }, 10)

      return () => clearInterval(timer)
    }
  }, [output, isLoading])

  const copyToClipboard = async () => {
    try {
      await navigator.clipboard.writeText(output)
      toast({
        title: "Copied",
        description: "Output copied to clipboard",
      })
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to copy to clipboard",
        variant: "destructive",
      })
    }
  }

  const downloadAsText = () => {
    const blob = new Blob([output], { type: "text/plain" })
    const url = URL.createObjectURL(blob)
    const a = document.createElement("a")
    a.href = url
    a.download = `${title.toLowerCase().replace(/\s+/g, "-")}-${Date.now()}.txt`
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  const getStatusIcon = () => {
    switch (status) {
      case "success":
        return <CheckCircle className="h-4 w-4 text-success" />
      case "error":
        return <XCircle className="h-4 w-4 text-error" />
      case "timeout":
        return <Clock className="h-4 w-4 text-warning" />
      default:
        return <Terminal className="h-4 w-4 text-muted-foreground" />
    }
  }

  const getStatusColor = () => {
    switch (status) {
      case "success":
        return "status-success"
      case "error":
        return "status-error"
      case "timeout":
        return "status-warning"
      default:
        return "text-muted-foreground"
    }
  }

  return (
    <Card className="mt-6 glass-card animate-slide-up">
      <CardHeader className="flex flex-row items-center justify-between pb-3">
        <div className="flex items-center gap-3">
          {getStatusIcon()}
          <CardTitle className="text-lg">{title} Output</CardTitle>
        </div>
        <div className="flex items-center gap-2">
          {executionTime && (
            <div className="flex items-center gap-1 px-2 py-1 rounded-md bg-muted/50">
              <Clock className="h-3 w-3" />
              <span className={`text-xs font-mono ${getStatusColor()}`}>{executionTime}ms</span>
            </div>
          )}
          {output && (
            <>
              <Button
                variant="outline"
                size="sm"
                onClick={copyToClipboard}
                className="flex items-center gap-2 glass hover:glow-hover transition-all duration-200 bg-transparent"
              >
                <Copy className="h-4 w-4" />
                Copy
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={downloadAsText}
                className="flex items-center gap-2 glass hover:glow-hover transition-all duration-200 bg-transparent"
              >
                <Download className="h-4 w-4" />
                Download
              </Button>
            </>
          )}
        </div>
      </CardHeader>
      <CardContent>
        <div className="terminal rounded-lg p-4 min-h-[200px] font-mono text-sm border border-border/50 relative overflow-hidden">
          {/* Cyber grid background */}
          <div className="absolute inset-0 bg-cyber-grid opacity-20 pointer-events-none"></div>

          <div className="relative z-10">
            {isLoading ? (
              <div className="flex items-center space-x-3">
                <div className="spinner w-4 h-4"></div>
                <span className="text-primary animate-pulse">Executing command...</span>
                <div className="flex space-x-1">
                  <div className="w-1 h-1 bg-primary rounded-full animate-bounce"></div>
                  <div
                    className="w-1 h-1 bg-primary rounded-full animate-bounce"
                    style={{ animationDelay: "0.1s" }}
                  ></div>
                  <div
                    className="w-1 h-1 bg-primary rounded-full animate-bounce"
                    style={{ animationDelay: "0.2s" }}
                  ></div>
                </div>
              </div>
            ) : displayedOutput ? (
              <div className="space-y-1">
                <div className="flex items-center gap-2 text-xs text-muted-foreground mb-2 pb-2 border-b border-border/30">
                  <Terminal className="h-3 w-3" />
                  <span>unified-toolkit@security:~$</span>
                </div>
                <pre className="text-terminal-text whitespace-pre-wrap leading-relaxed">
                  {displayedOutput}
                  <span className="animate-pulse text-primary">█</span>
                </pre>
              </div>
            ) : (
              <div className="flex flex-col items-center justify-center h-32 text-muted-foreground">
                <Terminal className="h-8 w-8 mb-2 opacity-50" />
                <p className="text-sm italic">No output yet. Run a command to see results here.</p>
              </div>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  )
}
