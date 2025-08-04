"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Badge } from "@/components/ui/badge"
import { ArrowLeft, HardDrive, Search, FileText, Database } from "lucide-react"
import Link from "next/link"
import { TerminalOutput } from "@/components/TerminalOutput"
import { useApi } from "@/hooks/useApi"

interface ScanResult {
  output: string
  error?: string
  executionTime: number
  status: "success" | "error" | "timeout"
}

export default function ForensicsPage() {
  const [target, setTarget] = useState("")
  const [analysisType, setAnalysisType] = useState("file")
  const [result, setResult] = useState<ScanResult | null>(null)
  const { apiCall, loading } = useApi()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return

    try {
      const response = await apiCall("/api/tools/advanced/digital-forensics", {
        method: "POST",
        body: {
          target: target.trim(),
          analysisType,
        },
      })

      if (response?.success) {
        setResult(response.result)
      }
    } catch {
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
          <HardDrive className="h-6 w-6 text-primary" />
          <h1 className="text-3xl font-bold">Digital Forensics</h1>
        </div>
      </div>

      <div className="grid gap-8 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              Forensic Analysis
            </CardTitle>
            <CardDescription>
              Analyze digital evidence and artifacts
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="target">File Path or Evidence Target</Label>
                <Input
                  id="target"
                  type="text"
                  placeholder="/path/to/evidence or system.img"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  required
                />
              </div>

              <div className="space-y-3">
                <Label>Analysis Type</Label>
                <RadioGroup value={analysisType} onValueChange={setAnalysisType}>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="file" id="file" />
                    <Label htmlFor="file" className="flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      File Analysis
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="disk" id="disk" />
                    <Label htmlFor="disk" className="flex items-center gap-2">
                      <HardDrive className="h-4 w-4" />
                      Disk Image Analysis
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="metadata" id="metadata" />
                    <Label htmlFor="metadata" className="flex items-center gap-2">
                      <Database className="h-4 w-4" />
                      Metadata Extraction
                    </Label>
                  </div>
                  <div className="flex items-center space-x-2">
                    <RadioGroupItem value="recovery" id="recovery" />
                    <Label htmlFor="recovery" className="flex items-center gap-2">
                      <Search className="h-4 w-4" />
                      Data Recovery
                    </Label>
                  </div>
                </RadioGroup>
              </div>

              <Button type="submit" disabled={loading} className="w-full">
                {loading ? "Analyzing..." : "Run Forensic Analysis"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Output</CardTitle>
            <CardDescription>
              Digital forensics analysis results
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TerminalOutput 
              output={result?.output || ""}
              isLoading={loading}
              title="Forensic Analysis"
              executionTime={result?.executionTime}
              status={result?.status}
            />
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>About Digital Forensics</CardTitle>
          <CardDescription>
            Professional digital evidence analysis and investigation tools
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="font-semibold mb-2">Analysis Capabilities:</h3>
            <div className="flex flex-wrap gap-2">
              <Badge variant="secondary">File System Analysis</Badge>
              <Badge variant="secondary">Metadata Extraction</Badge>
              <Badge variant="secondary">Deleted File Recovery</Badge>
              <Badge variant="secondary">Timeline Analysis</Badge>
              <Badge variant="secondary">Hash Verification</Badge>
              <Badge variant="secondary">Evidence Preservation</Badge>
            </div>
          </div>
          
          <div>
            <h3 className="font-semibold mb-2">Supported Formats:</h3>
            <ul className="list-disc pl-6 space-y-1 text-sm text-muted-foreground">
              <li>Disk images (DD, E01, VMDK, VHD)</li>
              <li>File system analysis (NTFS, FAT32, EXT4, HFS+)</li>
              <li>Memory dumps and volatile data</li>
              <li>Network packet captures (PCAP)</li>
              <li>Mobile device extractions</li>
              <li>Registry and system artifacts</li>
            </ul>
          </div>

          <div>
            <h3 className="font-semibold mb-2">Legal and Ethical Use:</h3>
            <p className="text-sm text-muted-foreground">
              This tool is intended for authorized digital forensics investigations, incident response, 
              and educational purposes only. Always ensure proper legal authorization before analyzing 
              digital evidence. Maintain chain of custody and follow forensic best practices.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
