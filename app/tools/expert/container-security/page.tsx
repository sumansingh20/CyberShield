"use client"

import { useState } from "react"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { RadioGroup, RadioGroupItem } from "@/components/ui/radio-group"
import { Badge } from "@/components/ui/badge"
import { ArrowLeft, Container, Shield, FileText, Settings, Globe } from "lucide-react"
import Link from "next/link"
import { TerminalOutput } from "@/components/TerminalOutput"
import { useApi } from "@/hooks/useApi"

interface ScanResult {
  output: string
  error?: string
  executionTime: number
  status: "success" | "error" | "timeout"
}

export default function ContainerSecurityPage() {
  const [target, setTarget] = useState("")
  const [scanType, setScanType] = useState("docker-image")
  const [result, setResult] = useState<ScanResult | null>(null)
  const { apiCall, loading } = useApi()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    if (!target.trim()) return

    try {
      const response = await apiCall("/api/tools/expert/container-security", {
        method: "POST",
        body: {
          target: target.trim(),
          scanType,
        },
      })

      if (response && response.success) {
        setResult(response.result)
      }
    } catch (error) {
      // Error handled by useApi hook
    }
  }

  const scanTypes = [
    {
      id: "docker-image",
      label: "Docker Image Scan",
      description: "Vulnerability scanning of Docker images",
      icon: Container,
      example: "nginx:latest"
    },
    {
      id: "docker-container",
      label: "Container Runtime Analysis",
      description: "Security analysis of running containers",
      icon: Settings,
      example: "my-app-container"
    },
    {
      id: "kubernetes-pod",
      label: "Kubernetes Pod Security",
      description: "Pod security standards and configuration review",
      icon: Shield,
      example: "my-app-pod"
    },
    {
      id: "kubernetes-cluster",
      label: "Cluster Security Audit",
      description: "Comprehensive cluster security assessment",
      icon: Globe,
      example: "production-cluster"
    },
    {
      id: "dockerfile",
      label: "Dockerfile Analysis",
      description: "Static analysis of Dockerfile security best practices",
      icon: FileText,
      example: "./Dockerfile"
    }
  ]

  const selectedScanType = scanTypes.find(type => type.id === scanType)

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
          <Container className="h-6 w-6 text-primary" />
          <h1 className="text-3xl font-bold">Container Security</h1>
        </div>
      </div>

      <div className="grid gap-8 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5" />
              Container Security Analysis
            </CardTitle>
            <CardDescription>
              Comprehensive security assessment for containers and Kubernetes
            </CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              <div className="space-y-2">
                <Label htmlFor="target">Target (Image/Container/Pod/Cluster/Dockerfile)</Label>
                <Input
                  id="target"
                  type="text"
                  placeholder={selectedScanType?.example || "Enter target..."}
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  required
                />
                <p className="text-sm text-muted-foreground">
                  {selectedScanType?.description}
                </p>
              </div>

              <div className="space-y-4">
                <Label>Security Scan Type</Label>
                <RadioGroup value={scanType} onValueChange={setScanType}>
                  {scanTypes.map((type) => {
                    const IconComponent = type.icon
                    return (
                      <div key={type.id} className="flex items-center space-x-3 p-3 rounded-lg border hover:bg-accent/50 transition-colors">
                        <RadioGroupItem value={type.id} id={type.id} />
                        <div className="flex items-center gap-3 flex-1">
                          <div className="p-2 rounded-md bg-primary/10">
                            <IconComponent className="h-4 w-4 text-primary" />
                          </div>
                          <div className="flex-1">
                            <Label htmlFor={type.id} className="cursor-pointer font-medium">
                              {type.label}
                            </Label>
                            <p className="text-sm text-muted-foreground mt-1">
                              {type.description}
                            </p>
                            <p className="text-xs text-muted-foreground mt-1">
                              Example: {type.example}
                            </p>
                          </div>
                        </div>
                      </div>
                    )
                  })}
                </RadioGroup>
              </div>

              <Button type="submit" disabled={loading} className="w-full">
                {loading ? "Analyzing..." : "Run Security Analysis"}
              </Button>
            </form>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Analysis Results</CardTitle>
            <CardDescription>
              Container security assessment findings and recommendations
            </CardDescription>
          </CardHeader>
          <CardContent>
            <TerminalOutput 
              output={result?.output || ""}
              isLoading={loading}
              title="Container Security Analysis"
              executionTime={result?.executionTime}
              status={result?.status}
            />
          </CardContent>
        </Card>
      </div>

      <div className="grid gap-6 md:grid-cols-2">
        <Card>
          <CardHeader>
            <CardTitle>Container Security Features</CardTitle>
            <CardDescription>
              Comprehensive security analysis capabilities
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h3 className="font-semibold mb-2">Docker Security:</h3>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary">Image Vulnerability Scanning</Badge>
                <Badge variant="secondary">Runtime Security Analysis</Badge>
                <Badge variant="secondary">Dockerfile Best Practices</Badge>
                <Badge variant="secondary">Secret Detection</Badge>
                <Badge variant="secondary">Base Image Analysis</Badge>
                <Badge variant="secondary">Layer Security Review</Badge>
              </div>
            </div>
            
            <div>
              <h3 className="font-semibold mb-2">Kubernetes Security:</h3>
              <div className="flex flex-wrap gap-2">
                <Badge variant="secondary">Pod Security Standards</Badge>
                <Badge variant="secondary">RBAC Analysis</Badge>
                <Badge variant="secondary">Network Policies</Badge>
                <Badge variant="secondary">Cluster Configuration</Badge>
                <Badge variant="secondary">Security Context Review</Badge>
                <Badge variant="secondary">Admission Controllers</Badge>
              </div>
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Security Compliance</CardTitle>
            <CardDescription>
              Industry standards and best practices coverage
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <h3 className="font-semibold mb-2">Compliance Frameworks:</h3>
              <ul className="list-disc pl-6 space-y-1 text-sm text-muted-foreground">
                <li>CIS Docker Benchmark</li>
                <li>CIS Kubernetes Benchmark</li>
                <li>NIST Container Security Guide</li>
                <li>OWASP Container Security</li>
                <li>Pod Security Standards (PSS)</li>
                <li>Docker Security Best Practices</li>
              </ul>
            </div>
            
            <div>
              <h3 className="font-semibold mb-2">Key Security Areas:</h3>
              <ul className="list-disc pl-6 space-y-1 text-sm text-muted-foreground">
                <li>Container image vulnerabilities and CVE detection</li>
                <li>Runtime security configuration analysis</li>
                <li>Network segmentation and policies</li>
                <li>Access control and RBAC configuration</li>
                <li>Secret management and exposure detection</li>
                <li>Resource limits and security contexts</li>
              </ul>
            </div>
          </CardContent>
        </Card>
      </div>

      <Card>
        <CardHeader>
          <CardTitle>About Container Security Analysis</CardTitle>
          <CardDescription>
            Professional container and Kubernetes security assessment
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div>
            <h3 className="font-semibold mb-2">Analysis Types:</h3>
            <div className="grid gap-3 md:grid-cols-2">
              <div className="p-3 rounded-lg bg-blue-50 dark:bg-blue-950/30 border border-blue-200 dark:border-blue-800">
                <h4 className="font-medium text-blue-900 dark:text-blue-100">Docker Image Security</h4>
                <p className="text-sm text-blue-700 dark:text-blue-300 mt-1">
                  Vulnerability scanning, base image analysis, and security best practices review
                </p>
              </div>
              <div className="p-3 rounded-lg bg-green-50 dark:bg-green-950/30 border border-green-200 dark:border-green-800">
                <h4 className="font-medium text-green-900 dark:text-green-100">Runtime Analysis</h4>
                <p className="text-sm text-green-700 dark:text-green-300 mt-1">
                  Container runtime security configuration and privilege analysis
                </p>
              </div>
              <div className="p-3 rounded-lg bg-purple-50 dark:bg-purple-950/30 border border-purple-200 dark:border-purple-800">
                <h4 className="font-medium text-purple-900 dark:text-purple-100">Kubernetes Security</h4>
                <p className="text-sm text-purple-700 dark:text-purple-300 mt-1">
                  Pod security standards, RBAC, and cluster configuration assessment
                </p>
              </div>
              <div className="p-3 rounded-lg bg-orange-50 dark:bg-orange-950/30 border border-orange-200 dark:border-orange-800">
                <h4 className="font-medium text-orange-900 dark:text-orange-100">Static Analysis</h4>
                <p className="text-sm text-orange-700 dark:text-orange-300 mt-1">
                  Dockerfile security review and build-time vulnerability detection
                </p>
              </div>
            </div>
          </div>

          <div>
            <h3 className="font-semibold mb-2">Security Assessment Areas:</h3>
            <div className="grid gap-2 md:grid-cols-3">
              <div className="text-sm">
                <div className="font-medium">Image Security</div>
                <div className="text-muted-foreground">CVE scanning, base images, layers</div>
              </div>
              <div className="text-sm">
                <div className="font-medium">Runtime Security</div>
                <div className="text-muted-foreground">Privileges, capabilities, contexts</div>
              </div>
              <div className="text-sm">
                <div className="font-medium">Network Security</div>
                <div className="text-muted-foreground">Policies, segmentation, exposure</div>
              </div>
              <div className="text-sm">
                <div className="font-medium">Access Control</div>
                <div className="text-muted-foreground">RBAC, service accounts, permissions</div>
              </div>
              <div className="text-sm">
                <div className="font-medium">Secrets Management</div>
                <div className="text-muted-foreground">Credential exposure, secret handling</div>
              </div>
              <div className="text-sm">
                <div className="font-medium">Compliance</div>
                <div className="text-muted-foreground">CIS benchmarks, industry standards</div>
              </div>
            </div>
          </div>

          <div>
            <h3 className="font-semibold mb-2">Professional Use:</h3>
            <p className="text-sm text-muted-foreground">
              This tool is designed for security professionals, DevSecOps engineers, and penetration testers 
              conducting authorized container and Kubernetes security assessments. Always ensure you have 
              proper authorization before scanning production systems. Use in compliance with your 
              organization's security policies and applicable laws.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
