"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Badge } from "@/src/ui/components/ui/badge"
import { AlertTriangle, Mail, MessageSquare, Phone, Copy, Download, ArrowLeft, Users, Eye, Shield } from "lucide-react"
import Link from "next/link"

interface SETemplate {
  id: string
  type: string
  category: string
  name: string
  description: string
  subject?: string
  content: string
  target_info: string[]
  effectiveness_score: number
  difficulty: string
  detection_risk: string
  customizable_fields: string[]
  preview_html?: string
}

interface SECampaign {
  template: SETemplate
  customizations: Record<string, string>
  target_count: number
  estimated_success_rate: number
  risk_assessment: {
    legal_risk: string
    detection_risk: string
    ethical_concerns: string[]
  }
  generated_content: string
  delivery_methods: string[]
  tracking_options: string[]
}

interface SEResult {
  campaign: SECampaign
  templates: SETemplate[]
  total_templates: number
  generation_time: number
  timestamp: string
}

export default function SocialEngineeringPage() {
  const [templateType, setTemplateType] = useState("phishing_email")
  const [category, setCategory] = useState("credential_harvesting")
  const [targetCompany, setTargetCompany] = useState("")
  const [targetName, setTargetName] = useState("")
  const [targetEmail, setTargetEmail] = useState("")
  const [customSubject, setCustomSubject] = useState("")
  const [customMessage, setCustomMessage] = useState("")
  const [result, setResult] = useState<SEResult | null>(null)
  const [isLoading, setIsLoading] = useState(false)
  const [error, setError] = useState("")
  const [selectedTemplate, setSelectedTemplate] = useState<SETemplate | null>(null)

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setIsLoading(true)
    setError("")
    setResult(null)
    setSelectedTemplate(null)

    try {
      const response = await fetch("/api/tools/social-engineering", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          template_type: templateType,
          category,
          target_company: targetCompany || null,
          target_name: targetName || null,
          target_email: targetEmail || null,
          custom_subject: customSubject || null,
          custom_message: customMessage || null
        })
      })

      const data = await response.json()
      
      if (!response.ok) {
        throw new Error(data.error || "Template generation failed")
      }

      setResult(data)
      if (data.templates.length > 0) {
        setSelectedTemplate(data.templates[0])
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : "An error occurred")
    } finally {
      setIsLoading(false)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const downloadTemplate = (template: SETemplate) => {
    const element = document.createElement("a")
    const file = new Blob([template.content], { type: "text/html" })
    element.href = URL.createObjectURL(file)
    element.download = `se_template_${template.type}_${template.id}.html`
    document.body.appendChild(element)
    element.click()
    document.body.removeChild(element)
  }

  const getRiskColor = (risk: string) => {
    switch (risk.toLowerCase()) {
      case "high": return "text-red-500 bg-red-500/10"
      case "medium": return "text-yellow-500 bg-yellow-500/10"
      case "low": return "text-green-500 bg-green-500/10"
      default: return "text-gray-500 bg-gray-500/10"
    }
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case "phishing_email": return <Mail className="h-4 w-4" />
      case "sms_phishing": return <MessageSquare className="h-4 w-4" />
      case "voice_phishing": return <Phone className="h-4 w-4" />
      case "social_media": return <Users className="h-4 w-4" />
      default: return <Eye className="h-4 w-4" />
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-4">
      <div className="container mx-auto max-w-7xl">
        <div className="mb-8 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Link href="/tools">
              <Button variant="outline" size="sm">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Tools
              </Button>
            </Link>
            <div>
              <h1 className="text-4xl font-bold text-white">Social Engineering Toolkit</h1>
              <p className="text-slate-300 mt-2">
                Educational templates for social engineering awareness and authorized testing
              </p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
          {/* Configuration Form */}
          <div className="lg:col-span-1">
            <Card>
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Users className="h-5 w-5" />
                  Template Configuration
                </CardTitle>
                <CardDescription>
                  Generate social engineering templates for awareness training
                </CardDescription>
              </CardHeader>
              <CardContent>
                <form onSubmit={handleSubmit} className="space-y-4">
                  <div>
                    <Label htmlFor="templateType">Template Type</Label>
                    <Select value={templateType} onValueChange={setTemplateType}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select template type" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="phishing_email">Phishing Email</SelectItem>
                        <SelectItem value="sms_phishing">SMS Phishing</SelectItem>
                        <SelectItem value="voice_phishing">Voice Phishing Script</SelectItem>
                        <SelectItem value="social_media">Social Media</SelectItem>
                        <SelectItem value="physical_pretexting">Physical Pretexting</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label htmlFor="category">Campaign Category</Label>
                    <Select value={category} onValueChange={setCategory}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select category" />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="credential_harvesting">Credential Harvesting</SelectItem>
                        <SelectItem value="malware_delivery">Malware Delivery</SelectItem>
                        <SelectItem value="information_gathering">Information Gathering</SelectItem>
                        <SelectItem value="business_email_compromise">Business Email Compromise</SelectItem>
                        <SelectItem value="tech_support_scam">Tech Support Scam</SelectItem>
                        <SelectItem value="invoice_fraud">Invoice Fraud</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>

                  <div>
                    <Label htmlFor="targetCompany">Target Company (Optional)</Label>
                    <Input
                      id="targetCompany"
                      value={targetCompany}
                      onChange={(e) => setTargetCompany(e.target.value)}
                      placeholder="Acme Corporation"
                    />
                  </div>

                  <div>
                    <Label htmlFor="targetName">Target Name (Optional)</Label>
                    <Input
                      id="targetName"
                      value={targetName}
                      onChange={(e) => setTargetName(e.target.value)}
                      placeholder="John Smith"
                    />
                  </div>

                  <div>
                    <Label htmlFor="targetEmail">Target Email (Optional)</Label>
                    <Input
                      id="targetEmail"
                      value={targetEmail}
                      onChange={(e) => setTargetEmail(e.target.value)}
                      placeholder="john.smith@company.com"
                    />
                  </div>

                  {templateType === "phishing_email" && (
                    <div>
                      <Label htmlFor="customSubject">Custom Subject</Label>
                      <Input
                        id="customSubject"
                        value={customSubject}
                        onChange={(e) => setCustomSubject(e.target.value)}
                        placeholder="Urgent: Account Security Alert"
                      />
                    </div>
                  )}

                  <div>
                    <Label htmlFor="customMessage">Additional Context</Label>
                    <Textarea
                      id="customMessage"
                      value={customMessage}
                      onChange={(e) => setCustomMessage(e.target.value)}
                      placeholder="Add specific context or requirements..."
                      rows={3}
                    />
                  </div>

                  <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
                    <div className="flex items-center gap-2 text-red-500 mb-2">
                      <AlertTriangle className="h-4 w-4" />
                      <span className="font-semibold">Ethical Use Only</span>
                    </div>
                    <p className="text-sm text-red-400">
                      These templates are for educational purposes, authorized penetration testing, 
                      and security awareness training only. Unauthorized use is illegal and unethical.
                    </p>
                  </div>

                  <Button type="submit" className="w-full" disabled={isLoading}>
                    {isLoading ? "Generating..." : "Generate Templates"}
                  </Button>
                </form>
              </CardContent>
            </Card>
          </div>

          {/* Results */}
          <div className="lg:col-span-2 space-y-6">
            {error && (
              <Card className="border-red-500/20 bg-red-500/10">
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2 text-red-500">
                    <AlertTriangle className="h-4 w-4" />
                    <span className="font-semibold">Generation Error</span>
                  </div>
                  <p className="mt-2 text-red-400">{error}</p>
                </CardContent>
              </Card>
            )}

            {isLoading && (
              <Card>
                <CardContent className="pt-6">
                  <div className="flex items-center gap-2 mb-4">
                    <Users className="h-4 w-4 animate-pulse" />
                    <span>Generating social engineering templates...</span>
                  </div>
                  <p className="text-sm text-gray-500">
                    Creating customized templates with psychological triggers
                  </p>
                </CardContent>
              </Card>
            )}

            {result && (
              <Tabs defaultValue="templates" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="templates">Templates ({result.total_templates})</TabsTrigger>
                  <TabsTrigger value="preview">Preview</TabsTrigger>
                  <TabsTrigger value="analysis">Risk Analysis</TabsTrigger>
                </TabsList>

                <TabsContent value="templates" className="space-y-4">
                  <Card>
                    <CardHeader>
                      <CardTitle>Generated Templates</CardTitle>
                      <CardDescription>
                        {result.total_templates} templates generated in {result.generation_time}ms
                      </CardDescription>
                    </CardHeader>
                  </Card>

                  <div className="space-y-4">
                    {result.templates.map((template) => (
                      <Card 
                        key={template.id} 
                        className={`cursor-pointer transition-colors ${
                          selectedTemplate?.id === template.id 
                            ? "border-blue-500 bg-blue-500/5" 
                            : "hover:bg-slate-50 dark:hover:bg-slate-800"
                        }`}
                        onClick={() => setSelectedTemplate(template)}
                      >
                        <CardHeader className="pb-3">
                          <div className="flex justify-between items-start">
                            <div>
                              <CardTitle className="flex items-center gap-2 text-lg">
                                {getTypeIcon(template.type)}
                                {template.name}
                              </CardTitle>
                              <CardDescription>
                                {template.description}
                              </CardDescription>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge className={getRiskColor(template.detection_risk)}>
                                {template.detection_risk.toUpperCase()} RISK
                              </Badge>
                              <Badge variant="secondary">
                                {template.difficulty}
                              </Badge>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <div className="flex items-center justify-between text-sm text-gray-500">
                            <span>Effectiveness: {template.effectiveness_score}/10</span>
                            <div className="flex gap-2">
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  copyToClipboard(template.content)
                                }}
                              >
                                <Copy className="h-3 w-3 mr-1" />
                                Copy
                              </Button>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={(e) => {
                                  e.stopPropagation()
                                  downloadTemplate(template)
                                }}
                              >
                                <Download className="h-3 w-3 mr-1" />
                                Download
                              </Button>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="preview" className="space-y-4">
                  {selectedTemplate ? (
                    <Card>
                      <CardHeader>
                        <CardTitle className="flex items-center gap-2">
                          {getTypeIcon(selectedTemplate.type)}
                          Template Preview
                        </CardTitle>
                        <CardDescription>
                          {selectedTemplate.name} - {selectedTemplate.description}
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-6">
                        {selectedTemplate.subject && (
                          <div>
                            <h4 className="font-semibold mb-2">Subject Line</h4>
                            <div className="bg-gray-100 dark:bg-gray-800 p-3 rounded border">
                              <code className="text-sm">{selectedTemplate.subject}</code>
                            </div>
                          </div>
                        )}

                        <div>
                          <h4 className="font-semibold mb-2 flex items-center gap-2">
                            Template Content
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(selectedTemplate.content)}
                            >
                              <Copy className="h-3 w-3" />
                            </Button>
                          </h4>
                          {selectedTemplate.preview_html ? (
                            <div className="border rounded-lg p-4 bg-white dark:bg-gray-900">
                              <div dangerouslySetInnerHTML={{ __html: selectedTemplate.preview_html }} />
                            </div>
                          ) : (
                            <Textarea
                              value={selectedTemplate.content}
                              readOnly
                              className="font-mono text-sm min-h-[300px]"
                            />
                          )}
                        </div>

                        <div>
                          <h4 className="font-semibold mb-2">Target Information Required</h4>
                          <div className="flex flex-wrap gap-2">
                            {selectedTemplate.target_info.map((info, index) => (
                              <Badge key={index} variant="outline" className="text-xs">
                                {info}
                              </Badge>
                            ))}
                          </div>
                        </div>

                        <div>
                          <h4 className="font-semibold mb-2">Customizable Fields</h4>
                          <div className="flex flex-wrap gap-2">
                            {selectedTemplate.customizable_fields.map((field, index) => (
                              <Badge key={index} className="bg-blue-500/10 text-blue-500 text-xs">
                                {field}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ) : (
                    <Card>
                      <CardContent className="pt-6 text-center">
                        <Eye className="h-12 w-12 text-gray-400 mx-auto mb-4" />
                        <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">
                          Select a Template
                        </h3>
                        <p className="text-gray-500 dark:text-gray-400">
                          Click on any template to view its preview and details
                        </p>
                      </CardContent>
                    </Card>
                  )}
                </TabsContent>

                <TabsContent value="analysis" className="space-y-4">
                  {result.campaign && (
                    <Card>
                      <CardHeader>
                        <CardTitle>Risk Assessment</CardTitle>
                        <CardDescription>
                          Comprehensive analysis of campaign risks and effectiveness
                        </CardDescription>
                      </CardHeader>
                      <CardContent className="space-y-6">
                        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                          <div>
                            <h4 className="font-semibold mb-2">Legal Risk</h4>
                            <Badge className={getRiskColor(result.campaign.risk_assessment.legal_risk)}>
                              {result.campaign.risk_assessment.legal_risk.toUpperCase()}
                            </Badge>
                          </div>
                          <div>
                            <h4 className="font-semibold mb-2">Detection Risk</h4>
                            <Badge className={getRiskColor(result.campaign.risk_assessment.detection_risk)}>
                              {result.campaign.risk_assessment.detection_risk.toUpperCase()}
                            </Badge>
                          </div>
                          <div>
                            <h4 className="font-semibold mb-2">Success Rate</h4>
                            <span className="text-lg font-bold text-green-600">
                              {result.campaign.estimated_success_rate}%
                            </span>
                          </div>
                        </div>

                        <div>
                          <h4 className="font-semibold mb-2">Ethical Concerns</h4>
                          <ul className="text-sm space-y-1">
                            {result.campaign.risk_assessment.ethical_concerns.map((concern, index) => (
                              <li key={index} className="flex items-start gap-2">
                                <span className="w-1 h-1 bg-red-500 rounded-full mt-2 flex-shrink-0"></span>
                                <span className="text-red-400">{concern}</span>
                              </li>
                            ))}
                          </ul>
                        </div>

                        <div>
                          <h4 className="font-semibold mb-2">Recommended Delivery Methods</h4>
                          <div className="flex flex-wrap gap-2">
                            {result.campaign.delivery_methods.map((method, index) => (
                              <Badge key={index} variant="secondary" className="text-xs">
                                {method}
                              </Badge>
                            ))}
                          </div>
                        </div>

                        <div>
                          <h4 className="font-semibold mb-2">Tracking Options</h4>
                          <div className="flex flex-wrap gap-2">
                            {result.campaign.tracking_options.map((option, index) => (
                              <Badge key={index} className="bg-purple-500/10 text-purple-500 text-xs">
                                {option}
                              </Badge>
                            ))}
                          </div>
                        </div>

                        <div className="bg-amber-500/10 border border-amber-500/20 rounded p-4">
                          <h4 className="font-semibold text-amber-600 mb-2">Important Reminders</h4>
                          <ul className="text-sm text-amber-700 dark:text-amber-300 space-y-1">
                            <li>• Always obtain proper authorization before conducting social engineering tests</li>
                            <li>• Use these templates only for legitimate security assessments and training</li>
                            <li>• Document all activities and maintain ethical standards</li>
                            <li>• Consider the psychological impact on target individuals</li>
                            <li>• Provide proper disclosure and education after testing</li>
                          </ul>
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </TabsContent>
              </Tabs>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
