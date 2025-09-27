"use client"

import React, { useState } from 'react'
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Alert, AlertDescription } from "@/src/ui/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { 
  Users, 
  Mail,
  MessageSquare,
  Phone,
  AlertTriangle, 
  Shield, 
  Eye,
  Terminal,
  ArrowLeft,
  RefreshCw,
  Target,
  Activity,
  Brain,
  Fingerprint,
  Globe,
  Camera,
  FileText,
  Lock,
  User,
  Calendar
} from 'lucide-react'
import Link from 'next/link'

interface SocialEngineeringResult {
  campaignType: string;
  targetAnalysis: {
    profile: {
      name: string;
      role: string;
      company: string;
      email: string;
      socialMedia: string[];
      vulnerabilities: string[];
      riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
    };
    digitalFootprint: {
      socialPlatforms: string[];
      publicInfo: string[];
      connections: string[];
      interests: string[];
    };
    attackVectors: {
      vector: string;
      method: string;
      success_rate: number;
      difficulty: 'Easy' | 'Medium' | 'Hard';
      description: string;
    }[];
  };
  templates: {
    emails: {
      subject: string;
      body: string;
      type: string;
      effectiveness: number;
      red_flags: string[];
    }[];
    messages: {
      platform: string;
      message: string;
      context: string;
      approach: string;
    }[];
    calls: {
      script: string;
      scenario: string;
      duration: string;
      key_points: string[];
    }[];
  };
  psychologyProfiles: {
    personalityType: string;
    triggers: string[];
    approaches: string[];
    avoidance: string[];
    successRate: number;
  }[];
  defensiveMeasures: string[];
  awarenessTips: string[];
  summary: string;
}

export default function SocialEngineeringPage() {
  const [campaignType, setCampaignType] = useState('phishing')
  const [targetType, setTargetType] = useState('individual')
  const [industry, setIndustry] = useState('technology')
  const [targetName, setTargetName] = useState('')
  const [targetEmail, setTargetEmail] = useState('')
  const [targetCompany, setTargetCompany] = useState('')
  const [attackGoal, setAttackGoal] = useState('credential_theft')
  const [complexity, setComplexity] = useState('medium')
  const [includePersonalization, setIncludePersonalization] = useState(true)
  const [includePsychology, setIncludePsychology] = useState(true)
  const [includeDefenses, setIncludeDefenses] = useState(true)
  const [results, setResults] = useState<SocialEngineeringResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleAnalyze = async () => {
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const response = await fetch('/api/tools/social-engineering', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          campaignType,
          targetType,
          industry,
          targetName,
          targetEmail,
          targetCompany,
          attackGoal,
          complexity,
          includePersonalization,
          includePsychology,
          includeDefenses,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to analyze social engineering vectors')
      }

      const data = await response.json()
      setResults(data)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      setLoading(false)
    }
  }

  const getRiskLevelColor = (risk: string) => {
    switch (risk) {
      case 'Critical': return 'bg-red-500 text-white'
      case 'High': return 'bg-orange-500 text-white'
      case 'Medium': return 'bg-yellow-500 text-black'
      case 'Low': return 'bg-green-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  const getDifficultyColor = (difficulty: string) => {
    switch (difficulty) {
      case 'Easy': return 'text-green-400'
      case 'Medium': return 'text-yellow-400'
      case 'Hard': return 'text-red-400'
      default: return 'text-gray-400'
    }
  }

  const getSuccessRateColor = (rate: number) => {
    if (rate >= 80) return 'text-red-400'
    if (rate >= 60) return 'text-orange-400'
    if (rate >= 40) return 'text-yellow-400'
    return 'text-blue-400'
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-red-900 to-slate-900 p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/tools" className="p-2 hover:bg-white/10 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-white" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Social Engineering Toolkit</h1>
            <p className="text-gray-300">
              Analyze social engineering attack vectors and develop defensive strategies
            </p>
          </div>
        </div>

        {/* Configuration Form */}
        <Card className="mb-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Users className="w-5 h-5" />
              Social Engineering Analysis Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure target analysis and attack vector simulation
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label htmlFor="campaignType" className="text-gray-200">Campaign Type</Label>
                <Select value={campaignType} onValueChange={setCampaignType}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="phishing">Email Phishing</SelectItem>
                    <SelectItem value="spear_phishing">Spear Phishing</SelectItem>
                    <SelectItem value="vishing">Voice Phishing (Vishing)</SelectItem>
                    <SelectItem value="smishing">SMS Phishing (Smishing)</SelectItem>
                    <SelectItem value="pretexting">Pretexting</SelectItem>
                    <SelectItem value="baiting">Baiting</SelectItem>
                    <SelectItem value="quid_pro_quo">Quid Pro Quo</SelectItem>
                    <SelectItem value="tailgating">Tailgating</SelectItem>
                    <SelectItem value="watering_hole">Watering Hole</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="targetType" className="text-gray-200">Target Type</Label>
                <Select value={targetType} onValueChange={setTargetType}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="individual">Individual</SelectItem>
                    <SelectItem value="executive">Executive/C-Level</SelectItem>
                    <SelectItem value="employee">Employee</SelectItem>
                    <SelectItem value="contractor">Contractor</SelectItem>
                    <SelectItem value="customer">Customer</SelectItem>
                    <SelectItem value="vendor">Vendor/Supplier</SelectItem>
                    <SelectItem value="department">Department</SelectItem>
                    <SelectItem value="organization">Entire Organization</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="industry" className="text-gray-200">Industry</Label>
                <Select value={industry} onValueChange={setIndustry}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="technology">Technology</SelectItem>
                    <SelectItem value="healthcare">Healthcare</SelectItem>
                    <SelectItem value="finance">Finance/Banking</SelectItem>
                    <SelectItem value="education">Education</SelectItem>
                    <SelectItem value="government">Government</SelectItem>
                    <SelectItem value="retail">Retail</SelectItem>
                    <SelectItem value="manufacturing">Manufacturing</SelectItem>
                    <SelectItem value="legal">Legal</SelectItem>
                    <SelectItem value="consulting">Consulting</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid md:grid-cols-3 gap-4">
              <div className="space-y-2">
                <Label htmlFor="targetName" className="text-gray-200">Target Name (Optional)</Label>
                <Input
                  id="targetName"
                  placeholder="John Doe"
                  value={targetName}
                  onChange={(e) => setTargetName(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="targetEmail" className="text-gray-200">Target Email (Optional)</Label>
                <Input
                  id="targetEmail"
                  placeholder="john.doe@company.com"
                  value={targetEmail}
                  onChange={(e) => setTargetEmail(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="targetCompany" className="text-gray-200">Target Company (Optional)</Label>
                <Input
                  id="targetCompany"
                  placeholder="Example Corp"
                  value={targetCompany}
                  onChange={(e) => setTargetCompany(e.target.value)}
                  className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                />
              </div>
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="attackGoal" className="text-gray-200">Attack Goal</Label>
                <Select value={attackGoal} onValueChange={setAttackGoal}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="credential_theft">Credential Theft</SelectItem>
                    <SelectItem value="malware_delivery">Malware Delivery</SelectItem>
                    <SelectItem value="data_extraction">Data Extraction</SelectItem>
                    <SelectItem value="financial_fraud">Financial Fraud</SelectItem>
                    <SelectItem value="physical_access">Physical Access</SelectItem>
                    <SelectItem value="information_gathering">Information Gathering</SelectItem>
                    <SelectItem value="system_access">System Access</SelectItem>
                    <SelectItem value="privilege_escalation">Privilege Escalation</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="complexity" className="text-gray-200">Campaign Complexity</Label>
                <Select value={complexity} onValueChange={setComplexity}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="basic">Basic</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="advanced">Advanced</SelectItem>
                    <SelectItem value="expert">Expert</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <div className="grid md:grid-cols-3 gap-4">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="includePersonalization"
                  checked={includePersonalization}
                  onChange={(e) => setIncludePersonalization(e.target.checked)}
                  className="rounded"
                  aria-label="Include personalization"
                />
                <Label htmlFor="includePersonalization" className="text-gray-200">
                  Include Personalization
                </Label>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="includePsychology"
                  checked={includePsychology}
                  onChange={(e) => setIncludePsychology(e.target.checked)}
                  className="rounded"
                  aria-label="Include psychology analysis"
                />
                <Label htmlFor="includePsychology" className="text-gray-200">
                  Psychology Analysis
                </Label>
              </div>

              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="includeDefenses"
                  checked={includeDefenses}
                  onChange={(e) => setIncludeDefenses(e.target.checked)}
                  className="rounded"
                  aria-label="Include defensive measures"
                />
                <Label htmlFor="includeDefenses" className="text-gray-200">
                  Defensive Measures
                </Label>
              </div>
            </div>

            <Button 
              onClick={handleAnalyze}
              disabled={loading}
              className="w-full bg-red-600 hover:bg-red-700"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Analyzing Vectors...
                </>
              ) : (
                <>
                  <Brain className="w-4 h-4 mr-2" />
                  Analyze Social Engineering Vectors
                </>
              )}
            </Button>
          </CardContent>
        </Card>

        {/* Error Display */}
        {error && (
          <Alert className="mb-6 bg-red-900/50 border-red-500 text-red-200">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Results */}
        {results && (
          <div className="space-y-6">
            {/* Summary Card */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-white">
                  <Target className="w-5 h-5" />
                  Social Engineering Analysis Summary
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-red-400">
                      {results.targetAnalysis.attackVectors.length}
                    </div>
                    <div className="text-sm text-gray-300">Attack Vectors</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">
                      {results.templates.emails.length + results.templates.messages.length}
                    </div>
                    <div className="text-sm text-gray-300">Templates</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-green-400">
                      {results.psychologyProfiles.length}
                    </div>
                    <div className="text-sm text-gray-300">Profiles</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className={`text-2xl font-bold ${getRiskLevelColor(results.targetAnalysis.profile.riskLevel).includes('bg-red') ? 'text-red-400' : getRiskLevelColor(results.targetAnalysis.profile.riskLevel).includes('bg-orange') ? 'text-orange-400' : getRiskLevelColor(results.targetAnalysis.profile.riskLevel).includes('bg-yellow') ? 'text-yellow-400' : 'text-green-400'}`}>
                      {results.targetAnalysis.profile.riskLevel}
                    </div>
                    <div className="text-sm text-gray-300">Risk Level</div>
                  </div>
                </div>

                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-white mb-2">Analysis Summary</h3>
                  <p className="text-gray-300">{results.summary}</p>
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Social Engineering Analysis</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="target" className="space-y-4">
                  <TabsList className="bg-slate-700">
                    <TabsTrigger value="target">Target Analysis</TabsTrigger>
                    <TabsTrigger value="vectors">Attack Vectors</TabsTrigger>
                    <TabsTrigger value="templates">Templates</TabsTrigger>
                    <TabsTrigger value="psychology">Psychology</TabsTrigger>
                    <TabsTrigger value="defenses">Defenses</TabsTrigger>
                  </TabsList>

                  <TabsContent value="target" className="space-y-4">
                    <div className="grid md:grid-cols-2 gap-6">
                      <Card className="bg-slate-700/30">
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2 text-white">
                            <User className="w-5 h-5" />
                            Target Profile
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div className="space-y-2">
                            <div className="flex justify-between">
                              <span className="text-gray-400">Name:</span>
                              <span className="text-white">{results.targetAnalysis.profile.name}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Role:</span>
                              <span className="text-blue-400">{results.targetAnalysis.profile.role}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Company:</span>
                              <span className="text-green-400">{results.targetAnalysis.profile.company}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Email:</span>
                              <span className="text-orange-400">{results.targetAnalysis.profile.email}</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-400">Risk Level:</span>
                              <Badge className={getRiskLevelColor(results.targetAnalysis.profile.riskLevel)}>
                                {results.targetAnalysis.profile.riskLevel}
                              </Badge>
                            </div>
                          </div>

                          <div>
                            <span className="text-gray-400 block mb-2">Social Media:</span>
                            <div className="flex flex-wrap gap-1">
                              {results.targetAnalysis.profile.socialMedia.map((platform, index) => (
                                <Badge key={index} variant="outline" className="text-purple-400 border-purple-400 text-xs">
                                  {platform}
                                </Badge>
                              ))}
                            </div>
                          </div>

                          <div>
                            <span className="text-gray-400 block mb-2">Vulnerabilities:</span>
                            <ul className="space-y-1">
                              {results.targetAnalysis.profile.vulnerabilities.map((vuln, index) => (
                                <li key={index} className="text-red-400 text-sm flex items-start gap-2">
                                  <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                                  {vuln}
                                </li>
                              ))}
                            </ul>
                          </div>
                        </CardContent>
                      </Card>

                      <Card className="bg-slate-700/30">
                        <CardHeader>
                          <CardTitle className="flex items-center gap-2 text-white">
                            <Fingerprint className="w-5 h-5" />
                            Digital Footprint
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div>
                            <span className="text-gray-400 block mb-2">Social Platforms:</span>
                            <div className="flex flex-wrap gap-1">
                              {results.targetAnalysis.digitalFootprint.socialPlatforms.map((platform, index) => (
                                <Badge key={index} variant="outline" className="text-blue-400 border-blue-400 text-xs">
                                  {platform}
                                </Badge>
                              ))}
                            </div>
                          </div>

                          <div>
                            <span className="text-gray-400 block mb-2">Public Information:</span>
                            <ul className="space-y-1 max-h-24 overflow-y-auto">
                              {results.targetAnalysis.digitalFootprint.publicInfo.map((info, index) => (
                                <li key={index} className="text-yellow-400 text-sm">• {info}</li>
                              ))}
                            </ul>
                          </div>

                          <div>
                            <span className="text-gray-400 block mb-2">Connections:</span>
                            <div className="flex flex-wrap gap-1">
                              {results.targetAnalysis.digitalFootprint.connections.slice(0, 5).map((conn, index) => (
                                <Badge key={index} variant="outline" className="text-green-400 border-green-400 text-xs">
                                  {conn}
                                </Badge>
                              ))}
                              {results.targetAnalysis.digitalFootprint.connections.length > 5 && (
                                <Badge variant="outline" className="text-gray-400 border-gray-400 text-xs">
                                  +{results.targetAnalysis.digitalFootprint.connections.length - 5} more
                                </Badge>
                              )}
                            </div>
                          </div>

                          <div>
                            <span className="text-gray-400 block mb-2">Interests:</span>
                            <div className="flex flex-wrap gap-1">
                              {results.targetAnalysis.digitalFootprint.interests.map((interest, index) => (
                                <Badge key={index} variant="outline" className="text-cyan-400 border-cyan-400 text-xs">
                                  {interest}
                                </Badge>
                              ))}
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>

                  <TabsContent value="vectors" className="space-y-4">
                    {results.targetAnalysis.attackVectors.map((vector, index) => (
                      <Card key={index} className="bg-slate-700/30">
                        <CardHeader className="pb-3">
                          <div className="flex items-center justify-between">
                            <CardTitle className="text-lg text-white">{vector.vector}</CardTitle>
                            <div className="flex items-center gap-2">
                              <Badge className={getDifficultyColor(vector.difficulty)} variant="outline">
                                {vector.difficulty}
                              </Badge>
                              <Badge className={`bg-opacity-20 border ${getSuccessRateColor(vector.success_rate)}`}>
                                {vector.success_rate}% Success
                              </Badge>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="space-y-3">
                          <div className="grid md:grid-cols-2 gap-4">
                            <div>
                              <span className="text-gray-400 block mb-1">Method:</span>
                              <span className="text-blue-400">{vector.method}</span>
                            </div>
                            <div>
                              <span className="text-gray-400 block mb-1">Success Rate:</span>
                              <span className={getSuccessRateColor(vector.success_rate)}>
                                {vector.success_rate}%
                              </span>
                            </div>
                          </div>
                          <div>
                            <span className="text-gray-400 block mb-1">Description:</span>
                            <p className="text-gray-300 text-sm">{vector.description}</p>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </TabsContent>

                  <TabsContent value="templates" className="space-y-4">
                    <div className="space-y-6">
                      {/* Email Templates */}
                      <div>
                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                          <Mail className="w-5 h-5" />
                          Email Templates
                        </h3>
                        <div className="space-y-4">
                          {results.templates.emails.map((email, index) => (
                            <Card key={index} className="bg-slate-700/30">
                              <CardHeader className="pb-3">
                                <div className="flex items-center justify-between">
                                  <CardTitle className="text-lg text-white">{email.subject}</CardTitle>
                                  <div className="flex items-center gap-2">
                                    <Badge className="bg-blue-500 text-white">{email.type}</Badge>
                                    <Badge className={`bg-opacity-20 border ${getSuccessRateColor(email.effectiveness)}`}>
                                      {email.effectiveness}% Effective
                                    </Badge>
                                  </div>
                                </div>
                              </CardHeader>
                              <CardContent className="space-y-3">
                                <div className="bg-slate-800 rounded-lg p-4">
                                  <pre className="text-gray-300 text-sm whitespace-pre-wrap font-sans">
                                    {email.body}
                                  </pre>
                                </div>
                                
                                <div>
                                  <span className="text-gray-400 block mb-2">Red Flags:</span>
                                  <ul className="space-y-1">
                                    {email.red_flags.map((flag, flagIndex) => (
                                      <li key={flagIndex} className="text-red-400 text-sm flex items-start gap-2">
                                        <AlertTriangle className="w-3 h-3 mt-0.5 flex-shrink-0" />
                                        {flag}
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </div>

                      {/* Message Templates */}
                      <div>
                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                          <MessageSquare className="w-5 h-5" />
                          Message Templates
                        </h3>
                        <div className="grid md:grid-cols-2 gap-4">
                          {results.templates.messages.map((message, index) => (
                            <Card key={index} className="bg-slate-700/30">
                              <CardHeader>
                                <CardTitle className="text-white">{message.platform}</CardTitle>
                                <p className="text-gray-400 text-sm">{message.context}</p>
                              </CardHeader>
                              <CardContent>
                                <div className="bg-slate-800 rounded-lg p-3 mb-3">
                                  <p className="text-gray-300 text-sm">{message.message}</p>
                                </div>
                                <div>
                                  <span className="text-gray-400 text-sm">Approach: </span>
                                  <span className="text-blue-400 text-sm">{message.approach}</span>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </div>

                      {/* Call Scripts */}
                      <div>
                        <h3 className="text-lg font-semibold text-white mb-4 flex items-center gap-2">
                          <Phone className="w-5 h-5" />
                          Call Scripts
                        </h3>
                        <div className="space-y-4">
                          {results.templates.calls.map((call, index) => (
                            <Card key={index} className="bg-slate-700/30">
                              <CardHeader>
                                <CardTitle className="text-white">{call.scenario}</CardTitle>
                                <p className="text-gray-400 text-sm">Estimated Duration: {call.duration}</p>
                              </CardHeader>
                              <CardContent className="space-y-3">
                                <div className="bg-slate-800 rounded-lg p-4">
                                  <pre className="text-gray-300 text-sm whitespace-pre-wrap font-sans">
                                    {call.script}
                                  </pre>
                                </div>
                                
                                <div>
                                  <span className="text-gray-400 block mb-2">Key Points:</span>
                                  <ul className="space-y-1">
                                    {call.key_points.map((point, pointIndex) => (
                                      <li key={pointIndex} className="text-blue-400 text-sm flex items-start gap-2">
                                        <Activity className="w-3 h-3 mt-0.5 flex-shrink-0" />
                                        {point}
                                      </li>
                                    ))}
                                  </ul>
                                </div>
                              </CardContent>
                            </Card>
                          ))}
                        </div>
                      </div>
                    </div>
                  </TabsContent>

                  <TabsContent value="psychology" className="space-y-4">
                    {results.psychologyProfiles.map((profile, index) => (
                      <Card key={index} className="bg-slate-700/30">
                        <CardHeader>
                          <CardTitle className="flex items-center justify-between text-white">
                            {profile.personalityType}
                            <Badge className={`bg-opacity-20 border ${getSuccessRateColor(profile.successRate)}`}>
                              {profile.successRate}% Success Rate
                            </Badge>
                          </CardTitle>
                        </CardHeader>
                        <CardContent className="space-y-4">
                          <div className="grid md:grid-cols-3 gap-4">
                            <div>
                              <span className="text-gray-400 block mb-2">Psychological Triggers:</span>
                              <ul className="space-y-1">
                                {profile.triggers.map((trigger, triggerIndex) => (
                                  <li key={triggerIndex} className="text-red-400 text-sm">• {trigger}</li>
                                ))}
                              </ul>
                            </div>
                            
                            <div>
                              <span className="text-gray-400 block mb-2">Effective Approaches:</span>
                              <ul className="space-y-1">
                                {profile.approaches.map((approach, approachIndex) => (
                                  <li key={approachIndex} className="text-green-400 text-sm">• {approach}</li>
                                ))}
                              </ul>
                            </div>
                            
                            <div>
                              <span className="text-gray-400 block mb-2">What to Avoid:</span>
                              <ul className="space-y-1">
                                {profile.avoidance.map((avoid, avoidIndex) => (
                                  <li key={avoidIndex} className="text-orange-400 text-sm">• {avoid}</li>
                                ))}
                              </ul>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </TabsContent>

                  <TabsContent value="defenses" className="space-y-4">
                    <div className="grid md:grid-cols-2 gap-6">
                      <Card className="bg-slate-700/30">
                        <CardHeader>
                          <CardTitle className="text-white">Defensive Measures</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-2">
                            {results.defensiveMeasures.map((measure, index) => (
                              <li key={index} className="flex items-start gap-2">
                                <Shield className="w-4 h-4 text-green-400 mt-1 flex-shrink-0" />
                                <span className="text-gray-300 text-sm">{measure}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>

                      <Card className="bg-slate-700/30">
                        <CardHeader>
                          <CardTitle className="text-white">Awareness Tips</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <ul className="space-y-2">
                            {results.awarenessTips.map((tip, index) => (
                              <li key={index} className="flex items-start gap-2">
                                <Eye className="w-4 h-4 text-blue-400 mt-1 flex-shrink-0" />
                                <span className="text-gray-300 text-sm">{tip}</span>
                              </li>
                            ))}
                          </ul>
                        </CardContent>
                      </Card>
                    </div>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Educational Information */}
        <Card className="mt-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Terminal className="w-5 h-5" />
              Social Engineering Defense
            </CardTitle>
          </CardHeader>
          <CardContent className="text-gray-300 space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2 text-white">Common Tactics:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• <strong>Authority:</strong> Impersonating figures of authority</li>
                  <li>• <strong>Urgency:</strong> Creating false time pressure</li>
                  <li>• <strong>Fear:</strong> Threatening negative consequences</li>
                  <li>• <strong>Trust:</strong> Building rapport and relationships</li>
                  <li>• <strong>Reciprocity:</strong> Offering help or gifts first</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-white">Defense Strategies:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Verify requests through official channels</li>
                  <li>• Be suspicious of urgent requests</li>
                  <li>• Never share sensitive information unsolicited</li>
                  <li>• Regular security awareness training</li>
                  <li>• Implement multi-factor authentication</li>
                </ul>
              </div>
            </div>

            <Alert className="bg-amber-900/20 border-amber-500/50 text-amber-200">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Educational Purpose Only:</strong> This toolkit is designed for security awareness, 
                training, and defensive planning. Never use these techniques for malicious purposes or 
                against individuals or organizations without explicit written authorization.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}