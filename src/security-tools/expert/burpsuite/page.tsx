'use client';

import React, { useState } from 'react';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card';
import { Button } from '@/src/ui/components/ui/button';
import { Input } from '@/src/ui/components/ui/input';
import { Label } from '@/src/ui/components/ui/label';
import { Textarea } from '@/src/ui/components/ui/textarea';
import { Badge } from '@/src/ui/components/ui/badge';
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select';
import { Loader2, Shield, AlertTriangle, Search, Globe, Zap, Database, FileText } from 'lucide-react';

interface BurpSuiteResult {
  targetUrl: string;
  scanType: string;
  vulnerabilities: {
    severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
    name: string;
    description: string;
    url: string;
    parameter: string;
    evidence: string;
    remediation: string;
    references: string[];
    cvss: number;
  }[];
  crawledUrls: {
    url: string;
    method: string;
    status: number;
    length: number;
    mimeType: string;
    parameters: string[];
  }[];
  intruderResults: {
    position: string;
    payloads: { payload: string; status: number; length: number; response_time: number }[];
    successfulPayloads: string[];
    patterns: string[];
  };
  scanStatistics: {
    totalRequests: number;
    uniqueUrls: number;
    parameters: number;
    cookies: number;
    scanDuration: string;
  };
  complianceIssues: {
    standard: string;
    requirement: string;
    status: 'Pass' | 'Fail' | 'Warning';
    description: string;
  }[];
  recommendations: string[];
}

export default function BurpSuiteTool() {
  const [targetUrl, setTargetUrl] = useState('');
  const [scanType, setScanType] = useState('active');
  const [crawlDepth, setCrawlDepth] = useState('3');
  const [authType, setAuthType] = useState('none');
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [customHeaders, setCustomHeaders] = useState('');
  const [excludePatterns, setExcludePatterns] = useState('');
  const [results, setResults] = useState<BurpSuiteResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleScan = async () => {
    if (!targetUrl.trim()) {
      setError('Please enter a target URL');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await fetch('/api/tools/burpsuite', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetUrl: targetUrl.trim(),
          scanType,
          crawlDepth: parseInt(crawlDepth),
          authType,
          username: username.trim(),
          password: password.trim(),
          customHeaders: customHeaders.trim(),
          excludePatterns: excludePatterns.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to perform Burp Suite scan');
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical': return 'bg-purple-100 text-purple-800 border-purple-200';
      case 'high': return 'bg-red-100 text-red-800 border-red-200';
      case 'medium': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'low': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'info': return 'bg-blue-100 text-blue-800 border-blue-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'bg-green-100 text-green-800';
    if (status >= 300 && status < 400) return 'bg-yellow-100 text-yellow-800';
    if (status >= 400 && status < 500) return 'bg-orange-100 text-orange-800';
    if (status >= 500) return 'bg-red-100 text-red-800';
    return 'bg-gray-100 text-gray-800';
  };

  const getComplianceColor = (status: string) => {
    switch (status.toLowerCase()) {
      case 'pass': return 'bg-green-100 text-green-800';
      case 'fail': return 'bg-red-100 text-red-800';
      case 'warning': return 'bg-yellow-100 text-yellow-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 flex items-center gap-3">
          <Shield className="text-orange-600" />
          Burp Suite Professional
        </h1>
        <p className="text-lg text-muted-foreground">
          Advanced web application security testing platform with comprehensive vulnerability scanning
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="w-5 h-5" />
              Scan Configuration
            </CardTitle>
            <CardDescription>
              Configure your web application security scan
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="targetUrl">Target URL</Label>
              <Input
                id="targetUrl"
                placeholder="https://example.com"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
              />
            </div>

            <div>
              <Label htmlFor="scanType">Scan Type</Label>
              <Select value={scanType} onValueChange={setScanType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="passive">Passive Scan Only</SelectItem>
                  <SelectItem value="active">Active Security Scan</SelectItem>
                  <SelectItem value="crawl">Crawl & Audit</SelectItem>
                  <SelectItem value="comprehensive">Comprehensive Analysis</SelectItem>
                  <SelectItem value="compliance">Compliance Testing</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="crawlDepth">Crawl Depth</Label>
              <Select value={crawlDepth} onValueChange={setCrawlDepth}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="1">1 Level (Fast)</SelectItem>
                  <SelectItem value="2">2 Levels (Balanced)</SelectItem>
                  <SelectItem value="3">3 Levels (Thorough)</SelectItem>
                  <SelectItem value="5">5 Levels (Deep)</SelectItem>
                  <SelectItem value="unlimited">Unlimited (Comprehensive)</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="authType">Authentication</Label>
              <Select value={authType} onValueChange={setAuthType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No Authentication</SelectItem>
                  <SelectItem value="basic">HTTP Basic Auth</SelectItem>
                  <SelectItem value="form">Form-based Login</SelectItem>
                  <SelectItem value="ntlm">NTLM Authentication</SelectItem>
                  <SelectItem value="digest">Digest Authentication</SelectItem>
                  <SelectItem value="bearer">Bearer Token</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {authType !== 'none' && authType !== 'bearer' && (
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label htmlFor="username">Username</Label>
                  <Input
                    id="username"
                    placeholder="admin"
                    value={username}
                    onChange={(e) => setUsername(e.target.value)}
                  />
                </div>
                <div>
                  <Label htmlFor="password">Password</Label>
                  <Input
                    id="password"
                    type="password"
                    placeholder="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                  />
                </div>
              </div>
            )}

            <div>
              <Label htmlFor="customHeaders">Custom Headers (Optional)</Label>
              <Textarea
                id="customHeaders"
                placeholder="X-API-Key: your-api-key&#10;Custom-Header: value"
                value={customHeaders}
                onChange={(e) => setCustomHeaders(e.target.value)}
                rows={3}
              />
            </div>

            <div>
              <Label htmlFor="excludePatterns">Exclude URLs (Regex patterns)</Label>
              <Input
                id="excludePatterns"
                placeholder="/logout|/admin/delete|\.pdf$"
                value={excludePatterns}
                onChange={(e) => setExcludePatterns(e.target.value)}
              />
            </div>

            <Button 
              onClick={handleScan} 
              disabled={loading}
              className="w-full"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Scanning Application...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  Start Security Scan
                </>
              )}
            </Button>

            {error && (
              <Alert className="border-red-200 bg-red-50">
                <AlertTriangle className="h-4 w-4" />
                <AlertDescription className="text-red-800">
                  {error}
                </AlertDescription>
              </Alert>
            )}

            <div className="bg-orange-50 border border-orange-200 rounded-lg p-4">
              <div className="flex items-center gap-2 text-orange-600 mb-2">
                <Shield className="h-4 w-4" />
                <span className="font-semibold">Professional Testing</span>
              </div>
              <p className="text-sm text-orange-700">
                This tool simulates Burp Suite Professional capabilities. Only scan applications you own or have 
                explicit permission to test. Be mindful of active scanning impact on production systems.
              </p>
            </div>
          </CardContent>
        </Card>

        {results && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="w-5 h-5" />
                Security Scan Results
              </CardTitle>
              <CardDescription>
                Comprehensive security analysis for {results.targetUrl}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="vulnerabilities" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="vulnerabilities">Vulnerabilities</TabsTrigger>
                  <TabsTrigger value="crawl">Site Map</TabsTrigger>
                  <TabsTrigger value="intruder">Intruder</TabsTrigger>
                  <TabsTrigger value="compliance">Compliance</TabsTrigger>
                </TabsList>

                <TabsContent value="vulnerabilities" className="space-y-4">
                  <div className="grid grid-cols-5 gap-2 mb-4">
                    {['Critical', 'High', 'Medium', 'Low', 'Info'].map((severity) => {
                      const count = results.vulnerabilities.filter(v => v.severity === severity).length;
                      return (
                        <div key={severity} className="text-center p-3 bg-gray-50 rounded-lg">
                          <div className={`text-xl font-bold ${
                            severity === 'Critical' ? 'text-purple-600' :
                            severity === 'High' ? 'text-red-600' :
                            severity === 'Medium' ? 'text-orange-600' :
                            severity === 'Low' ? 'text-yellow-600' :
                            'text-blue-600'
                          }`}>
                            {count}
                          </div>
                          <div className="text-xs text-gray-600">{severity}</div>
                        </div>
                      );
                    })}
                  </div>

                  <div className="max-h-96 overflow-y-auto space-y-3">
                    {results.vulnerabilities.map((vuln, index) => (
                      <div key={index} className="border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="font-medium">{vuln.name}</h4>
                          <div className="flex gap-2">
                            <Badge className={getSeverityColor(vuln.severity)}>
                              {vuln.severity}
                            </Badge>
                            <Badge className="bg-gray-100 text-gray-800">
                              CVSS: {vuln.cvss}
                            </Badge>
                          </div>
                        </div>
                        
                        <p className="text-sm text-gray-600 mb-3">{vuln.description}</p>
                        
                        <div className="space-y-2 text-sm">
                          <div>
                            <span className="font-medium">URL:</span>
                            <span className="ml-2 font-mono text-blue-600">{vuln.url}</span>
                          </div>
                          {vuln.parameter && (
                            <div>
                              <span className="font-medium">Parameter:</span>
                              <span className="ml-2 font-mono">{vuln.parameter}</span>
                            </div>
                          )}
                          <div>
                            <span className="font-medium">Evidence:</span>
                            <div className="mt-1 p-2 bg-gray-50 rounded font-mono text-xs">
                              {vuln.evidence}
                            </div>
                          </div>
                          <div>
                            <span className="font-medium">Remediation:</span>
                            <p className="mt-1 text-gray-700">{vuln.remediation}</p>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="crawl" className="space-y-4">
                  <div className="grid grid-cols-4 gap-4 mb-4">
                    <div className="text-center p-3 bg-gray-50 rounded-lg">
                      <div className="text-xl font-bold text-blue-600">
                        {results.scanStatistics.totalRequests}
                      </div>
                      <div className="text-xs text-gray-600">Total Requests</div>
                    </div>
                    <div className="text-center p-3 bg-gray-50 rounded-lg">
                      <div className="text-xl font-bold text-green-600">
                        {results.scanStatistics.uniqueUrls}
                      </div>
                      <div className="text-xs text-gray-600">Unique URLs</div>
                    </div>
                    <div className="text-center p-3 bg-gray-50 rounded-lg">
                      <div className="text-xl font-bold text-purple-600">
                        {results.scanStatistics.parameters}
                      </div>
                      <div className="text-xs text-gray-600">Parameters</div>
                    </div>
                    <div className="text-center p-3 bg-gray-50 rounded-lg">
                      <div className="text-xl font-bold text-orange-600">
                        {results.scanStatistics.cookies}
                      </div>
                      <div className="text-xs text-gray-600">Cookies</div>
                    </div>
                  </div>

                  <div className="max-h-96 overflow-y-auto space-y-2">
                    {results.crawledUrls.map((url, index) => (
                      <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <Badge className="bg-blue-100 text-blue-800 text-xs">
                              {url.method}
                            </Badge>
                            <Badge className={getStatusColor(url.status)}>
                              {url.status}
                            </Badge>
                            <span className="text-xs text-gray-500">{url.mimeType}</span>
                          </div>
                          <div className="font-mono text-sm truncate">{url.url}</div>
                          {url.parameters.length > 0 && (
                            <div className="text-xs text-gray-600 mt-1">
                              Parameters: {url.parameters.join(', ')}
                            </div>
                          )}
                        </div>
                        <div className="text-xs text-gray-500">
                          {url.length} bytes
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="intruder" className="space-y-4">
                  <div className="p-4 bg-blue-50 rounded-lg">
                    <h4 className="font-medium mb-2">Intruder Attack Results</h4>
                    <div className="text-sm space-y-1">
                      <div>Position: {results.intruderResults.position}</div>
                      <div>Total Payloads: {results.intruderResults.payloads.length}</div>
                      <div>Successful: {results.intruderResults.successfulPayloads.length}</div>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2">Payload Results:</h4>
                    <div className="max-h-64 overflow-y-auto space-y-2">
                      {results.intruderResults.payloads.slice(0, 20).map((payload, index) => (
                        <div key={index} className="flex items-center justify-between p-2 border rounded">
                          <span className="font-mono text-sm">{payload.payload}</span>
                          <div className="flex gap-2">
                            <Badge className={getStatusColor(payload.status)}>
                              {payload.status}
                            </Badge>
                            <span className="text-xs text-gray-500">
                              {payload.length}b • {payload.response_time}ms
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {results.intruderResults.successfulPayloads.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2 text-red-600">⚠️ Successful Payloads:</h4>
                      <div className="space-y-1">
                        {results.intruderResults.successfulPayloads.map((payload, index) => (
                          <div key={index} className="bg-red-50 p-2 rounded font-mono text-sm">
                            {payload}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {results.intruderResults.patterns.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Patterns Detected:</h4>
                      <div className="space-y-1">
                        {results.intruderResults.patterns.map((pattern, index) => (
                          <div key={index} className="bg-yellow-50 p-2 rounded text-sm">
                            {pattern}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="compliance" className="space-y-4">
                  <div className="space-y-3">
                    {results.complianceIssues.map((issue, index) => (
                      <div key={index} className="p-4 border rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-medium">{issue.standard}</span>
                          <Badge className={getComplianceColor(issue.status)}>
                            {issue.status}
                          </Badge>
                        </div>
                        <div className="text-sm">
                          <div className="font-medium mb-1">{issue.requirement}</div>
                          <div className="text-gray-600">{issue.description}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>
              </Tabs>

              {results.recommendations.length > 0 && (
                <div className="mt-6">
                  <h4 className="font-medium mb-2">Security Recommendations:</h4>
                  <div className="space-y-2">
                    {results.recommendations.map((rec, index) => (
                      <Alert key={index}>
                        <Shield className="h-4 w-4" />
                        <AlertDescription>{rec}</AlertDescription>
                      </Alert>
                    ))}
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        )}
      </div>

      {/* Educational Information */}
      <Card className="mt-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <FileText className="w-5 h-5" />
            About Burp Suite Professional
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="space-y-1 text-sm">
                <li>• <strong>Scanner:</strong> Automated vulnerability detection</li>
                <li>• <strong>Intruder:</strong> Customizable attacks and fuzzing</li>
                <li>• <strong>Repeater:</strong> Manual request modification and testing</li>
                <li>• <strong>Proxy:</strong> Intercept and modify HTTP traffic</li>
                <li>• <strong>Spider:</strong> Automated web application crawling</li>
                <li>• <strong>Sequencer:</strong> Random token analysis</li>
                <li>• <strong>Decoder:</strong> Encode/decode data in various formats</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Testing Methodology:</h4>
              <ul className="space-y-1 text-sm">
                <li>• Map application structure and functionality</li>
                <li>• Identify entry points and attack surfaces</li>
                <li>• Test for common web vulnerabilities (OWASP Top 10)</li>
                <li>• Perform authentication and session management tests</li>
                <li>• Analyze client-side security controls</li>
                <li>• Document findings with evidence and remediation</li>
                <li>• Validate fixes through retesting</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
