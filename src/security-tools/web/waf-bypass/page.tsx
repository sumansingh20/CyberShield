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
import { Loader2, Shield, AlertTriangle, Code, Lock, Zap } from 'lucide-react';

interface WAFBypassResult {
  bypassesFound: number;
  totalTechniques: number;
  successfulPayloads: string[];
  bypassTechniques: string[];
  detectedWAF: string;
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  recommendations: string[];
  detailedResults: {
    technique: string;
    payload: string;
    originalPayload: string;
    success: boolean;
    method: string;
  }[];
}

export default function WAFBypassTool() {
  const [payload, setPayload] = useState('');
  const [targetUrl, setTargetUrl] = useState('');
  const [bypassType, setBypassType] = useState('comprehensive');
  const [wafType, setWafType] = useState('auto-detect');
  const [results, setResults] = useState<WAFBypassResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleBypass = async () => {
    if (!payload.trim()) {
      setError('Please enter a payload to bypass');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await fetch('/api/tools/waf-bypass', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          payload: payload.trim(),
          targetUrl: targetUrl.trim(),
          bypassType,
          wafType,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to perform WAF bypass analysis');
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getRiskColor = (risk: string) => {
    switch (risk) {
      case 'Critical': return 'bg-red-100 text-red-800 border-red-200';
      case 'High': return 'bg-orange-100 text-orange-800 border-orange-200';
      case 'Medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'Low': return 'bg-green-100 text-green-800 border-green-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 flex items-center gap-3">
          <Lock className="text-purple-600" />
          WAF Bypass Tool
        </h1>
        <p className="text-lg text-muted-foreground">
          Advanced Web Application Firewall bypass techniques and payload encoding
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-5 h-5" />
              WAF Bypass Configuration
            </CardTitle>
            <CardDescription>
              Configure your Web Application Firewall bypass testing
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="payload">Original Payload</Label>
              <Textarea
                id="payload"
                placeholder="<script>alert('XSS')</script> or ' OR 1=1--"
                value={payload}
                onChange={(e) => setPayload(e.target.value)}
                rows={3}
              />
            </div>

            <div>
              <Label htmlFor="targetUrl">Target URL (Optional)</Label>
              <Input
                id="targetUrl"
                placeholder="https://example.com/vulnerable-endpoint"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
              />
            </div>

            <div>
              <Label htmlFor="bypassType">Bypass Technique</Label>
              <Select value={bypassType} onValueChange={setBypassType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="comprehensive">All Techniques</SelectItem>
                  <SelectItem value="encoding">Encoding Methods</SelectItem>
                  <SelectItem value="obfuscation">Obfuscation</SelectItem>
                  <SelectItem value="case-manipulation">Case Manipulation</SelectItem>
                  <SelectItem value="comment-insertion">Comment Insertion</SelectItem>
                  <SelectItem value="unicode">Unicode Bypass</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="wafType">WAF Type</Label>
              <Select value={wafType} onValueChange={setWafType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="auto-detect">Auto Detect</SelectItem>
                  <SelectItem value="cloudflare">Cloudflare</SelectItem>
                  <SelectItem value="aws-waf">AWS WAF</SelectItem>
                  <SelectItem value="mod-security">ModSecurity</SelectItem>
                  <SelectItem value="imperva">Imperva</SelectItem>
                  <SelectItem value="akamai">Akamai</SelectItem>
                  <SelectItem value="generic">Generic WAF</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <Button 
              onClick={handleBypass} 
              disabled={loading}
              className="w-full"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Generating WAF Bypasses...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  Generate WAF Bypasses
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
          </CardContent>
        </Card>

        {results && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="w-5 h-5" />
                WAF Bypass Results
              </CardTitle>
              <CardDescription>
                Web Application Firewall bypass analysis completed
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="payloads">Bypasses</TabsTrigger>
                  <TabsTrigger value="recommendations">Defense</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-blue-600">
                        {results.totalTechniques}
                      </div>
                      <div className="text-sm text-gray-600">Techniques Tested</div>
                    </div>
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-green-600">
                        {results.bypassesFound}
                      </div>
                      <div className="text-sm text-gray-600">Successful Bypasses</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium">Detected WAF:</span>
                      <Badge className="bg-blue-100 text-blue-800">
                        {results.detectedWAF}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="font-medium">Bypass Success Rate:</span>
                      <Badge className={getRiskColor(results.riskLevel)}>
                        {Math.round((results.bypassesFound / results.totalTechniques) * 100)}%
                      </Badge>
                    </div>
                  </div>

                  {results.bypassTechniques.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Effective Techniques:</h4>
                      <div className="flex flex-wrap gap-2">
                        {results.bypassTechniques.map((technique, index) => (
                          <Badge key={index} className="bg-green-100 text-green-800">
                            {technique}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="payloads" className="space-y-4">
                  <div className="max-h-96 overflow-y-auto space-y-2">
                    {results.detailedResults.map((result, index) => (
                      <div
                        key={index}
                        className={`p-3 rounded-lg border ${
                          result.success 
                            ? 'border-green-200 bg-green-50' 
                            : 'border-gray-200 bg-gray-50'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex gap-2">
                            <Badge 
                              className={result.success ? 'bg-green-600' : 'bg-gray-600'}
                            >
                              {result.technique}
                            </Badge>
                            <Badge className="bg-blue-100 text-blue-800">
                              {result.method}
                            </Badge>
                          </div>
                          <Badge className={result.success ? 'bg-green-100 text-green-800' : 'bg-red-100 text-red-800'}>
                            {result.success ? 'BYPASS' : 'BLOCKED'}
                          </Badge>
                        </div>
                        <div className="space-y-2">
                          <div className="font-mono text-sm bg-white p-2 rounded border">
                            <strong>Original:</strong> {result.originalPayload}
                          </div>
                          <div className="font-mono text-sm bg-white p-2 rounded border">
                            <strong>Bypassed:</strong> {result.payload}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="recommendations" className="space-y-4">
                  {results.recommendations.map((rec, index) => (
                    <Alert key={index}>
                      <Shield className="h-4 w-4" />
                      <AlertDescription>{rec}</AlertDescription>
                    </Alert>
                  ))}
                </TabsContent>
              </Tabs>
            </CardContent>
          </Card>
        )}
      </div>

      {/* Educational Information */}
      <Card className="mt-6">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Code className="w-5 h-5" />
            WAF Bypass Techniques
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold mb-2">Common Bypass Methods:</h4>
              <ul className="space-y-1 text-sm">
                <li>• <strong>Encoding:</strong> URL, HTML, Unicode encoding</li>
                <li>• <strong>Case Manipulation:</strong> Mixed case variations</li>
                <li>• <strong>Comment Insertion:</strong> SQL/HTML comments</li>
                <li>• <strong>String Fragmentation:</strong> Breaking payloads</li>
                <li>• <strong>Obfuscation:</strong> Code obfuscation techniques</li>
                <li>• <strong>Alternative Syntax:</strong> Different payload formats</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">WAF Defense Strategies:</h4>
              <ul className="space-y-1 text-sm">
                <li>• Regular rule updates and tuning</li>
                <li>• Multi-layer security approach</li>
                <li>• Behavioral analysis and machine learning</li>
                <li>• Rate limiting and IP reputation</li>
                <li>• Custom rules for application-specific attacks</li>
                <li>• Continuous monitoring and alerting</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
