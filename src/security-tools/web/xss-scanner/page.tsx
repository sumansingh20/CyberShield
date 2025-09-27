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
import { Loader2, Shield, AlertTriangle, Code, Bug, Zap } from 'lucide-react';

interface XSSResult {
  vulnerable: boolean;
  payloadsTested: number;
  successfulPayloads: string[];
  vulnerabilityType: string[];
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  recommendations: string[];
  detailedResults: {
    payload: string;
    context: string;
    vulnerable: boolean;
    type: string;
    location: string;
  }[];
}

export default function XSSVulnerabilityScanner() {
  const [url, setUrl] = useState('');
  const [customPayload, setCustomPayload] = useState('');
  const [testType, setTestType] = useState('comprehensive');
  const [inputFields, setInputFields] = useState('');
  const [results, setResults] = useState<XSSResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleTest = async () => {
    if (!url.trim()) {
      setError('Please enter a target URL');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await fetch('/api/tools/xss-scanner', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url.trim(),
          testType,
          inputFields: inputFields.trim(),
          customPayload: customPayload.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to perform XSS vulnerability scan');
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
          <Bug className="text-orange-600" />
          XSS Vulnerability Scanner
        </h1>
        <p className="text-lg text-muted-foreground">
          Advanced Cross-Site Scripting (XSS) vulnerability detection and analysis tool
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-5 h-5" />
              XSS Scanner Configuration
            </CardTitle>
            <CardDescription>
              Configure your Cross-Site Scripting vulnerability assessment
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="url">Target URL</Label>
              <Input
                id="url"
                placeholder="https://example.com/search.php"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>

            <div>
              <Label htmlFor="testType">XSS Test Type</Label>
              <Select value={testType} onValueChange={setTestType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
                  <SelectItem value="reflected">Reflected XSS</SelectItem>
                  <SelectItem value="stored">Stored XSS</SelectItem>
                  <SelectItem value="dom">DOM-based XSS</SelectItem>
                  <SelectItem value="blind">Blind XSS</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="inputFields">Input Fields to Test (comma-separated)</Label>
              <Input
                id="inputFields"
                placeholder="search, comment, username"
                value={inputFields}
                onChange={(e) => setInputFields(e.target.value)}
              />
            </div>

            <div>
              <Label htmlFor="customPayload">Custom XSS Payload (Optional)</Label>
              <Textarea
                id="customPayload"
                placeholder="<script>alert('XSS')</script>"
                value={customPayload}
                onChange={(e) => setCustomPayload(e.target.value)}
                rows={3}
              />
            </div>

            <Button 
              onClick={handleTest} 
              disabled={loading}
              className="w-full"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Scanning for XSS Vulnerabilities...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  Start XSS Vulnerability Scan
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
                <Bug className="w-5 h-5" />
                XSS Vulnerability Results
              </CardTitle>
              <CardDescription>
                Cross-Site Scripting assessment completed
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="grid w-full grid-cols-3">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="payloads">Payloads</TabsTrigger>
                  <TabsTrigger value="recommendations">Fix</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-blue-600">
                        {results.payloadsTested}
                      </div>
                      <div className="text-sm text-gray-600">Payloads Tested</div>
                    </div>
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-red-600">
                        {results.successfulPayloads.length}
                      </div>
                      <div className="text-sm text-gray-600">XSS Vulnerabilities</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium">Vulnerability Status:</span>
                      <Badge className={results.vulnerable ? 'bg-red-100 text-red-800' : 'bg-green-100 text-green-800'}>
                        {results.vulnerable ? 'VULNERABLE' : 'SECURE'}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="font-medium">Risk Level:</span>
                      <Badge className={getRiskColor(results.riskLevel)}>
                        {results.riskLevel}
                      </Badge>
                    </div>
                  </div>

                  {results.vulnerabilityType.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">XSS Types Found:</h4>
                      <div className="flex flex-wrap gap-2">
                        {results.vulnerabilityType.map((type, index) => (
                          <Badge key={index} variant="outline">
                            {type}
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
                          result.vulnerable 
                            ? 'border-red-200 bg-red-50' 
                            : 'border-gray-200 bg-gray-50'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex gap-2">
                            <Badge 
                              className={result.vulnerable ? 'bg-red-600' : 'bg-gray-600'}
                            >
                              {result.type}
                            </Badge>
                            <Badge variant="outline">
                              {result.location}
                            </Badge>
                          </div>
                          <Badge variant="outline">
                            {result.vulnerable ? 'VULNERABLE' : 'BLOCKED'}
                          </Badge>
                        </div>
                        <div className="font-mono text-sm bg-white p-2 rounded border mb-2">
                          {result.payload}
                        </div>
                        {result.context && (
                          <div className="text-sm text-gray-600">
                            <strong>Context:</strong> {result.context}
                          </div>
                        )}
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
            About XSS Vulnerabilities
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold mb-2">XSS Types:</h4>
              <ul className="space-y-1 text-sm">
                <li>• <strong>Reflected XSS:</strong> Non-persistent, executes immediately</li>
                <li>• <strong>Stored XSS:</strong> Persistent, stored in database</li>
                <li>• <strong>DOM-based XSS:</strong> Client-side script manipulation</li>
                <li>• <strong>Blind XSS:</strong> Payload executes in different context</li>
                <li>• <strong>Self XSS:</strong> Requires user interaction</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Prevention Measures:</h4>
              <ul className="space-y-1 text-sm">
                <li>• Input validation and sanitization</li>
                <li>• Output encoding/escaping</li>
                <li>• Content Security Policy (CSP)</li>
                <li>• HTTPOnly cookies</li>
                <li>• X-XSS-Protection headers</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
