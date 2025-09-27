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
import { Loader2, Shield, AlertTriangle, Database, Code, Zap } from 'lucide-react';

interface SQLInjectionResult {
  vulnerable: boolean;
  payloadsTested: number;
  successfulPayloads: string[];
  vulnerabilityType: string[];
  riskLevel: 'Low' | 'Medium' | 'High' | 'Critical';
  recommendations: string[];
  detailedResults: {
    payload: string;
    response: string;
    vulnerable: boolean;
    type: string;
  }[];
}

export default function SQLInjectionTool() {
  const [url, setUrl] = useState('');
  const [customPayload, setCustomPayload] = useState('');
  const [testType, setTestType] = useState('comprehensive');
  const [parameters, setParameters] = useState('');
  const [results, setResults] = useState<SQLInjectionResult | null>(null);
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
      const response = await fetch('/api/tools/sql-injection', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          url: url.trim(),
          testType,
          parameters: parameters.trim(),
          customPayload: customPayload.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to perform SQL injection test');
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
          <Database className="text-red-600" />
          SQL Injection Testing Tool
        </h1>
        <p className="text-lg text-muted-foreground">
          Advanced SQL injection vulnerability scanner with comprehensive payload testing
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-5 h-5" />
              SQL Injection Test Configuration
            </CardTitle>
            <CardDescription>
              Configure your SQL injection vulnerability assessment
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="url">Target URL</Label>
              <Input
                id="url"
                placeholder="https://example.com/login.php"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
              />
            </div>

            <div>
              <Label htmlFor="testType">Test Scope</Label>
              <Select value={testType} onValueChange={setTestType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
                  <SelectItem value="basic">Basic Testing</SelectItem>
                  <SelectItem value="boolean">Boolean-based Blind</SelectItem>
                  <SelectItem value="time">Time-based Blind</SelectItem>
                  <SelectItem value="union">UNION-based</SelectItem>
                  <SelectItem value="error">Error-based</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="parameters">Parameters to Test (comma-separated)</Label>
              <Input
                id="parameters"
                placeholder="id, username, search"
                value={parameters}
                onChange={(e) => setParameters(e.target.value)}
              />
            </div>

            <div>
              <Label htmlFor="customPayload">Custom Payload (Optional)</Label>
              <Textarea
                id="customPayload"
                placeholder="' OR 1=1--"
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
                  Testing for SQL Injection...
                </>
              ) : (
                <>
                  <Shield className="mr-2 h-4 w-4" />
                  Start SQL Injection Test
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
                <Database className="w-5 h-5" />
                SQL Injection Test Results
              </CardTitle>
              <CardDescription>
                Vulnerability assessment completed
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
                      <div className="text-sm text-gray-600">Successful Injections</div>
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
                      <h4 className="font-medium mb-2">Vulnerability Types Found:</h4>
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
                          <Badge 
                            className={result.vulnerable ? 'bg-red-600' : 'bg-gray-600'}
                          >
                            {result.type}
                          </Badge>
                          <Badge variant="outline">
                            {result.vulnerable ? 'VULNERABLE' : 'BLOCKED'}
                          </Badge>
                        </div>
                        <div className="font-mono text-sm bg-white p-2 rounded border">
                          {result.payload}
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
            About SQL Injection Testing
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold mb-2">Common SQL Injection Types:</h4>
              <ul className="space-y-1 text-sm">
                <li>• Union-based SQL Injection</li>
                <li>• Boolean-based Blind SQL Injection</li>
                <li>• Time-based Blind SQL Injection</li>
                <li>• Error-based SQL Injection</li>
                <li>• Stacked Queries</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Prevention Measures:</h4>
              <ul className="space-y-1 text-sm">
                <li>• Use Prepared Statements/Parameterized Queries</li>
                <li>• Input Validation and Sanitization</li>
                <li>• Least Privilege Database Access</li>
                <li>• Web Application Firewalls (WAF)</li>
                <li>• Regular Security Testing</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
