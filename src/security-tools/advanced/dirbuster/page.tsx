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
import { Progress } from '@/src/ui/components/ui/progress';
import { Loader2, Shield, AlertTriangle, Terminal, FolderOpen, Search, Clock } from 'lucide-react';

interface DirBusterResult {
  targetUrl: string;
  wordlistUsed: string;
  directoriesFound: string[];
  filesFound: string[];
  totalRequests: number;
  successfulRequests: number;
  timeElapsed: string;
  statusCodes: { [key: string]: number };
  interestingFindings: {
    path: string;
    statusCode: number;
    size: number;
    contentType: string;
    reason: string;
  }[];
  hiddenDirectories: string[];
  backupFiles: string[];
  configFiles: string[];
  recommendations: string[];
}

export default function DirBusterTool() {
  const [targetUrl, setTargetUrl] = useState('');
  const [wordlist, setWordlist] = useState('common');
  const [customWordlist, setCustomWordlist] = useState('');
  const [fileExtensions, setFileExtensions] = useState('php,asp,jsp,html,txt,bak,old');
  const [threads, setThreads] = useState('10');
  const [maxDepth, setMaxDepth] = useState('3');
  const [results, setResults] = useState<DirBusterResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);

  const handleBust = async () => {
    if (!targetUrl.trim()) {
      setError('Please enter a target URL');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);
    setProgress(0);

    // Simulate progress
    const progressInterval = setInterval(() => {
      setProgress(prev => Math.min(prev + Math.random() * 5, 90));
    }, 1000);

    try {
      const response = await fetch('/api/tools/dirbuster', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetUrl: targetUrl.trim(),
          wordlist,
          customWordlist: customWordlist.trim(),
          fileExtensions: fileExtensions.trim(),
          threads: parseInt(threads),
          maxDepth: parseInt(maxDepth),
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to perform directory busting');
      }

      const data = await response.json();
      setResults(data);
      setProgress(100);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      clearInterval(progressInterval);
      setLoading(false);
    }
  };

  const getStatusColor = (statusCode: number) => {
    if (statusCode >= 200 && statusCode < 300) return 'bg-green-100 text-green-800';
    if (statusCode >= 300 && statusCode < 400) return 'bg-yellow-100 text-yellow-800';
    if (statusCode >= 400 && statusCode < 500) return 'bg-orange-100 text-orange-800';
    if (statusCode >= 500) return 'bg-red-100 text-red-800';
    return 'bg-gray-100 text-gray-800';
  };

  const getSeverityColor = (reason: string) => {
    if (reason.includes('sensitive') || reason.includes('config')) return 'border-red-200 bg-red-50';
    if (reason.includes('backup') || reason.includes('old')) return 'border-orange-200 bg-orange-50';
    if (reason.includes('admin') || reason.includes('login')) return 'border-yellow-200 bg-yellow-50';
    return 'border-blue-200 bg-blue-50';
  };

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 flex items-center gap-3">
          <Terminal className="text-pink-600" />
          Directory Buster
        </h1>
        <p className="text-lg text-muted-foreground">
          Discover hidden directories and files using intelligent brute-force techniques
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="w-5 h-5" />
              Brute Force Configuration
            </CardTitle>
            <CardDescription>
              Configure directory and file discovery parameters
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
              <Label htmlFor="wordlist">Wordlist Type</Label>
              <Select value={wordlist} onValueChange={setWordlist}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="common">Common Directories</SelectItem>
                  <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
                  <SelectItem value="small">Small & Fast</SelectItem>
                  <SelectItem value="medium">Medium Coverage</SelectItem>
                  <SelectItem value="large">Large & Thorough</SelectItem>
                  <SelectItem value="admin">Admin Panels</SelectItem>
                  <SelectItem value="backup">Backup Files</SelectItem>
                  <SelectItem value="config">Configuration Files</SelectItem>
                  <SelectItem value="custom">Custom Wordlist</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {wordlist === 'custom' && (
              <div>
                <Label htmlFor="customWordlist">Custom Wordlist</Label>
                <Textarea
                  id="customWordlist"
                  placeholder="admin&#10;backup&#10;config&#10;test&#10;dev"
                  value={customWordlist}
                  onChange={(e) => setCustomWordlist(e.target.value)}
                  rows={6}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Enter one directory/file name per line
                </p>
              </div>
            )}

            <div>
              <Label htmlFor="fileExtensions">File Extensions</Label>
              <Input
                id="fileExtensions"
                placeholder="php,asp,jsp,html,txt,bak,old"
                value={fileExtensions}
                onChange={(e) => setFileExtensions(e.target.value)}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Comma-separated extensions to append to directory names
              </p>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="threads">Concurrent Threads</Label>
                <Select value={threads} onValueChange={setThreads}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="5">5 (Slow)</SelectItem>
                    <SelectItem value="10">10 (Normal)</SelectItem>
                    <SelectItem value="20">20 (Fast)</SelectItem>
                    <SelectItem value="50">50 (Aggressive)</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="maxDepth">Max Directory Depth</Label>
                <Select value={maxDepth} onValueChange={setMaxDepth}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="1">1 Level</SelectItem>
                    <SelectItem value="2">2 Levels</SelectItem>
                    <SelectItem value="3">3 Levels</SelectItem>
                    <SelectItem value="5">5 Levels</SelectItem>
                    <SelectItem value="10">10 Levels</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            <Button 
              onClick={handleBust} 
              disabled={loading}
              className="w-full"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Directory Busting...
                </>
              ) : (
                <>
                  <FolderOpen className="mr-2 h-4 w-4" />
                  Start Directory Buster
                </>
              )}
            </Button>

            {loading && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Scan Progress</span>
                  <span>{Math.round(progress)}%</span>
                </div>
                <Progress value={progress} className="w-full" />
              </div>
            )}

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
                <FolderOpen className="w-5 h-5" />
                Discovery Results
              </CardTitle>
              <CardDescription>
                Directory busting completed for {results.targetUrl}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="directories">Directories</TabsTrigger>
                  <TabsTrigger value="files">Files</TabsTrigger>
                  <TabsTrigger value="findings">Findings</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-blue-600">
                        {results.directoriesFound.length}
                      </div>
                      <div className="text-sm text-gray-600">Directories</div>
                    </div>
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-green-600">
                        {results.filesFound.length}
                      </div>
                      <div className="text-sm text-gray-600">Files</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium">Total Requests:</span>
                      <Badge className="bg-blue-100 text-blue-800">
                        {results.totalRequests}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="font-medium">Successful:</span>
                      <Badge className="bg-green-100 text-green-800">
                        {results.successfulRequests}
                      </Badge>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="font-medium">Time Elapsed:</span>
                      <Badge className="bg-purple-100 text-purple-800">
                        <Clock className="w-3 h-3 mr-1" />
                        {results.timeElapsed}
                      </Badge>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2">Response Codes:</h4>
                    <div className="flex flex-wrap gap-2">
                      {Object.entries(results.statusCodes).map(([code, count]) => (
                        <Badge key={code} className={getStatusColor(parseInt(code))}>
                          {code}: {count}
                        </Badge>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="directories" className="space-y-4">
                  <div className="max-h-96 overflow-y-auto space-y-2">
                    {results.directoriesFound.map((dir, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-blue-50 rounded-lg border">
                        <div className="flex items-center gap-2">
                          <FolderOpen className="w-4 h-4 text-blue-600" />
                          <span className="font-mono text-sm">{dir}</span>
                        </div>
                        <Badge className="bg-blue-100 text-blue-800">Directory</Badge>
                      </div>
                    ))}
                  </div>

                  {results.hiddenDirectories.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2 text-orange-600">Hidden Directories:</h4>
                      <div className="space-y-1">
                        {results.hiddenDirectories.map((dir, index) => (
                          <div key={index} className="text-sm bg-orange-50 p-2 rounded border-l-4 border-orange-400 font-mono">
                            {dir}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="files" className="space-y-4">
                  <div className="max-h-96 overflow-y-auto space-y-2">
                    {results.filesFound.map((file, index) => (
                      <div key={index} className="flex items-center justify-between p-3 bg-green-50 rounded-lg border">
                        <div className="flex items-center gap-2">
                          <Search className="w-4 h-4 text-green-600" />
                          <span className="font-mono text-sm">{file}</span>
                        </div>
                        <Badge className="bg-green-100 text-green-800">File</Badge>
                      </div>
                    ))}
                  </div>

                  {results.backupFiles.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2 text-orange-600">⚠️ Backup Files:</h4>
                      <div className="space-y-1">
                        {results.backupFiles.map((file, index) => (
                          <div key={index} className="text-sm bg-orange-50 p-2 rounded border-l-4 border-orange-400 font-mono">
                            {file}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {results.configFiles.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2 text-red-600">🔥 Configuration Files:</h4>
                      <div className="space-y-1">
                        {results.configFiles.map((file, index) => (
                          <div key={index} className="text-sm bg-red-50 p-2 rounded border-l-4 border-red-400 font-mono">
                            {file}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="findings" className="space-y-4">
                  {results.interestingFindings.map((finding, index) => (
                    <div
                      key={index}
                      className={`p-4 rounded-lg border ${getSeverityColor(finding.reason)}`}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-mono text-sm font-medium">{finding.path}</span>
                        <div className="flex gap-2">
                          <Badge className={getStatusColor(finding.statusCode)}>
                            {finding.statusCode}
                          </Badge>
                          <Badge className="bg-gray-100 text-gray-800">
                            {finding.size} bytes
                          </Badge>
                        </div>
                      </div>
                      <div className="text-sm text-gray-600 mb-2">
                        Content-Type: {finding.contentType}
                      </div>
                      <div className="text-sm font-medium">
                        {finding.reason}
                      </div>
                    </div>
                  ))}

                  {results.recommendations.length > 0 && (
                    <div>
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
            <Terminal className="w-5 h-5" />
            About Directory Busting
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold mb-2">Common Targets:</h4>
              <ul className="space-y-1 text-sm">
                <li>• <strong>/admin:</strong> Administrative interfaces</li>
                <li>• <strong>/backup:</strong> Backup files and archives</li>
                <li>• <strong>/config:</strong> Configuration files</li>
                <li>• <strong>/test:</strong> Test environments</li>
                <li>• <strong>/dev:</strong> Development directories</li>
                <li>• <strong>/.git:</strong> Git repositories</li>
                <li>• <strong>/old:</strong> Old versions and files</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Detection Methods:</h4>
              <ul className="space-y-1 text-sm">
                <li>• HTTP response code analysis</li>
                <li>• Content length variations</li>
                <li>• Response time patterns</li>
                <li>• Custom error page detection</li>
                <li>• Recursive directory traversal</li>
                <li>• File extension enumeration</li>
                <li>• Fuzzing with common patterns</li>
              </ul>
            </div>
          </div>

          <Alert>
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              <strong>Ethical Use Only:</strong> Directory busting should only be performed on systems you own 
              or have explicit permission to test. Unauthorized scanning may violate terms of service or local laws.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    </div>
  );
}
