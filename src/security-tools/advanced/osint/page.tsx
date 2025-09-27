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
import { Loader2, Shield, AlertTriangle, Eye, Search, Globe, Mail, Users, MapPin } from 'lucide-react';

interface OSINTResult {
  target: string;
  toolsUsed: string[];
  emails: {
    email: string;
    source: string;
    verified: boolean;
    domain: string;
  }[];
  domains: {
    domain: string;
    registrar: string;
    created: string;
    expires: string;
    nameservers: string[];
  }[];
  subdomains: {
    subdomain: string;
    ip: string;
    status: string;
    technologies: string[];
  }[];
  socialMedia: {
    platform: string;
    username: string;
    url: string;
    followers?: number;
    verified: boolean;
  }[];
  ipInformation: {
    ip: string;
    country: string;
    city: string;
    organization: string;
    isp: string;
    services: string[];
  }[];
  technologies: {
    category: string;
    technology: string;
    version?: string;
    confidence: number;
  }[];
  breaches: {
    name: string;
    date: string;
    accounts: number;
    dataTypes: string[];
  }[];
  metadata: {
    searchTime: string;
    totalSources: number;
    confidence: 'Low' | 'Medium' | 'High';
  };
  recommendations: string[];
}

export default function OSINTTool() {
  const [target, setTarget] = useState('');
  const [searchType, setSearchType] = useState('domain');
  const [tools, setTools] = useState(['theHarvester', 'shodan']);
  const [deepScan, setDeepScan] = useState(false);
  const [results, setResults] = useState<OSINTResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleInvestigation = async () => {
    if (!target.trim()) {
      setError('Please enter a target to investigate');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await fetch('/api/tools/osint', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          target: target.trim(),
          searchType,
          tools,
          deepScan,
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to perform OSINT investigation');
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getConfidenceColor = (confidence: string) => {
    switch (confidence) {
      case 'High': return 'bg-green-100 text-green-800 border-green-200';
      case 'Medium': return 'bg-yellow-100 text-yellow-800 border-yellow-200';
      case 'Low': return 'bg-red-100 text-red-800 border-red-200';
      default: return 'bg-gray-100 text-gray-800 border-gray-200';
    }
  };

  const getVerificationColor = (verified: boolean) => {
    return verified ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 flex items-center gap-3">
          <Eye className="text-indigo-600" />
          OSINT Toolkit
        </h1>
        <p className="text-lg text-muted-foreground">
          Comprehensive Open Source Intelligence gathering using TheHarvester, Shodan, and other tools
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="w-5 h-5" />
              Investigation Configuration
            </CardTitle>
            <CardDescription>
              Configure your OSINT gathering parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="target">Target</Label>
              <Input
                id="target"
                placeholder="example.com, 192.168.1.1, or john@company.com"
                value={target}
                onChange={(e) => setTarget(e.target.value)}
              />
            </div>

            <div>
              <Label htmlFor="searchType">Search Type</Label>
              <Select value={searchType} onValueChange={setSearchType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="domain">Domain Investigation</SelectItem>
                  <SelectItem value="email">Email Investigation</SelectItem>
                  <SelectItem value="ip">IP Address Investigation</SelectItem>
                  <SelectItem value="company">Company Investigation</SelectItem>
                  <SelectItem value="person">Person Investigation</SelectItem>
                  <SelectItem value="comprehensive">Comprehensive Scan</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label>OSINT Tools to Use</Label>
              <div className="space-y-2">
                {[
                  { id: 'theHarvester', name: 'theHarvester', desc: 'Email and subdomain harvesting' },
                  { id: 'shodan', name: 'Shodan', desc: 'Internet-connected device search' },
                  { id: 'whois', name: 'WHOIS', desc: 'Domain registration information' },
                  { id: 'dnsenum', name: 'DNSEnum', desc: 'DNS enumeration and brute forcing' },
                  { id: 'maltego', name: 'Maltego CE', desc: 'Link analysis and data mining' },
                  { id: 'spiderfoot', name: 'SpiderFoot', desc: 'Automated OSINT collection' },
                ].map((tool) => (
                  <div key={tool.id} className="flex items-center space-x-2">
                    <input
                      type="checkbox"
                      id={tool.id}
                      checked={tools.includes(tool.id)}
                      onChange={(e) => {
                        if (e.target.checked) {
                          setTools([...tools, tool.id]);
                        } else {
                          setTools(tools.filter(t => t !== tool.id));
                        }
                      }}
                      className="rounded"
                    />
                    <div className="flex-1">
                      <Label htmlFor={tool.id} className="font-medium">{tool.name}</Label>
                      <p className="text-xs text-muted-foreground">{tool.desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>

            <div className="flex items-center space-x-2">
              <input
                type="checkbox"
                id="deepScan"
                checked={deepScan}
                onChange={(e) => setDeepScan(e.target.checked)}
                className="rounded"
              />
              <Label htmlFor="deepScan">Deep Scan (Longer, more thorough investigation)</Label>
            </div>

            <Button 
              onClick={handleInvestigation} 
              disabled={loading}
              className="w-full"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Investigating...
                </>
              ) : (
                <>
                  <Eye className="mr-2 h-4 w-4" />
                  Start OSINT Investigation
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

            <div className="bg-blue-50 border border-blue-200 rounded-lg p-4">
              <div className="flex items-center gap-2 text-blue-600 mb-2">
                <Shield className="h-4 w-4" />
                <span className="font-semibold">Legal Notice</span>
              </div>
              <p className="text-sm text-blue-700">
                OSINT gathering should only be performed on targets you own or have explicit permission to investigate. 
                Respect privacy laws and terms of service when conducting investigations.
              </p>
            </div>
          </CardContent>
        </Card>

        {results && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Globe className="w-5 h-5" />
                Investigation Results
              </CardTitle>
              <CardDescription>
                OSINT investigation completed for {results.target}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="emails">Emails</TabsTrigger>
                  <TabsTrigger value="domains">Domains</TabsTrigger>
                  <TabsTrigger value="social">Social</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-blue-600">
                        {results.emails.length}
                      </div>
                      <div className="text-sm text-gray-600">Emails Found</div>
                    </div>
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-green-600">
                        {results.subdomains.length}
                      </div>
                      <div className="text-sm text-gray-600">Subdomains</div>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <div className="flex items-center justify-between">
                      <span className="font-medium">Search Time:</span>
                      <Badge className="bg-purple-100 text-purple-800">
                        {results.metadata.searchTime}
                      </Badge>
                    </div>
                    
                    <div className="flex items-center justify-between">
                      <span className="font-medium">Sources Used:</span>
                      <Badge className="bg-blue-100 text-blue-800">
                        {results.metadata.totalSources}
                      </Badge>
                    </div>

                    <div className="flex items-center justify-between">
                      <span className="font-medium">Confidence Level:</span>
                      <Badge className={getConfidenceColor(results.metadata.confidence)}>
                        {results.metadata.confidence}
                      </Badge>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2">Tools Used:</h4>
                    <div className="flex flex-wrap gap-2">
                      {results.toolsUsed.map((tool, index) => (
                        <Badge key={index} className="bg-indigo-100 text-indigo-800">
                          {tool}
                        </Badge>
                      ))}
                    </div>
                  </div>

                  {results.technologies.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Technologies Detected:</h4>
                      <div className="space-y-1">
                        {results.technologies.slice(0, 5).map((tech, index) => (
                          <div key={index} className="flex items-center justify-between text-sm bg-gray-50 p-2 rounded">
                            <span>{tech.technology} {tech.version && `(${tech.version})`}</span>
                            <Badge className="bg-gray-100 text-gray-800 text-xs">
                              {tech.confidence}%
                            </Badge>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="emails" className="space-y-4">
                  <div className="max-h-96 overflow-y-auto space-y-3">
                    {results.emails.map((email, index) => (
                      <div key={index} className="p-3 border rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <span className="font-mono text-sm">{email.email}</span>
                          <div className="flex gap-2">
                            <Badge className={getVerificationColor(email.verified)}>
                              {email.verified ? 'Verified' : 'Unverified'}
                            </Badge>
                          </div>
                        </div>
                        <div className="flex justify-between text-xs text-gray-600">
                          <span>Domain: {email.domain}</span>
                          <span>Source: {email.source}</span>
                        </div>
                      </div>
                    ))}
                  </div>

                  {results.breaches.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2 text-red-600">⚠️ Data Breaches Found:</h4>
                      <div className="space-y-2">
                        {results.breaches.map((breach, index) => (
                          <div key={index} className="bg-red-50 border border-red-200 p-3 rounded-lg">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-medium">{breach.name}</span>
                              <Badge className="bg-red-100 text-red-800">
                                {breach.accounts.toLocaleString()} accounts
                              </Badge>
                            </div>
                            <div className="text-sm text-gray-600">
                              <div>Date: {breach.date}</div>
                              <div>Data Types: {breach.dataTypes.join(', ')}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>

                <TabsContent value="domains" className="space-y-4">
                  <div className="space-y-4">
                    {results.domains.map((domain, index) => (
                      <div key={index} className="p-4 border rounded-lg">
                        <div className="flex items-center justify-between mb-3">
                          <span className="font-mono font-medium">{domain.domain}</span>
                          <Badge className="bg-blue-100 text-blue-800">Domain</Badge>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-sm">
                          <div>Registrar: {domain.registrar}</div>
                          <div>Created: {domain.created}</div>
                          <div>Expires: {domain.expires}</div>
                          <div>Nameservers: {domain.nameservers.length}</div>
                        </div>
                      </div>
                    ))}
                  </div>

                  <div>
                    <h4 className="font-medium mb-2">Subdomains ({results.subdomains.length}):</h4>
                    <div className="max-h-64 overflow-y-auto space-y-2">
                      {results.subdomains.map((sub, index) => (
                        <div key={index} className="p-3 bg-gray-50 rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <span className="font-mono text-sm">{sub.subdomain}</span>
                            <Badge className="bg-gray-100 text-gray-800">
                              {sub.status}
                            </Badge>
                          </div>
                          <div className="flex justify-between text-xs text-gray-600">
                            <span>IP: {sub.ip}</span>
                            <span>Tech: {sub.technologies.join(', ')}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="social" className="space-y-4">
                  <div className="max-h-96 overflow-y-auto space-y-3">
                    {results.socialMedia.map((social, index) => (
                      <div key={index} className="p-3 border rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Users className="w-4 h-4" />
                            <span className="font-medium">{social.platform}</span>
                          </div>
                          <div className="flex gap-2">
                            {social.verified && (
                              <Badge className="bg-blue-100 text-blue-800">Verified</Badge>
                            )}
                            {social.followers && (
                              <Badge className="bg-gray-100 text-gray-800">
                                {social.followers.toLocaleString()} followers
                              </Badge>
                            )}
                          </div>
                        </div>
                        <div className="text-sm">
                          <div>Username: @{social.username}</div>
                          <div className="text-blue-600 hover:underline">
                            <a href={social.url} target="_blank" rel="noopener noreferrer">
                              {social.url}
                            </a>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>

                  {results.ipInformation.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">IP Information:</h4>
                      <div className="space-y-2">
                        {results.ipInformation.map((ip, index) => (
                          <div key={index} className="p-3 bg-gray-50 rounded-lg">
                            <div className="flex items-center justify-between mb-2">
                              <span className="font-mono">{ip.ip}</span>
                              <div className="flex items-center gap-1 text-sm text-gray-600">
                                <MapPin className="w-3 h-3" />
                                {ip.city}, {ip.country}
                              </div>
                            </div>
                            <div className="text-sm text-gray-600">
                              <div>Organization: {ip.organization}</div>
                              <div>ISP: {ip.isp}</div>
                              <div>Services: {ip.services.join(', ')}</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>
              </Tabs>

              {results.recommendations.length > 0 && (
                <div className="mt-4">
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
            <Eye className="w-5 h-5" />
            About OSINT
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold mb-2">OSINT Sources:</h4>
              <ul className="space-y-1 text-sm">
                <li>• <strong>Search Engines:</strong> Google, Bing, DuckDuckGo</li>
                <li>• <strong>Social Media:</strong> LinkedIn, Twitter, Facebook</li>
                <li>• <strong>Domain Records:</strong> WHOIS, DNS, Certificate logs</li>
                <li>• <strong>Archives:</strong> Wayback Machine, cached pages</li>
                <li>• <strong>Code Repositories:</strong> GitHub, GitLab, Bitbucket</li>
                <li>• <strong>Breach Databases:</strong> HaveIBeenPwned, breaches</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Investigation Process:</h4>
              <ul className="space-y-1 text-sm">
                <li>• <strong>Planning:</strong> Define scope and objectives</li>
                <li>• <strong>Collection:</strong> Gather data from multiple sources</li>
                <li>• <strong>Processing:</strong> Filter and organize information</li>
                <li>• <strong>Analysis:</strong> Connect dots and identify patterns</li>
                <li>• <strong>Reporting:</strong> Document findings and recommendations</li>
                <li>• <strong>Verification:</strong> Cross-reference and validate data</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
