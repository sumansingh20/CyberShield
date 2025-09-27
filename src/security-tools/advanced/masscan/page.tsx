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
import { Loader2, Shield, AlertTriangle, Target, Zap, Network, Clock } from 'lucide-react';

interface MasscanResult {
  targets: string;
  portsScanned: string;
  scanRate: number;
  totalHosts: number;
  totalPorts: number;
  openPorts: {
    host: string;
    port: number;
    protocol: string;
    service: string;
    state: string;
    timestamp: string;
  }[];
  scanStatistics: {
    hostsScanned: number;
    portsScanned: number;
    packetsTransmitted: number;
    packetsReceived: number;
    timeElapsed: string;
    averageRate: number;
  };
  topPorts: { port: number; protocol: string; count: number; service: string }[];
  hostSummary: { host: string; openPorts: number; services: string[] }[];
  recommendations: string[];
}

export default function MasscanTool() {
  const [targets, setTargets] = useState('');
  const [ports, setPorts] = useState('80,443,22,21,25,53,110,993,995,143');
  const [scanRate, setScanRate] = useState('1000');
  const [scanType, setScanType] = useState('syn');
  const [excludeHosts, setExcludeHosts] = useState('');
  const [results, setResults] = useState<MasscanResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const [progress, setProgress] = useState(0);

  const handleScan = async () => {
    if (!targets.trim()) {
      setError('Please enter target hosts or IP ranges');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);
    setProgress(0);

    // Simulate progress updates
    const progressInterval = setInterval(() => {
      setProgress(prev => Math.min(prev + Math.random() * 10, 90));
    }, 500);

    try {
      const response = await fetch('/api/tools/masscan', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targets: targets.trim(),
          ports: ports.trim(),
          rate: parseInt(scanRate),
          scanType,
          excludeHosts: excludeHosts.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to perform Masscan');
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

  const getServiceColor = (service: string) => {
    switch (service.toLowerCase()) {
      case 'http': case 'https': return 'bg-blue-100 text-blue-800';
      case 'ssh': return 'bg-green-100 text-green-800';
      case 'ftp': return 'bg-orange-100 text-orange-800';
      case 'smtp': return 'bg-purple-100 text-purple-800';
      case 'dns': return 'bg-cyan-100 text-cyan-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 flex items-center gap-3">
          <Target className="text-orange-600" />
          Masscan - High-Speed Port Scanner
        </h1>
        <p className="text-lg text-muted-foreground">
          Ultra-fast port scanner capable of scanning the entire Internet in under 6 minutes
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Zap className="w-5 h-5" />
              Scan Configuration
            </CardTitle>
            <CardDescription>
              Configure your high-speed port scanning parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="targets">Target Hosts/Networks</Label>
              <Textarea
                id="targets"
                placeholder="192.168.1.0/24&#10;10.0.0.1-10.0.0.255&#10;scanme.nmap.org"
                value={targets}
                onChange={(e) => setTargets(e.target.value)}
                rows={4}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Enter IP addresses, CIDR ranges, or hostnames (one per line)
              </p>
            </div>

            <div>
              <Label htmlFor="ports">Ports to Scan</Label>
              <Input
                id="ports"
                placeholder="80,443,22,21,25,53,110,993,995,143"
                value={ports}
                onChange={(e) => setPorts(e.target.value)}
              />
              <p className="text-xs text-muted-foreground mt-1">
                Comma-separated ports or ranges (e.g., 1-1000,8080,9000-9100)
              </p>
            </div>

            <div>
              <Label htmlFor="scanRate">Scan Rate (packets/second)</Label>
              <Select value={scanRate} onValueChange={setScanRate}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="100">100 (Very Slow)</SelectItem>
                  <SelectItem value="1000">1,000 (Slow)</SelectItem>
                  <SelectItem value="10000">10,000 (Normal)</SelectItem>
                  <SelectItem value="100000">100,000 (Fast)</SelectItem>
                  <SelectItem value="1000000">1,000,000 (Very Fast)</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">
                Higher rates = faster scans but may cause packet loss
              </p>
            </div>

            <div>
              <Label htmlFor="scanType">Scan Type</Label>
              <Select value={scanType} onValueChange={setScanType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="syn">SYN Scan (Stealth)</SelectItem>
                  <SelectItem value="connect">Connect Scan</SelectItem>
                  <SelectItem value="ack">ACK Scan</SelectItem>
                  <SelectItem value="window">Window Scan</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div>
              <Label htmlFor="excludeHosts">Exclude Hosts (Optional)</Label>
              <Input
                id="excludeHosts"
                placeholder="192.168.1.1,10.0.0.1"
                value={excludeHosts}
                onChange={(e) => setExcludeHosts(e.target.value)}
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
                  Scanning...
                </>
              ) : (
                <>
                  <Target className="mr-2 h-4 w-4" />
                  Start Masscan
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
                <Network className="w-5 h-5" />
                Scan Results
              </CardTitle>
              <CardDescription>
                High-speed port scan completed
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="overview" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="overview">Overview</TabsTrigger>
                  <TabsTrigger value="ports">Open Ports</TabsTrigger>
                  <TabsTrigger value="hosts">Host Summary</TabsTrigger>
                  <TabsTrigger value="stats">Statistics</TabsTrigger>
                </TabsList>

                <TabsContent value="overview" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-blue-600">
                        {results.totalHosts}
                      </div>
                      <div className="text-sm text-gray-600">Hosts Scanned</div>
                    </div>
                    <div className="text-center p-4 bg-gray-50 rounded-lg">
                      <div className="text-2xl font-bold text-green-600">
                        {results.openPorts.length}
                      </div>
                      <div className="text-sm text-gray-600">Open Ports</div>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-3">Top Services Found:</h4>
                    <div className="space-y-2">
                      {results.topPorts.slice(0, 5).map((portInfo, index) => (
                        <div key={index} className="flex items-center justify-between p-3 bg-gray-50 rounded-lg">
                          <div className="flex items-center gap-3">
                            <Badge className={getServiceColor(portInfo.service)}>
                              {portInfo.port}/{portInfo.protocol}
                            </Badge>
                            <span className="font-medium">{portInfo.service}</span>
                          </div>
                          <Badge variant="outline">
                            {portInfo.count} hosts
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2">Scan Performance:</h4>
                    <div className="grid grid-cols-2 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Average Rate:</span>
                        <div className="font-mono">{results.scanStatistics.averageRate.toLocaleString()} pps</div>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Time Elapsed:</span>
                        <div className="font-mono">{results.scanStatistics.timeElapsed}</div>
                      </div>
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="ports" className="space-y-4">
                  <div className="max-h-96 overflow-y-auto space-y-2">
                    {results.openPorts.map((port, index) => (
                      <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-sm">{port.host}</span>
                          <Badge className={getServiceColor(port.service)}>
                            {port.port}/{port.protocol}
                          </Badge>
                          <span className="text-sm">{port.service}</span>
                        </div>
                        <div className="text-right">
                          <Badge variant="outline" className="mb-1">
                            {port.state}
                          </Badge>
                          <div className="text-xs text-muted-foreground">
                            <Clock className="w-3 h-3 inline mr-1" />
                            {port.timestamp}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="hosts" className="space-y-4">
                  <div className="max-h-96 overflow-y-auto space-y-3">
                    {results.hostSummary.map((host, index) => (
                      <div key={index} className="p-4 border rounded-lg">
                        <div className="flex items-center justify-between mb-3">
                          <span className="font-mono font-medium">{host.host}</span>
                          <Badge className="bg-blue-100 text-blue-800">
                            {host.openPorts} open ports
                          </Badge>
                        </div>
                        <div className="flex flex-wrap gap-2">
                          {host.services.map((service, serviceIndex) => (
                            <Badge key={serviceIndex} variant="outline" className="text-xs">
                              {service}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    ))}
                  </div>
                </TabsContent>

                <TabsContent value="stats" className="space-y-4">
                  <div className="grid grid-cols-2 gap-4">
                    <div className="space-y-3">
                      <div>
                        <div className="text-sm text-muted-foreground">Hosts Scanned</div>
                        <div className="text-2xl font-bold">{results.scanStatistics.hostsScanned.toLocaleString()}</div>
                      </div>
                      <div>
                        <div className="text-sm text-muted-foreground">Ports Scanned</div>
                        <div className="text-2xl font-bold">{results.scanStatistics.portsScanned.toLocaleString()}</div>
                      </div>
                    </div>
                    <div className="space-y-3">
                      <div>
                        <div className="text-sm text-muted-foreground">Packets Sent</div>
                        <div className="text-2xl font-bold">{results.scanStatistics.packetsTransmitted.toLocaleString()}</div>
                      </div>
                      <div>
                        <div className="text-sm text-muted-foreground">Packets Received</div>
                        <div className="text-2xl font-bold">{results.scanStatistics.packetsReceived.toLocaleString()}</div>
                      </div>
                    </div>
                  </div>

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
            <Target className="w-5 h-5" />
            About Masscan
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold mb-2">Key Features:</h4>
              <ul className="space-y-1 text-sm">
                <li>• <strong>Ultra-fast:</strong> Can scan the entire Internet in under 6 minutes</li>
                <li>• <strong>Asynchronous:</strong> Uses its own TCP/IP stack for maximum speed</li>
                <li>• <strong>Flexible:</strong> Supports various scan types and protocols</li>
                <li>• <strong>Scalable:</strong> Can handle millions of IP addresses</li>
                <li>• <strong>Customizable:</strong> Configurable scan rates and exclusions</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Best Practices:</h4>
              <ul className="space-y-1 text-sm">
                <li>• Start with lower scan rates to avoid overwhelming networks</li>
                <li>• Use exclusion lists to avoid scanning critical infrastructure</li>
                <li>• Be mindful of network bandwidth and firewall rules</li>
                <li>• Always obtain proper authorization before scanning</li>
                <li>• Consider legal and ethical implications of large-scale scanning</li>
              </ul>
            </div>
          </div>

          <Alert className="mt-4">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>
              <strong>Warning:</strong> Masscan is extremely powerful and can generate massive amounts of network traffic. 
              Use responsibly and only scan networks you own or have explicit permission to test.
            </AlertDescription>
          </Alert>
        </CardContent>
      </Card>
    </div>
  );
}
