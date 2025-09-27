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
import { Loader2, Shield, AlertTriangle, Zap, Target, Terminal, Database } from 'lucide-react';

interface MetasploitResult {
  sessionId: string;
  targetInfo: {
    host: string;
    os: string;
    architecture: string;
    services: { port: number; service: string; version: string }[];
  };
  exploitUsed: {
    name: string;
    description: string;
    reliability: string;
    rank: string;
    targets: string[];
  };
  payloadInfo: {
    name: string;
    description: string;
    platform: string;
    architecture: string;
  };
  sessionDetails: {
    type: string;
    user: string;
    privileges: string;
    systemInfo: string;
    networkInfo: string[];
  };
  postExploitation: {
    filesAccessed: string[];
    commandsExecuted: string[];
    dataExfiltrated: { type: string; size: string; description: string }[];
    persistenceMethods: string[];
  };
  recommendations: string[];
  mitigations: string[];
}

export default function MetasploitTool() {
  const [targetHost, setTargetHost] = useState('');
  const [targetPort, setTargetPort] = useState('');
  const [exploitModule, setExploitModule] = useState('');
  const [payloadType, setPayloadType] = useState('windows/meterpreter/reverse_tcp');
  const [lhost, setLhost] = useState('');
  const [lport, setLport] = useState('4444');
  const [sessionAction, setSessionAction] = useState('');
  const [customCommand, setCustomCommand] = useState('');
  const [results, setResults] = useState<MetasploitResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  const handleExploit = async () => {
    if (!targetHost.trim()) {
      setError('Please enter a target host');
      return;
    }

    setLoading(true);
    setError('');
    setResults(null);

    try {
      const response = await fetch('/api/tools/metasploit', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          targetHost: targetHost.trim(),
          targetPort: targetPort.trim(),
          exploitModule: exploitModule.trim(),
          payloadType,
          lhost: lhost.trim(),
          lport: lport.trim(),
          sessionAction: sessionAction.trim(),
          customCommand: customCommand.trim(),
        }),
      });

      if (!response.ok) {
        throw new Error('Failed to execute Metasploit operation');
      }

      const data = await response.json();
      setResults(data);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred');
    } finally {
      setLoading(false);
    }
  };

  const getRankColor = (rank: string) => {
    switch (rank.toLowerCase()) {
      case 'excellent': return 'bg-green-100 text-green-800';
      case 'great': return 'bg-blue-100 text-blue-800';
      case 'good': return 'bg-yellow-100 text-yellow-800';
      case 'normal': return 'bg-orange-100 text-orange-800';
      case 'low': return 'bg-red-100 text-red-800';
      default: return 'bg-gray-100 text-gray-800';
    }
  };

  const getPrivilegeColor = (privilege: string) => {
    if (privilege.toLowerCase().includes('system') || privilege.toLowerCase().includes('admin')) {
      return 'bg-red-100 text-red-800';
    }
    if (privilege.toLowerCase().includes('user')) {
      return 'bg-blue-100 text-blue-800';
    }
    return 'bg-gray-100 text-gray-800';
  };

  return (
    <div className="container mx-auto p-6 max-w-6xl">
      <div className="mb-8">
        <h1 className="text-4xl font-bold mb-4 flex items-center gap-3">
          <Zap className="text-red-600" />
          Metasploit Framework
        </h1>
        <p className="text-lg text-muted-foreground">
          Advanced exploitation framework for penetration testing and security research
        </p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Target className="w-5 h-5" />
              Exploit Configuration
            </CardTitle>
            <CardDescription>
              Configure your Metasploit exploitation parameters
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="targetHost">Target Host</Label>
                <Input
                  id="targetHost"
                  placeholder="192.168.1.100"
                  value={targetHost}
                  onChange={(e) => setTargetHost(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="targetPort">Target Port</Label>
                <Input
                  id="targetPort"
                  placeholder="445"
                  value={targetPort}
                  onChange={(e) => setTargetPort(e.target.value)}
                />
              </div>
            </div>

            <div>
              <Label htmlFor="exploitModule">Exploit Module</Label>
              <Select value={exploitModule} onValueChange={setExploitModule}>
                <SelectTrigger>
                  <SelectValue placeholder="Select exploit module" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows/smb/ms17_010_eternalblue">MS17-010 EternalBlue</SelectItem>
                  <SelectItem value="windows/smb/ms08_067_netapi">MS08-067 NetAPI</SelectItem>
                  <SelectItem value="linux/samba/is_known_pipename">Samba Is_Known_Pipename</SelectItem>
                  <SelectItem value="multi/handler">Multi Handler (Listener)</SelectItem>
                  <SelectItem value="unix/webapp/php_include">PHP Include</SelectItem>
                  <SelectItem value="windows/browser/ie_createobject">IE CreateObject</SelectItem>
                  <SelectItem value="linux/http/apache_mod_cgi_bash_env_exec">Apache mod_cgi Bash</SelectItem>
                  <SelectItem value="custom">Custom Module</SelectItem>
                </SelectContent>
              </Select>
              {exploitModule === 'custom' && (
                <Input
                  className="mt-2"
                  placeholder="exploit/windows/smb/ms17_010_eternalblue"
                  onChange={(e) => setExploitModule(e.target.value)}
                />
              )}
            </div>

            <div>
              <Label htmlFor="payloadType">Payload Type</Label>
              <Select value={payloadType} onValueChange={setPayloadType}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows/meterpreter/reverse_tcp">Windows Meterpreter Reverse TCP</SelectItem>
                  <SelectItem value="linux/x86/meterpreter/reverse_tcp">Linux Meterpreter Reverse TCP</SelectItem>
                  <SelectItem value="windows/shell/reverse_tcp">Windows Shell Reverse TCP</SelectItem>
                  <SelectItem value="linux/x86/shell_reverse_tcp">Linux Shell Reverse TCP</SelectItem>
                  <SelectItem value="windows/vncinject/reverse_tcp">Windows VNC Inject</SelectItem>
                  <SelectItem value="java/meterpreter/reverse_tcp">Java Meterpreter</SelectItem>
                  <SelectItem value="php/meterpreter_reverse_tcp">PHP Meterpreter</SelectItem>
                </SelectContent>
              </Select>
            </div>

            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label htmlFor="lhost">Local Host (LHOST)</Label>
                <Input
                  id="lhost"
                  placeholder="192.168.1.50"
                  value={lhost}
                  onChange={(e) => setLhost(e.target.value)}
                />
              </div>
              <div>
                <Label htmlFor="lport">Local Port (LPORT)</Label>
                <Input
                  id="lport"
                  placeholder="4444"
                  value={lport}
                  onChange={(e) => setLport(e.target.value)}
                />
              </div>
            </div>

            <div>
              <Label htmlFor="sessionAction">Post-Exploitation Action</Label>
              <Select value={sessionAction} onValueChange={setSessionAction}>
                <SelectTrigger>
                  <SelectValue placeholder="Select action after exploitation" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="sysinfo">Get System Information</SelectItem>
                  <SelectItem value="hashdump">Dump Password Hashes</SelectItem>
                  <SelectItem value="screenshot">Take Screenshot</SelectItem>
                  <SelectItem value="migrate">Migrate Process</SelectItem>
                  <SelectItem value="persistence">Install Persistence</SelectItem>
                  <SelectItem value="enumerate">Enumerate System</SelectItem>
                  <SelectItem value="custom">Custom Command</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {sessionAction === 'custom' && (
              <div>
                <Label htmlFor="customCommand">Custom Meterpreter Command</Label>
                <Textarea
                  id="customCommand"
                  placeholder="getuid&#10;pwd&#10;ls"
                  value={customCommand}
                  onChange={(e) => setCustomCommand(e.target.value)}
                  rows={3}
                />
              </div>
            )}

            <Button 
              onClick={handleExploit} 
              disabled={loading}
              className="w-full"
            >
              {loading ? (
                <>
                  <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                  Exploiting Target...
                </>
              ) : (
                <>
                  <Zap className="mr-2 h-4 w-4" />
                  Launch Exploit
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

            <div className="bg-red-50 border border-red-200 rounded-lg p-4">
              <div className="flex items-center gap-2 text-red-600 mb-2">
                <AlertTriangle className="h-4 w-4" />
                <span className="font-semibold">Authorized Testing Only</span>
              </div>
              <p className="text-sm text-red-700">
                Metasploit should only be used against systems you own or have explicit written permission to test. 
                Unauthorized use is illegal and unethical.
              </p>
            </div>
          </CardContent>
        </Card>

        {results && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Terminal className="w-5 h-5" />
                Exploitation Results
              </CardTitle>
              <CardDescription>
                Session {results.sessionId} established with {results.targetInfo.host}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <Tabs defaultValue="target" className="w-full">
                <TabsList className="grid w-full grid-cols-4">
                  <TabsTrigger value="target">Target Info</TabsTrigger>
                  <TabsTrigger value="exploit">Exploit</TabsTrigger>
                  <TabsTrigger value="session">Session</TabsTrigger>
                  <TabsTrigger value="post">Post-Exploit</TabsTrigger>
                </TabsList>

                <TabsContent value="target" className="space-y-4">
                  <div className="p-4 bg-gray-50 rounded-lg">
                    <h4 className="font-medium mb-3">Target System Information</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="font-medium">Host:</span>
                        <span className="font-mono">{results.targetInfo.host}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="font-medium">OS:</span>
                        <span>{results.targetInfo.os}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="font-medium">Architecture:</span>
                        <span>{results.targetInfo.architecture}</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2">Services Detected:</h4>
                    <div className="space-y-2">
                      {results.targetInfo.services.map((service, index) => (
                        <div key={index} className="flex items-center justify-between p-3 border rounded-lg">
                          <div className="flex items-center gap-3">
                            <Badge className="bg-blue-100 text-blue-800">
                              {service.port}
                            </Badge>
                            <span className="font-medium">{service.service}</span>
                          </div>
                          <span className="text-sm text-gray-600">{service.version}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="exploit" className="space-y-4">
                  <div className="p-4 bg-blue-50 rounded-lg">
                    <h4 className="font-medium mb-3">Exploit Information</h4>
                    <div className="space-y-3">
                      <div>
                        <span className="font-medium">Module:</span>
                        <div className="font-mono text-sm mt-1">{results.exploitUsed.name}</div>
                      </div>
                      <div>
                        <span className="font-medium">Description:</span>
                        <div className="text-sm mt-1">{results.exploitUsed.description}</div>
                      </div>
                      <div className="flex justify-between">
                        <span className="font-medium">Reliability:</span>
                        <Badge className="bg-green-100 text-green-800">
                          {results.exploitUsed.reliability}
                        </Badge>
                      </div>
                      <div className="flex justify-between">
                        <span className="font-medium">Rank:</span>
                        <Badge className={getRankColor(results.exploitUsed.rank)}>
                          {results.exploitUsed.rank}
                        </Badge>
                      </div>
                    </div>
                  </div>

                  <div className="p-4 bg-green-50 rounded-lg">
                    <h4 className="font-medium mb-3">Payload Information</h4>
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="font-medium">Payload:</span>
                        <div className="font-mono mt-1">{results.payloadInfo.name}</div>
                      </div>
                      <div>
                        <span className="font-medium">Platform:</span>
                        <span className="ml-2">{results.payloadInfo.platform}</span>
                      </div>
                      <div>
                        <span className="font-medium">Architecture:</span>
                        <span className="ml-2">{results.payloadInfo.architecture}</span>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2">Compatible Targets:</h4>
                    <div className="space-y-1">
                      {results.exploitUsed.targets.map((target, index) => (
                        <div key={index} className="text-sm bg-gray-50 p-2 rounded font-mono">
                          {target}
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="session" className="space-y-4">
                  <div className="p-4 bg-green-50 rounded-lg">
                    <h4 className="font-medium mb-3">Session Details</h4>
                    <div className="space-y-2 text-sm">
                      <div className="flex justify-between">
                        <span className="font-medium">Session Type:</span>
                        <Badge className="bg-green-100 text-green-800">
                          {results.sessionDetails.type}
                        </Badge>
                      </div>
                      <div className="flex justify-between">
                        <span className="font-medium">User:</span>
                        <span className="font-mono">{results.sessionDetails.user}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="font-medium">Privileges:</span>
                        <Badge className={getPrivilegeColor(results.sessionDetails.privileges)}>
                          {results.sessionDetails.privileges}
                        </Badge>
                      </div>
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2">System Information:</h4>
                    <div className="bg-gray-50 p-3 rounded-lg font-mono text-sm">
                      {results.sessionDetails.systemInfo}
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-2">Network Information:</h4>
                    <div className="space-y-1">
                      {results.sessionDetails.networkInfo.map((info, index) => (
                        <div key={index} className="text-sm bg-blue-50 p-2 rounded font-mono">
                          {info}
                        </div>
                      ))}
                    </div>
                  </div>
                </TabsContent>

                <TabsContent value="post" className="space-y-4">
                  <div>
                    <h4 className="font-medium mb-2">Commands Executed:</h4>
                    <div className="max-h-32 overflow-y-auto space-y-1">
                      {results.postExploitation.commandsExecuted.map((cmd, index) => (
                        <div key={index} className="text-sm bg-gray-50 p-2 rounded font-mono">
                          {cmd}
                        </div>
                      ))}
                    </div>
                  </div>

                  {results.postExploitation.filesAccessed.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Files Accessed:</h4>
                      <div className="max-h-32 overflow-y-auto space-y-1">
                        {results.postExploitation.filesAccessed.map((file, index) => (
                          <div key={index} className="text-sm bg-yellow-50 p-2 rounded font-mono">
                            {file}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {results.postExploitation.dataExfiltrated.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2 text-red-600">Data Exfiltrated:</h4>
                      <div className="space-y-2">
                        {results.postExploitation.dataExfiltrated.map((data, index) => (
                          <div key={index} className="bg-red-50 border border-red-200 p-3 rounded-lg">
                            <div className="flex items-center justify-between mb-1">
                              <span className="font-medium">{data.type}</span>
                              <Badge className="bg-red-100 text-red-800">{data.size}</Badge>
                            </div>
                            <div className="text-sm text-gray-600">{data.description}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {results.postExploitation.persistenceMethods.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Persistence Methods:</h4>
                      <div className="space-y-1">
                        {results.postExploitation.persistenceMethods.map((method, index) => (
                          <div key={index} className="text-sm bg-orange-50 p-2 rounded">
                            {method}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </TabsContent>
              </Tabs>

              {(results.recommendations.length > 0 || results.mitigations.length > 0) && (
                <div className="mt-6 space-y-4">
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

                  {results.mitigations.length > 0 && (
                    <div>
                      <h4 className="font-medium mb-2">Mitigation Strategies:</h4>
                      <div className="space-y-2">
                        {results.mitigations.map((mit, index) => (
                          <Alert key={index} className="border-green-200 bg-green-50">
                            <Shield className="h-4 w-4" />
                            <AlertDescription className="text-green-800">{mit}</AlertDescription>
                          </Alert>
                        ))}
                      </div>
                    </div>
                  )}
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
            <Database className="w-5 h-5" />
            About Metasploit Framework
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid md:grid-cols-2 gap-6">
            <div>
              <h4 className="font-semibold mb-2">Core Components:</h4>
              <ul className="space-y-1 text-sm">
                <li>• <strong>Exploits:</strong> Code that takes advantage of vulnerabilities</li>
                <li>• <strong>Payloads:</strong> Code executed after successful exploitation</li>
                <li>• <strong>Encoders:</strong> Obfuscate payloads to evade detection</li>
                <li>• <strong>NOPs:</strong> No-operation instructions for buffer alignment</li>
                <li>• <strong>Auxiliaries:</strong> Scanning, fuzzing, and DoS modules</li>
                <li>• <strong>Post-exploitation:</strong> Modules for post-compromise activities</li>
              </ul>
            </div>
            <div>
              <h4 className="font-semibold mb-2">Responsible Usage:</h4>
              <ul className="space-y-1 text-sm">
                <li>• Only test systems you own or have permission for</li>
                <li>• Document all activities for compliance and reporting</li>
                <li>• Follow a structured penetration testing methodology</li>
                <li>• Ensure proper cleanup after testing is complete</li>
                <li>• Stay updated with the latest modules and techniques</li>
                <li>• Coordinate with system administrators when appropriate</li>
              </ul>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
