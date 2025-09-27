"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Terminal, Shield, Target, Zap, AlertTriangle, Play, Search, Settings } from "lucide-react"

interface ExploitModule {
  name: string
  description: string
  platform: string
  type: string
  rank: "Excellent" | "Great" | "Good" | "Normal" | "Average" | "Low"
}

interface PayloadOption {
  name: string
  description: string
  platform: string
  architecture: string
}

interface Session {
  id: string
  type: string
  host: string
  user: string
  status: "Active" | "Dead"
}

export default function MetasploitPage() {
  const [selectedModule, setSelectedModule] = useState<ExploitModule | null>(null)
  const [targetHost, setTargetHost] = useState("")
  const [targetPort, setTargetPort] = useState("")
  const [selectedPayload, setSelectedPayload] = useState("")
  const [isRunning, setIsRunning] = useState(false)
  const [consoleOutput, setConsoleOutput] = useState<string[]>([])
  const [sessions, setSessions] = useState<Session[]>([])
  const [activeTab, setActiveTab] = useState("exploits")

  const exploitModules: ExploitModule[] = [
    {
      name: "exploit/windows/smb/ms17_010_eternalblue",
      description: "MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption",
      platform: "Windows",
      type: "exploit",
      rank: "Excellent"
    },
    {
      name: "exploit/multi/handler",
      description: "Generic Payload Handler",
      platform: "Multi",
      type: "exploit",
      rank: "Excellent"
    },
    {
      name: "exploit/linux/http/apache_struts_rce",
      description: "Apache Struts 2 Content-Type Remote Command Execution",
      platform: "Linux",
      type: "exploit",
      rank: "Great"
    },
    {
      name: "exploit/windows/rdp/cve_2019_0708_bluekeep",
      description: "BlueKeep RDP Remote Windows Kernel Use After Free",
      platform: "Windows",
      type: "exploit",
      rank: "Good"
    }
  ]

  const payloadOptions: PayloadOption[] = [
    {
      name: "windows/x64/meterpreter/reverse_tcp",
      description: "Windows Meterpreter (Reflective Injection x64), Reverse TCP Stager",
      platform: "Windows",
      architecture: "x64"
    },
    {
      name: "linux/x64/shell/reverse_tcp",
      description: "Linux Command Shell, Reverse TCP Stager",
      platform: "Linux",
      architecture: "x64"
    },
    {
      name: "generic/shell_reverse_tcp",
      description: "Generic Command Shell, Reverse TCP Inline",
      platform: "Generic",
      architecture: "Generic"
    },
    {
      name: "windows/meterpreter/reverse_https",
      description: "Windows Meterpreter (Reflective Injection), Reverse HTTPS Stager",
      platform: "Windows",
      architecture: "x86"
    }
  ]

  const mockSessions: Session[] = [
    { id: "1", type: "meterpreter", host: "192.168.1.100", user: "SYSTEM", status: "Active" },
    { id: "2", type: "shell", host: "10.0.0.50", user: "www-data", status: "Active" },
    { id: "3", type: "meterpreter", host: "172.16.1.10", user: "Administrator", status: "Dead" }
  ]

  const handleModuleSelect = (module: ExploitModule) => {
    setSelectedModule(module)
    addConsoleOutput(`msf6 > use ${module.name}`)
    addConsoleOutput(`[*] Using configured payload ${selectedPayload || 'generic/shell_reverse_tcp'}`)
  }

  const addConsoleOutput = (output: string) => {
    setConsoleOutput(prev => [...prev, output])
  }

  const handleExploit = async () => {
    if (!selectedModule || !targetHost) return

    setIsRunning(true)
    
    addConsoleOutput(`msf6 exploit(${selectedModule.name.split('/').pop()}) > set RHOSTS ${targetHost}`)
    addConsoleOutput(`RHOSTS => ${targetHost}`)
    
    if (targetPort) {
      addConsoleOutput(`msf6 exploit(${selectedModule.name.split('/').pop()}) > set RPORT ${targetPort}`)
      addConsoleOutput(`RPORT => ${targetPort}`)
    }
    
    addConsoleOutput(`msf6 exploit(${selectedModule.name.split('/').pop()}) > exploit`)
    addConsoleOutput(`[*] Started reverse TCP handler on 0.0.0.0:4444`)
    
    // Simulate exploitation process
    await new Promise(resolve => setTimeout(resolve, 2000))
    addConsoleOutput(`[*] ${targetHost}:${targetPort || '445'} - Connecting to target for exploitation.`)
    
    await new Promise(resolve => setTimeout(resolve, 1500))
    addConsoleOutput(`[*] ${targetHost}:${targetPort || '445'} - Built a write-what-where primitive...`)
    
    await new Promise(resolve => setTimeout(resolve, 1000))
    addConsoleOutput(`[+] ${targetHost}:${targetPort || '445'} - Overwrite complete... SYSTEM`)
    
    await new Promise(resolve => setTimeout(resolve, 500))
    addConsoleOutput(`[*] Sending stage (175174 bytes) to ${targetHost}`)
    addConsoleOutput(`[*] Meterpreter session 4 opened (192.168.1.5:4444 -> ${targetHost}:49152)`)
    
    // Add new session
    const newSession: Session = {
      id: "4",
      type: "meterpreter",
      host: targetHost,
      user: "SYSTEM",
      status: "Active"
    }
    
    setSessions(prev => [newSession, ...prev])
    setIsRunning(false)
  }

  const getRankColor = (rank: string) => {
    switch (rank) {
      case "Excellent": return "text-green-700 bg-green-100 border-green-200"
      case "Great": return "text-blue-700 bg-blue-100 border-blue-200"
      case "Good": return "text-yellow-700 bg-yellow-100 border-yellow-200"
      case "Normal": return "text-orange-700 bg-orange-100 border-orange-200"
      default: return "text-gray-700 bg-gray-100 border-gray-200"
    }
  }

  const getStatusColor = (status: string) => {
    return status === "Active" 
      ? "text-green-700 bg-green-100 border-green-200"
      : "text-red-700 bg-red-100 border-red-200"
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-red-50 to-pink-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 p-4">
      <div className="container mx-auto max-w-7xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-3">
            <div className="p-3 rounded-xl bg-gradient-to-br from-red-600 to-pink-600 text-white shadow-xl">
              <Target className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-red-600 to-pink-600 bg-clip-text text-transparent">
                Metasploit Framework
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Professional penetration testing and exploit development platform
              </p>
            </div>
          </div>
          
          <div className="flex items-center justify-center space-x-4">
            <Badge className="bg-red-500/10 text-red-600 border-red-200 dark:border-red-800">
              <Shield className="w-3 h-3 mr-1" />
              Expert Level
            </Badge>
            <Badge className="bg-pink-500/10 text-pink-600 border-pink-200 dark:border-pink-800">
              <Target className="w-3 h-3 mr-1" />
              Exploitation Framework
            </Badge>
            <Badge className="bg-orange-500/10 text-orange-600 border-orange-200 dark:border-orange-800">
              <AlertTriangle className="w-3 h-3 mr-1" />
              Use Responsibly
            </Badge>
          </div>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="exploits">Exploits</TabsTrigger>
            <TabsTrigger value="payloads">Payloads</TabsTrigger>
            <TabsTrigger value="sessions">Sessions</TabsTrigger>
            <TabsTrigger value="console">Console</TabsTrigger>
          </TabsList>

          <TabsContent value="exploits" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Exploit Selection */}
              <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Search className="h-5 w-5" />
                    Exploit Modules
                  </CardTitle>
                  <CardDescription>
                    Select and configure exploit modules
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-3">
                    {exploitModules.map((module, index) => (
                      <div 
                        key={index} 
                        className={`p-3 rounded-lg border cursor-pointer transition-all ${
                          selectedModule?.name === module.name 
                            ? 'bg-red-50 border-red-200 dark:bg-red-900/20 dark:border-red-800' 
                            : 'bg-white/50 hover:bg-gray-50 dark:bg-slate-700/50 dark:hover:bg-slate-700'
                        }`}
                        onClick={() => handleModuleSelect(module)}
                      >
                        <div className="flex items-start justify-between mb-2">
                          <div className="font-mono text-sm font-semibold truncate">
                            {module.name}
                          </div>
                          <Badge className={getRankColor(module.rank)}>
                            {module.rank}
                          </Badge>
                        </div>
                        <div className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                          {module.description}
                        </div>
                        <div className="flex items-center space-x-2">
                          <Badge variant="outline" className="text-xs">
                            {module.platform}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {module.type}
                          </Badge>
                        </div>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>

              {/* Target Configuration */}
              <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Settings className="h-5 w-5" />
                    Target Configuration
                  </CardTitle>
                  <CardDescription>
                    Configure target and payload options
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="target-host">Target Host (RHOSTS)</Label>
                    <Input
                      id="target-host"
                      value={targetHost}
                      onChange={(e) => setTargetHost(e.target.value)}
                      placeholder="192.168.1.100"
                      disabled={isRunning}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="target-port">Target Port (RPORT)</Label>
                    <Input
                      id="target-port"
                      value={targetPort}
                      onChange={(e) => setTargetPort(e.target.value)}
                      placeholder="445"
                      disabled={isRunning}
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="payload">Payload</Label>
                    <Select value={selectedPayload} onValueChange={setSelectedPayload}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select payload..." />
                      </SelectTrigger>
                      <SelectContent>
                        {payloadOptions.map((payload, index) => (
                          <SelectItem key={index} value={payload.name}>
                            {payload.name}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  {selectedModule && (
                    <div className="p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                      <div className="text-sm font-semibold mb-1">Selected Module:</div>
                      <div className="text-xs font-mono text-blue-600 dark:text-blue-400">
                        {selectedModule.name}
                      </div>
                    </div>
                  )}

                  <Button 
                    onClick={handleExploit} 
                    disabled={!selectedModule || !targetHost || isRunning}
                    className="w-full"
                  >
                    {isRunning ? (
                      <>
                        <Terminal className="mr-2 h-4 w-4 animate-spin" />
                        Exploiting...
                      </>
                    ) : (
                      <>
                        <Play className="mr-2 h-4 w-4" />
                        Launch Exploit
                      </>
                    )}
                  </Button>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="payloads" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Available Payloads
                </CardTitle>
                <CardDescription>
                  Payload modules for different platforms and architectures
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {payloadOptions.map((payload, index) => (
                    <div key={index} className="p-4 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                      <div className="flex items-start justify-between mb-2">
                        <div className="font-mono text-sm font-semibold">
                          {payload.name}
                        </div>
                        <div className="flex space-x-2">
                          <Badge variant="outline" className="text-xs">
                            {payload.platform}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {payload.architecture}
                          </Badge>
                        </div>
                      </div>
                      <div className="text-sm text-gray-600 dark:text-gray-400">
                        {payload.description}
                      </div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="sessions" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Terminal className="h-5 w-5" />
                  Active Sessions
                </CardTitle>
                <CardDescription>
                  Manage compromised systems and established sessions
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {sessions.length > 0 ? sessions.map((session) => (
                    <div key={session.id} className="p-4 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center space-x-4">
                          <Badge className="bg-blue-100 text-blue-700 border-blue-200">
                            Session {session.id}
                          </Badge>
                          <div>
                            <div className="font-semibold">{session.host}</div>
                            <div className="text-sm text-gray-600 dark:text-gray-400">
                              {session.type} - {session.user}
                            </div>
                          </div>
                        </div>
                        <Badge className={getStatusColor(session.status)}>
                          {session.status}
                        </Badge>
                      </div>
                    </div>
                  )) : (
                    <div className="text-center py-8 text-gray-500">
                      <Terminal className="h-8 w-8 mx-auto mb-2 opacity-50" />
                      <p>No active sessions</p>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="console" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Terminal className="h-5 w-5" />
                  Metasploit Console
                </CardTitle>
                <CardDescription>
                  Command output and framework messages
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="bg-black rounded-lg p-4 h-96 overflow-y-auto font-mono text-sm">
                  <div className="text-green-400">
                    msf6 &gt; 
                  </div>
                  {consoleOutput.map((line, index) => (
                    <div key={index} className="text-gray-300">
                      {line}
                    </div>
                  ))}
                  {isRunning && (
                    <div className="text-yellow-400 animate-pulse">
                      [*] Exploitation in progress...
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}