"use client"

import { useState } from "react"
import { useAuth } from "@/contexts/AuthContext"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs"
import { ArrowLeft, Shield, Search, Globe, Code, Wifi, Lock, Smartphone, HardDrive, Hash, Zap, Target, Cloud, Package } from "lucide-react"
import Link from "next/link"

interface Tool {
  name: string
  description: string
  path: string
  icon: React.ReactNode
  category: "basic" | "advanced" | "expert"
  tags: string[]
}

const tools: Tool[] = [
  // Basic Tools
  {
    name: "DNS Lookup",
    description: "Perform DNS queries to retrieve domain information and records",
    path: "/tools/dns-lookup",
    icon: <Globe className="h-6 w-6" />,
    category: "basic",
    tags: ["DNS", "Domain", "Network"]
  },
  {
    name: "WHOIS Lookup",
    description: "Get domain registration and ownership information",
    path: "/tools/whois",
    icon: <Search className="h-6 w-6" />,
    category: "basic",
    tags: ["WHOIS", "Domain", "OSINT"]
  },
  {
    name: "HTTP Headers",
    description: "Analyze HTTP response headers for security information",
    path: "/tools/http-headers",
    icon: <Globe className="h-6 w-6" />,
    category: "basic",
    tags: ["HTTP", "Headers", "Web"]
  },
  {
    name: "Port Scanner",
    description: "Scan for open ports on target systems",
    path: "/tools/port-scanner",
    icon: <Target className="h-6 w-6" />,
    category: "basic",
    tags: ["Ports", "Network", "Nmap"]
  },
  {
    name: "Subdomain Enumeration",
    description: "Discover subdomains of a target domain",
    path: "/tools/subdomain-enum",
    icon: <Search className="h-6 w-6" />,
    category: "basic",
    tags: ["Subdomain", "Reconnaissance", "DNS"]
  },
  {
    name: "Network Scanner",
    description: "Comprehensive network scanning and host discovery",
    path: "/tools/network-scan",
    icon: <Shield className="h-6 w-6" />,
    category: "basic",
    tags: ["Network", "Discovery", "Nmap"]
  },
  {
    name: "Vulnerability Scanner",
    description: "Scan for common vulnerabilities in web applications",
    path: "/tools/vuln-scanner",
    icon: <Shield className="h-6 w-6" />,
    category: "basic",
    tags: ["Vulnerability", "Web", "Security"]
  },
  {
    name: "Nmap Scanner",
    description: "Network exploration and advanced port scanning",
    path: "/tools/nmap",
    icon: <Target className="h-6 w-6" />,
    category: "basic",
    tags: ["Nmap", "Network", "Port Scan"]
  },
  {
    name: "DNS Resolver",
    description: "Advanced DNS record lookup and analysis",
    path: "/tools/dns",
    icon: <Globe className="h-6 w-6" />,
    category: "basic",
    tags: ["DNS", "Records", "Network"]
  },
  {
    name: "Subdomain Discovery",
    description: "Discover subdomains using multiple enumeration techniques",
    path: "/tools/subdomain",
    icon: <Search className="h-6 w-6" />,
    category: "basic",
    tags: ["Subdomain", "Discovery", "Reconnaissance"]
  },

  // Advanced Tools
  {
    name: "Directory Buster",
    description: "Brute force directories and files on web servers",
    path: "/tools/advanced/directory-buster",
    icon: <Search className="h-6 w-6" />,
    category: "advanced",
    tags: ["Directory", "Brute Force", "Web"]
  },
  {
    name: "OSINT Toolkit",
    description: "Open Source Intelligence gathering tools",
    path: "/tools/advanced/osint-toolkit",
    icon: <Search className="h-6 w-6" />,
    category: "advanced",
    tags: ["OSINT", "Intelligence", "Reconnaissance"]
  },
  {
    name: "Wireless Security",
    description: "Wireless network security testing and analysis",
    path: "/tools/advanced/wireless-security",
    icon: <Wifi className="h-6 w-6" />,
    category: "advanced",
    tags: ["Wireless", "WiFi", "Network"]
  },
  {
    name: "Social Engineering",
    description: "Social engineering toolkit and techniques",
    path: "/tools/advanced/social-engineering",
    icon: <Shield className="h-6 w-6" />,
    category: "advanced",
    tags: ["Social Engineering", "Phishing", "SET"]
  },
  {
    name: "Mobile Security",
    description: "Mobile application security analysis",
    path: "/tools/advanced/mobile-security",
    icon: <Smartphone className="h-6 w-6" />,
    category: "advanced",
    tags: ["Mobile", "APK", "Security"]
  },
  {
    name: "Digital Forensics",
    description: "Digital forensics and evidence analysis",
    path: "/tools/advanced/digital-forensics",
    icon: <HardDrive className="h-6 w-6" />,
    category: "advanced",
    tags: ["Forensics", "Analysis", "Evidence"]
  },
  {
    name: "Cryptography",
    description: "Cryptographic analysis and hash cracking",
    path: "/tools/advanced/cryptography",
    icon: <Hash className="h-6 w-6" />,
    category: "advanced",
    tags: ["Cryptography", "Hash", "Encryption"]
  },
  {
    name: "Masscan",
    description: "High-speed port scanner for large networks",
    path: "/tools/advanced/masscan",
    icon: <Zap className="h-6 w-6" />,
    category: "advanced",
    tags: ["Masscan", "Port Scan", "Network"]
  },

  // Expert Tools
  {
    name: "Metasploit",
    description: "Advanced exploitation framework",
    path: "/tools/expert/metasploit",
    icon: <Target className="h-6 w-6" />,
    category: "expert",
    tags: ["Metasploit", "Exploitation", "Framework"]
  },
  {
    name: "Burp Suite",
    description: "Web application security testing platform",
    path: "/tools/expert/burp-suite",
    icon: <Globe className="h-6 w-6" />,
    category: "expert",
    tags: ["Burp Suite", "Web", "Proxy"]
  },
  {
    name: "Binary Analysis",
    description: "Binary reverse engineering and analysis",
    path: "/tools/expert/binary-analysis",
    icon: <Code className="h-6 w-6" />,
    category: "expert",
    tags: ["Binary", "Reverse Engineering", "Analysis"]
  },
  {
    name: "Network Analysis",
    description: "Advanced network traffic analysis",
    path: "/tools/expert/network-analysis",
    icon: <Shield className="h-6 w-6" />,
    category: "expert",
    tags: ["Network", "Traffic", "Analysis"]
  },
  {
    name: "Cloud Security",
    description: "Cloud infrastructure security assessment",
    path: "/tools/expert/cloud-security",
    icon: <Cloud className="h-6 w-6" />,
    category: "expert",
    tags: ["Cloud", "AWS", "Security"]
  },
  {
    name: "Container Security",
    description: "Docker and container security scanning",
    path: "/tools/expert/container-security",
    icon: <Package className="h-6 w-6" />,
    category: "expert",
    tags: ["Container", "Docker", "Security"]
  }
]

function ToolCard({ tool }: { tool: Tool }) {
  const getCategoryColor = (category: string) => {
    switch (category) {
      case "basic": return "bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200"
      case "advanced": return "bg-yellow-100 text-yellow-800 dark:bg-yellow-900 dark:text-yellow-200"
      case "expert": return "bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200"
      default: return "bg-gray-100 text-gray-800 dark:bg-gray-900 dark:text-gray-200"
    }
  }

  return (
    <Link href={tool.path} className="block h-full">
      <Card className="h-full hover:shadow-lg transition-shadow duration-200 cursor-pointer border-2 hover:border-primary/50">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <div className="p-2 bg-primary/10 rounded-lg">
                {tool.icon}
              </div>
              <div>
                <CardTitle className="text-lg">{tool.name}</CardTitle>
                <Badge className={getCategoryColor(tool.category)}>
                  {tool.category.charAt(0).toUpperCase() + tool.category.slice(1)}
                </Badge>
              </div>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <CardDescription className="text-sm mb-3 line-clamp-2">
            {tool.description}
          </CardDescription>
          <div className="flex flex-wrap gap-1">
            {tool.tags.slice(0, 3).map((tag) => (
              <Badge key={tag} variant="outline" className="text-xs">
                {tag}
              </Badge>
            ))}
            {tool.tags.length > 3 && (
              <Badge variant="outline" className="text-xs">
                +{tool.tags.length - 3}
              </Badge>
            )}
          </div>
        </CardContent>
      </Card>
    </Link>
  )
}

export default function ToolsPage() {
  const { isAuthenticated } = useAuth()
  const [searchTerm, setSearchTerm] = useState("")

  if (!isAuthenticated) {
    return null
  }

  const filteredTools = tools.filter(tool =>
    tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    tool.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
    tool.tags.some(tag => tag.toLowerCase().includes(searchTerm.toLowerCase()))
  )

  const basicTools = filteredTools.filter(tool => tool.category === "basic")
  const advancedTools = filteredTools.filter(tool => tool.category === "advanced")
  const expertTools = filteredTools.filter(tool => tool.category === "expert")

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-4">
      <div className="container mx-auto max-w-7xl">
        {/* Header */}
        <div className="mb-8 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <Link href="/dashboard">
              <Button variant="outline" size="sm">
                <ArrowLeft className="h-4 w-4 mr-2" />
                Back to Dashboard
              </Button>
            </Link>
            <div>
              <h1 className="text-4xl font-bold text-white">Penetration Testing Tools</h1>
              <p className="text-slate-300 mt-2">
                Comprehensive cybersecurity toolkit for penetration testing and security analysis
              </p>
            </div>
          </div>
        </div>

        {/* Search */}
        <div className="mb-6">
          <div className="relative max-w-md">
            <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 h-4 w-4" />
            <input
              type="text"
              placeholder="Search tools..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="w-full pl-10 pr-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-primary focus:border-transparent dark:bg-slate-800 dark:border-slate-600 dark:text-white"
            />
          </div>
        </div>

        {/* Stats */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-8">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Total Tools</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{tools.length}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Basic Tools</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{tools.filter(t => t.category === "basic").length}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Advanced Tools</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-yellow-600">{tools.filter(t => t.category === "advanced").length}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Expert Tools</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-red-600">{tools.filter(t => t.category === "expert").length}</div>
            </CardContent>
          </Card>
        </div>

        {/* Tools Grid */}
        <Tabs defaultValue="all" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="all">All Tools ({filteredTools.length})</TabsTrigger>
            <TabsTrigger value="basic">Basic ({basicTools.length})</TabsTrigger>
            <TabsTrigger value="advanced">Advanced ({advancedTools.length})</TabsTrigger>
            <TabsTrigger value="expert">Expert ({expertTools.length})</TabsTrigger>
          </TabsList>

          <TabsContent value="all" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {filteredTools.map((tool) => (
                <ToolCard key={tool.path} tool={tool} />
              ))}
            </div>
          </TabsContent>

          <TabsContent value="basic" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {basicTools.map((tool) => (
                <ToolCard key={tool.path} tool={tool} />
              ))}
            </div>
          </TabsContent>

          <TabsContent value="advanced" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {advancedTools.map((tool) => (
                <ToolCard key={tool.path} tool={tool} />
              ))}
            </div>
          </TabsContent>

          <TabsContent value="expert" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {expertTools.map((tool) => (
                <ToolCard key={tool.path} tool={tool} />
              ))}
            </div>
          </TabsContent>
        </Tabs>

        {filteredTools.length === 0 && (
          <div className="text-center py-12">
            <Search className="h-12 w-12 text-gray-400 mx-auto mb-4" />
            <h3 className="text-lg font-medium text-gray-900 dark:text-white mb-2">No tools found</h3>
            <p className="text-gray-500 dark:text-gray-400">Try adjusting your search terms.</p>
          </div>
        )}
      </div>
    </div>
  )
}
