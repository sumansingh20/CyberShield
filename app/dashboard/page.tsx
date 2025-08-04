"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/AuthContext"
import { ThemeToggle } from "@/components/ThemeToggle"
import { DashboardStats } from "@/components/DashboardStats"
import { RecentActivity } from "@/components/RecentActivity"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import {
  Shield,
  Search,
  Info,
  NetworkIcon as Dns,
  FileText,
  LogOut,
  User,
  Activity,
  Zap,
  Target,
  Globe,
  Wifi,
  Smartphone,
  Lock,
  Eye,
  Terminal,
  HardDrive,
  Users,
} from "lucide-react"
import Link from "next/link"

const basicTools = [
  {
    name: "Network Scanner",
    description: "Comprehensive network discovery and port scanning",
    icon: Globe,
    path: "/tools/network-scan",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    category: "Network",
    difficulty: "Beginner",
  },
  {
    name: "Port Scanner",
    description: "Scan for open ports on target systems using Nmap",
    icon: Shield,
    path: "/tools/port-scanner",
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    category: "Network",
    difficulty: "Beginner",
  },
  {
    name: "Subdomain Enumeration",
    description: "Discover subdomains using Sublist3r and AssetFinder",
    icon: Search,
    path: "/tools/subdomain-enum",
    color: "text-green-500",
    bgColor: "bg-green-500/10",
    category: "Reconnaissance",
    difficulty: "Beginner",
  },
  {
    name: "Vulnerability Scanner",
    description: "Scan for vulnerabilities using Nikto and Nuclei",
    icon: Shield,
    path: "/tools/vuln-scanner",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    category: "Web Security",
    difficulty: "Intermediate",
  },
  {
    name: "WHOIS Lookup",
    description: "Get domain registration information",
    icon: Info,
    path: "/tools/whois",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    category: "OSINT",
    difficulty: "Beginner",
  },
  {
    name: "DNS Information",
    description: "Retrieve DNS records and zone information",
    icon: Dns,
    path: "/tools/dns-lookup",
    color: "text-yellow-500",
    bgColor: "bg-yellow-500/10",
    category: "Network",
    difficulty: "Beginner",
  },
  {
    name: "HTTP Headers",
    description: "Analyze HTTP response headers",
    icon: FileText,
    path: "/tools/http-headers",
    color: "text-cyan-500",
    bgColor: "bg-cyan-500/10",
    category: "Web Security",
    difficulty: "Beginner",
  },
]

const advancedTools = [
  {
    name: "Masscan",
    description: "High-speed port scanner for large networks",
    icon: Target,
    path: "/tools/advanced/masscan",
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    category: "Network",
    difficulty: "Advanced",
  },
  {
    name: "Directory Buster",
    description: "Discover hidden directories and files",
    icon: Terminal,
    path: "/tools/advanced/dirbuster",
    color: "text-pink-500",
    bgColor: "bg-pink-500/10",
    category: "Web Security",
    difficulty: "Intermediate",
  },
  {
    name: "OSINT Toolkit",
    description: "Information gathering using TheHarvester and Shodan",
    icon: Eye,
    path: "/tools/advanced/osint",
    color: "text-indigo-500",
    bgColor: "bg-indigo-500/10",
    category: "OSINT",
    difficulty: "Intermediate",
  },
  {
    name: "Wireless Security",
    description: "WiFi network analysis and security testing",
    icon: Wifi,
    path: "/tools/advanced/wireless",
    color: "text-teal-500",
    bgColor: "bg-teal-500/10",
    category: "Wireless",
    difficulty: "Advanced",
  },
  {
    name: "Mobile Security",
    description: "Android APK analysis with MobSF",
    icon: Smartphone,
    path: "/tools/advanced/mobile",
    color: "text-emerald-500",
    bgColor: "bg-emerald-500/10",
    category: "Mobile",
    difficulty: "Advanced",
  },
  {
    name: "Cryptography",
    description: "Hash cracking and cryptographic analysis",
    icon: Lock,
    path: "/tools/advanced/crypto",
    color: "text-violet-500",
    bgColor: "bg-violet-500/10",
    category: "Cryptography",
    difficulty: "Advanced",
  },
  {
    name: "Digital Forensics",
    description: "Memory analysis with Volatility",
    icon: HardDrive,
    path: "/tools/advanced/forensics",
    color: "text-rose-500",
    bgColor: "bg-rose-500/10",
    category: "Forensics",
    difficulty: "Expert",
  },
  {
    name: "Social Engineering",
    description: "SET toolkit for social engineering tests",
    icon: Users,
    path: "/tools/advanced/social",
    color: "text-amber-500",
    bgColor: "bg-amber-500/10",
    category: "Social Engineering",
    difficulty: "Advanced",
  },
]

const expertTools = [
  {
    name: "Metasploit Framework",
    description: "Advanced exploitation framework for penetration testing",
    icon: Zap,
    path: "/tools/expert/metasploit",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    category: "Exploitation",
    difficulty: "Expert",
  },
  {
    name: "Burp Suite Pro",
    description: "Professional web application security testing platform",
    icon: Shield,
    path: "/tools/expert/burpsuite",
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    category: "Web Security",
    difficulty: "Expert",
  },
  {
    name: "Cloud Security Audit",
    description: "Comprehensive cloud infrastructure security assessment",
    icon: Globe,
    path: "/tools/expert/cloud-security",
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    category: "Cloud Security",
    difficulty: "Expert",
  },
  {
    name: "Network Analysis",
    description: "Advanced packet capture and network protocol analysis",
    icon: Activity,
    path: "/tools/expert/network-analysis",
    color: "text-green-500",
    bgColor: "bg-green-500/10",
    category: "Network",
    difficulty: "Expert",
  },
  {
    name: "Binary Analysis",
    description: "Reverse engineering and malware analysis with Ghidra",
    icon: HardDrive,
    path: "/tools/expert/binary-analysis",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    category: "Reverse Engineering",
    difficulty: "Expert",
  },
  {
    name: "Container Security",
    description: "Docker and Kubernetes security assessment",
    icon: Terminal,
    path: "/tools/expert/container-security",
    color: "text-cyan-500",
    bgColor: "bg-cyan-500/10",
    category: "DevSecOps",
    difficulty: "Expert",
  },
]

const getDifficultyColor = (difficulty: string) => {
  switch (difficulty) {
    case "Beginner":
      return "bg-green-500/10 text-green-500"
    case "Intermediate":
      return "bg-yellow-500/10 text-yellow-500"
    case "Advanced":
      return "bg-orange-500/10 text-orange-500"
    case "Expert":
      return "bg-red-500/10 text-red-500"
    default:
      return "bg-gray-500/10 text-gray-500"
  }
}

export default function DashboardPage() {
  const { user, logout, isAuthenticated, isLoading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push("/login")
    }
  }, [isAuthenticated, isLoading, router])

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center gradient-bg">
        <div className="flex flex-col items-center gap-4">
          <div className="spinner w-8 h-8"></div>
          <p className="text-muted-foreground">Loading dashboard...</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return null
  }

  const isDemo = user?.email === "user@unified.com"

  return (
    <div className="min-h-screen gradient-bg">
      {/* Header */}
      <header className="border-b border-border/50 glass backdrop-blur-xl sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-4">
            <div className="flex items-center space-x-3">
              <div className="p-2 rounded-lg bg-primary/10 glow">
                <Shield className="h-6 w-6 text-primary" />
              </div>
              <div>
                <h1 className="text-xl font-bold">Unified Toolkit</h1>
                <p className="text-xs text-muted-foreground">For New Pen-Testers</p>
              </div>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <ThemeToggle />
            <Link href="/profile">
              <div className="flex items-center space-x-3 px-3 py-2 rounded-lg glass hover:glow-hover transition-all duration-200 cursor-pointer">
                <div className="p-1 rounded-full bg-primary/20">
                  <User className="h-3 w-3 text-primary" />
                </div>
                <div className="text-sm">
                  <div className="flex items-center gap-2">
                    <p className="font-medium">{user?.username}</p>
                    {isDemo && (
                      <Badge variant="secondary" className="text-xs">
                        DEMO
                      </Badge>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground capitalize">{user?.role}</p>
                </div>
              </div>
            </Link>
            <Button
              variant="outline"
              size="sm"
              onClick={logout}
              className="flex items-center space-x-2 glass hover:glow-hover transition-all duration-200 bg-transparent"
            >
              <LogOut className="h-4 w-4" />
              <span>Logout</span>
            </Button>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="container mx-auto px-4 py-8">
        {/* Welcome Section */}
        <div className="mb-8 animate-fade-in">
          <div className="glass-card p-6 mb-6">
            <div className="flex items-center justify-between">
              <div>
                <h2 className="text-3xl font-bold mb-2">
                  Welcome back, {user?.username}! 👋
                  {isDemo && <span className="text-lg text-muted-foreground ml-2">(Demo Account)</span>}
                </h2>
                <p className="text-muted-foreground">
                  {isDemo
                    ? "You're using the demo account. All tools are available for testing!"
                    : "Choose a security tool to get started with your penetration testing journey."}
                </p>
              </div>
              <div className="hidden md:block">
                <div className="p-4 rounded-full bg-primary/10 glow animate-pulse-glow">
                  <Activity className="h-8 w-8 text-primary" />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Dashboard Stats */}
        <DashboardStats userId={user?.id || ""} />

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-8 mb-8">
          {/* Tools Section */}
          <div className="lg:col-span-2 space-y-8">
            {/* Basic Tools */}
            <div>
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold">Essential Tools</h3>
                  <p className="text-muted-foreground">Perfect for beginners and daily use</p>
                </div>
                <Badge variant="outline" className="bg-green-500/10 text-green-500">
                  {basicTools.length} Tools
                </Badge>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {basicTools.map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card
                        className="h-full glass-card hover:glow-hover transition-all duration-300 cursor-pointer group animate-slide-up"
                        style={{ animationDelay: `${index * 0.1}s` }}
                      >
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center space-x-3">
                              <div
                                className={`p-3 rounded-lg ${tool.bgColor} group-hover:scale-110 transition-transform duration-200`}
                              >
                                <IconComponent className={`h-5 w-5 ${tool.color}`} />
                              </div>
                              <div>
                                <CardTitle className="text-base group-hover:text-primary transition-colors duration-200">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-2 mt-1">
                                  <Badge variant="outline" className="text-xs">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="w-2 h-2 rounded-full bg-success animate-pulse"></div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <CardDescription className="group-hover:text-foreground/80 transition-colors duration-200 text-sm">
                            {tool.description}
                          </CardDescription>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </div>

            {/* Advanced Tools */}
            <div>
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold">Advanced Arsenal</h3>
                  <p className="text-muted-foreground">Professional-grade security tools</p>
                </div>
                <Badge variant="outline" className="bg-orange-500/10 text-orange-500">
                  {advancedTools.length} Tools
                </Badge>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {advancedTools.map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card
                        className="h-full glass-card hover:glow-hover transition-all duration-300 cursor-pointer group animate-slide-up"
                        style={{ animationDelay: `${(index + basicTools.length) * 0.1}s` }}
                      >
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center space-x-3">
                              <div
                                className={`p-3 rounded-lg ${tool.bgColor} group-hover:scale-110 transition-transform duration-200`}
                              >
                                <IconComponent className={`h-5 w-5 ${tool.color}`} />
                              </div>
                              <div>
                                <CardTitle className="text-base group-hover:text-primary transition-colors duration-200">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-2 mt-1">
                                  <Badge variant="outline" className="text-xs">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="w-2 h-2 rounded-full bg-warning animate-pulse"></div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <CardDescription className="group-hover:text-foreground/80 transition-colors duration-200 text-sm">
                            {tool.description}
                          </CardDescription>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </div>

            {/* Expert Tools */}
            <div>
              <div className="flex items-center justify-between mb-6">
                <div>
                  <h3 className="text-2xl font-bold">Expert Arsenal</h3>
                  <p className="text-muted-foreground">Professional-grade exploitation and analysis tools</p>
                </div>
                <Badge variant="outline" className="bg-red-500/10 text-red-500">
                  {expertTools.length} Tools
                </Badge>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {expertTools.map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card
                        className="h-full glass-card hover:glow-hover transition-all duration-300 cursor-pointer group animate-slide-up"
                        style={{ animationDelay: `${(index + basicTools.length + advancedTools.length) * 0.1}s` }}
                      >
                        <CardHeader className="pb-3">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center space-x-3">
                              <div
                                className={`p-3 rounded-lg ${tool.bgColor} group-hover:scale-110 transition-transform duration-200`}
                              >
                                <IconComponent className={`h-5 w-5 ${tool.color}`} />
                              </div>
                              <div>
                                <CardTitle className="text-base group-hover:text-primary transition-colors duration-200">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-2 mt-1">
                                  <Badge variant="outline" className="text-xs">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <CardDescription className="group-hover:text-foreground/80 transition-colors duration-200 text-sm">
                            {tool.description}
                          </CardDescription>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            <RecentActivity />

            {/* Quick Actions */}
            <Card className="glass-card">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Quick Actions
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Link href="/tools/network-scan">
                  <Button variant="outline" className="w-full justify-start glass hover:glow-hover bg-transparent">
                    <Globe className="mr-2 h-4 w-4" />
                    Scan My Network
                  </Button>
                </Link>
                <Link href="/security-assessment">
                  <Button variant="outline" className="w-full justify-start glass hover:glow-hover bg-transparent">
                    <Shield className="mr-2 h-4 w-4" />
                    Security Assessment
                  </Button>
                </Link>
                <Link href="/tools">
                  <Button variant="outline" className="w-full justify-start glass hover:glow-hover bg-transparent">
                    <FileText className="mr-2 h-4 w-4" />
                    Browse All Tools
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Learning Resources */}
            <Card className="glass-card">
              <CardHeader>
                <CardTitle>Learning Resources</CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="p-3 rounded-lg bg-primary/5 border border-primary/20">
                  <h4 className="font-medium text-sm mb-1">Getting Started Guide</h4>
                  <p className="text-xs text-muted-foreground">Learn the basics of penetration testing</p>
                </div>
                <div className="p-3 rounded-lg bg-success/5 border border-success/20">
                  <h4 className="font-medium text-sm mb-1">Tool Documentation</h4>
                  <p className="text-xs text-muted-foreground">Detailed guides for each security tool</p>
                </div>
                <div className="p-3 rounded-lg bg-warning/5 border border-warning/20">
                  <h4 className="font-medium text-sm mb-1">Best Practices</h4>
                  <p className="text-xs text-muted-foreground">Professional tips and methodologies</p>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Footer */}
        <footer className="container mx-auto px-4 py-6 mt-12 border-t border-border/20">
          <div className="text-center">
            <div className="flex items-center justify-center space-x-3 mb-2">
              <Shield className="h-4 w-4 text-primary" />
              <span className="text-sm text-muted-foreground">
                © 2025 Unified Toolkit for New Pen-Testers. Developed by Suman.
              </span>
            </div>
          </div>
        </footer>
      </main>
    </div>
  )
}
