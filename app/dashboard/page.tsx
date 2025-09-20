"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/AuthContext"
import { ThemeToggle } from "@/components/ThemeToggle"
import { DashboardStats } from "@/components/DashboardStats"
import RecentActivity from "@/components/RecentActivity"
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
      router.push("/")
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

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900">
      {/* Animated Background Elements */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
  <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl animate-pulse delay-200"></div>
  <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl animate-pulse delay-400"></div>
      </div>

      {/* Header */}
  <header className="sticky top-0 z-50 border-b border-white/10 dark:border-gray-800/50 bg-white/60 dark:bg-slate-900/60 backdrop-blur-xl shadow-lg">
        <div className="container mx-auto px-4 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="flex items-center space-x-3">
                <div className="relative p-3 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 shadow-xl">
                  <Shield className="h-7 w-7 text-white" />
                  <div className="absolute inset-0 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 animate-pulse opacity-75"></div>
                </div>
                <div>
                  <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                    cybersec-pro-platform
                  </h1>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Professional Security Platform</p>
                </div>
              </div>
            </div>
            <div className="flex items-center space-x-4">
              <ThemeToggle />
              <Link href="/profile">
                <div className="flex items-center space-x-3 px-4 py-2 rounded-xl bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm border border-gray-200/50 dark:border-gray-700/50 hover:shadow-lg transition-all duration-300 cursor-pointer group">
                  <div className="relative p-2 rounded-full bg-gradient-to-br from-blue-500 to-indigo-500">
                    <User className="h-4 w-4 text-white" />
                  </div>
                  <div className="text-sm">
                    <div className="flex items-center gap-2">
                      <p className="font-semibold text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors">
                        {user?.username}
                      </p>
                    </div>
                    <p className="text-xs text-gray-500 dark:text-gray-400 capitalize">{user?.role}</p>
                  </div>
                </div>
              </Link>
              <Button
                variant="outline"
                size="sm"
                onClick={logout}
                className="flex items-center space-x-2 bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm border-gray-200/50 dark:border-gray-700/50 hover:shadow-lg transition-all duration-300 hover:bg-red-50 dark:hover:bg-red-900/20 hover:border-red-200 dark:hover:border-red-800"
              >
                <LogOut className="h-4 w-4" />
                <span>Logout</span>
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="relative container mx-auto px-4 py-8">
        {/* Hero Welcome Section */}
        <div className="mb-12 animate-fade-in">
          <div className="relative overflow-hidden rounded-3xl bg-gradient-to-br from-blue-600 via-indigo-600 to-purple-700 p-8 shadow-2xl">
            {/* Background Pattern */}
            <div className="absolute inset-0 bg-cyber-grid opacity-10"></div>
            <div className="absolute top-0 right-0 w-64 h-64 bg-white/10 rounded-full blur-3xl transform translate-x-32 -translate-y-32"></div>
            
            <div className="relative flex items-center justify-between">
              <div className="max-w-2xl">
                <div className="flex items-center space-x-3 mb-4">
                  <div className="p-2 rounded-lg bg-white/20 backdrop-blur-sm">
                    <Activity className="h-6 w-6 text-white" />
                  </div>
                  <span className="text-blue-100 text-sm font-medium">DASHBOARD OVERVIEW</span>
                </div>
                <h2 className="text-4xl font-bold text-white mb-4">
                  Welcome back,<br />
                  <span className="block text-blue-200">
                    {user?.firstName ? `${user.firstName} ${user?.lastName}` : user?.username}! 👋
                  </span>
                </h2>
                <p className="text-blue-100 text-lg leading-relaxed">
                  Your cybersecurity command center is ready. Access professional-grade penetration testing tools, 
                  vulnerability assessments, and security analytics trusted by professionals worldwide.
                </p>
                
                {/* Quick Stats */}
                <div className="grid grid-cols-3 gap-4 mt-8">
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">{basicTools.length + advancedTools.length + expertTools.length}</div>
                    <div className="text-blue-200 text-sm">Security Tools</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">24/7</div>
                    <div className="text-blue-200 text-sm">Available</div>
                  </div>
                  <div className="text-center">
                    <div className="text-2xl font-bold text-white">Pro</div>
                    <div className="text-blue-200 text-sm">Grade Tools</div>
                  </div>
                </div>
              </div>
              
              <div className="hidden lg:block">
                <div className="relative">
                  <div className="p-6 rounded-full bg-white/10 backdrop-blur-sm animate-pulse">
                    <Shield className="h-16 w-16 text-white" />
                  </div>
                  <div className="absolute inset-0 rounded-full border-2 border-white/20 animate-spin duration-[10s]"></div>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Dashboard Stats */}
        <div className="mb-8">
          <DashboardStats userId={user?.id || ""} />
        </div>

        {/* Main Content Grid */}
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-8 mb-8">
          {/* Tools Section */}
          <div className="xl:col-span-3 space-y-12">
            {/* Essential Tools */}
            <div className="animate-slide-up">
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h3 className="text-3xl font-bold bg-gradient-to-r from-green-600 to-emerald-600 bg-clip-text text-transparent">
                    Essential Tools
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400 mt-2">Perfect for beginners and daily security tasks</p>
                </div>
                <div className="flex items-center space-x-3">
                  <Badge className="bg-green-500/10 text-green-600 border-green-200 dark:border-green-800 px-3 py-1">
                    <Shield className="w-3 h-3 mr-1" />
                    {basicTools.length} Tools
                  </Badge>
                  <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {basicTools.map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card
                        className="group h-full relative overflow-hidden bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border-gray-200/50 dark:border-gray-700/50 hover:shadow-2xl hover:shadow-green-500/10 transition-all duration-500 cursor-pointer transform hover:-translate-y-2"
                        style={{ animationDelay: `${index * 0.1}s` }}
                      >
                        {/* Gradient Background on Hover */}
                        <div className="absolute inset-0 bg-gradient-to-br from-green-500/5 to-emerald-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                        
                        <CardHeader className="relative pb-3">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center space-x-4">
                              <div className={`relative p-4 rounded-2xl ${tool.bgColor} group-hover:scale-110 transition-transform duration-300`}>
                                <IconComponent className={`h-6 w-6 ${tool.color}`} />
                                <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                              </div>
                              <div>
                                <CardTitle className="text-lg font-bold text-gray-900 dark:text-white group-hover:text-green-600 dark:group-hover:text-green-400 transition-colors duration-300">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-2 mt-2">
                                  <Badge variant="secondary" className="text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="relative">
                              <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
                              <div className="absolute inset-0 w-3 h-3 rounded-full bg-green-500 animate-ping opacity-75"></div>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="relative">
                          <CardDescription className="text-gray-600 dark:text-gray-400 group-hover:text-gray-700 dark:group-hover:text-gray-300 transition-colors duration-300 text-sm leading-relaxed">
                            {tool.description}
                          </CardDescription>
                          
                          {/* Hover Arrow */}
                          <div className="flex justify-end mt-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                            <div className="flex items-center text-green-600 dark:text-green-400 text-sm font-medium">
                              Launch Tool
                              <svg className="w-4 h-4 ml-1 transform group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                              </svg>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </div>

            {/* Advanced Tools */}
            <div className="animate-slide-up delay-200">
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h3 className="text-3xl font-bold bg-gradient-to-r from-orange-600 to-red-600 bg-clip-text text-transparent">
                    Advanced Arsenal
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400 mt-2">Professional-grade security and analysis tools</p>
                </div>
                <div className="flex items-center space-x-3">
                  <Badge className="bg-orange-500/10 text-orange-600 border-orange-200 dark:border-orange-800 px-3 py-1">
                    <Target className="w-3 h-3 mr-1" />
                    {advancedTools.length} Tools
                  </Badge>
                  <div className="w-3 h-3 rounded-full bg-orange-500 animate-pulse"></div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {advancedTools.map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card
                        className="group h-full relative overflow-hidden bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border-gray-200/50 dark:border-gray-700/50 hover:shadow-2xl hover:shadow-orange-500/10 transition-all duration-500 cursor-pointer transform hover:-translate-y-2"
                        style={{ animationDelay: `${(index + basicTools.length) * 0.1}s` }}
                      >
                        <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-red-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                        
                        <CardHeader className="relative pb-3">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center space-x-4">
                              <div className={`relative p-4 rounded-2xl ${tool.bgColor} group-hover:scale-110 transition-transform duration-300`}>
                                <IconComponent className={`h-6 w-6 ${tool.color}`} />
                                <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                              </div>
                              <div>
                                <CardTitle className="text-lg font-bold text-gray-900 dark:text-white group-hover:text-orange-600 dark:group-hover:text-orange-400 transition-colors duration-300">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-2 mt-2">
                                  <Badge variant="secondary" className="text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="relative">
                              <div className="w-3 h-3 rounded-full bg-orange-500 animate-pulse"></div>
                              <div className="absolute inset-0 w-3 h-3 rounded-full bg-orange-500 animate-ping opacity-75"></div>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="relative">
                          <CardDescription className="text-gray-600 dark:text-gray-400 group-hover:text-gray-700 dark:group-hover:text-gray-300 transition-colors duration-300 text-sm leading-relaxed">
                            {tool.description}
                          </CardDescription>
                          
                          <div className="flex justify-end mt-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                            <div className="flex items-center text-orange-600 dark:text-orange-400 text-sm font-medium">
                              Launch Tool
                              <svg className="w-4 h-4 ml-1 transform group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                              </svg>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </div>

            {/* Expert Tools */}
            <div className="animate-slide-up delay-400">
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h3 className="text-3xl font-bold bg-gradient-to-r from-red-600 to-purple-600 bg-clip-text text-transparent">
                    Expert Arsenal
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400 mt-2">Elite-level exploitation and analysis frameworks</p>
                </div>
                <div className="flex items-center space-x-3">
                  <Badge className="bg-red-500/10 text-red-600 border-red-200 dark:border-red-800 px-3 py-1">
                    <Zap className="w-3 h-3 mr-1" />
                    {expertTools.length} Tools
                  </Badge>
                  <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse"></div>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {expertTools.map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card
                        className="group h-full relative overflow-hidden bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border-gray-200/50 dark:border-gray-700/50 hover:shadow-2xl hover:shadow-red-500/10 transition-all duration-500 cursor-pointer transform hover:-translate-y-2"
                        style={{ animationDelay: `${(index + basicTools.length + advancedTools.length) * 0.1}s` }}
                      >
                        <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 to-purple-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                        
                        <CardHeader className="relative pb-3">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center space-x-4">
                              <div className={`relative p-4 rounded-2xl ${tool.bgColor} group-hover:scale-110 transition-transform duration-300`}>
                                <IconComponent className={`h-6 w-6 ${tool.color}`} />
                                <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-white/20 to-transparent opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                              </div>
                              <div>
                                <CardTitle className="text-lg font-bold text-gray-900 dark:text-white group-hover:text-red-600 dark:group-hover:text-red-400 transition-colors duration-300">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-2 mt-2">
                                  <Badge variant="secondary" className="text-xs bg-gray-100 dark:bg-gray-700 text-gray-600 dark:text-gray-300">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="relative">
                              <div className="w-3 h-3 rounded-full bg-red-500 animate-pulse"></div>
                              <div className="absolute inset-0 w-3 h-3 rounded-full bg-red-500 animate-ping opacity-75"></div>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="relative">
                          <CardDescription className="text-gray-600 dark:text-gray-400 group-hover:text-gray-700 dark:group-hover:text-gray-300 transition-colors duration-300 text-sm leading-relaxed">
                            {tool.description}
                          </CardDescription>
                          
                          <div className="flex justify-end mt-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                            <div className="flex items-center text-red-600 dark:text-red-400 text-sm font-medium">
                              Launch Tool
                              <svg className="w-4 h-4 ml-1 transform group-hover:translate-x-1 transition-transform" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                              </svg>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </div>
          </div>

          {/* Enhanced Sidebar */}
          <div className="space-y-8">
            {/* Recent Activity */}
            <div className="animate-slide-up delay-600">
              <RecentActivity />
            </div>

            {/* Quick Actions */}
            <Card className="relative overflow-hidden bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border-gray-200/50 dark:border-gray-700/50 shadow-xl animate-slide-up" style={{animationDelay: '0.7s'}}>
              <div className="absolute top-0 right-0 w-24 h-24 bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-full blur-xl transform translate-x-8 -translate-y-8"></div>
              <CardHeader className="relative">
                <CardTitle className="flex items-center gap-3 text-xl">
                  <div className="p-2 rounded-lg bg-gradient-to-br from-blue-500 to-indigo-500 text-white">
                    <Zap className="h-5 w-5" />
                  </div>
                  Quick Actions
                </CardTitle>
              </CardHeader>
              <CardContent className="relative space-y-4">
                <Link href="/tools/network-scan">
                  <Button variant="outline" className="w-full justify-start h-12 bg-white/50 dark:bg-slate-700/50 backdrop-blur-sm border-gray-200/50 dark:border-gray-600/50 hover:shadow-lg hover:shadow-blue-500/10 transition-all duration-300 group">
                    <div className="p-1 rounded bg-blue-500/10 mr-3 group-hover:bg-blue-500/20 transition-colors">
                      <Globe className="h-4 w-4 text-blue-600" />
                    </div>
                    <span className="font-medium">Scan My Network</span>
                    <svg className="w-4 h-4 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </Button>
                </Link>
                <Link href="/security-assessment">
                  <Button variant="outline" className="w-full justify-start h-12 bg-white/50 dark:bg-slate-700/50 backdrop-blur-sm border-gray-200/50 dark:border-gray-600/50 hover:shadow-lg hover:shadow-green-500/10 transition-all duration-300 group">
                    <div className="p-1 rounded bg-green-500/10 mr-3 group-hover:bg-green-500/20 transition-colors">
                      <Shield className="h-4 w-4 text-green-600" />
                    </div>
                    <span className="font-medium">Security Assessment</span>
                    <svg className="w-4 h-4 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </Button>
                </Link>
                <Link href="/tools">
                  <Button variant="outline" className="w-full justify-start h-12 bg-white/50 dark:bg-slate-700/50 backdrop-blur-sm border-gray-200/50 dark:border-gray-600/50 hover:shadow-lg hover:shadow-purple-500/10 transition-all duration-300 group">
                    <div className="p-1 rounded bg-purple-500/10 mr-3 group-hover:bg-purple-500/20 transition-colors">
                      <FileText className="h-4 w-4 text-purple-600" />
                    </div>
                    <span className="font-medium">Browse All Tools</span>
                    <svg className="w-4 h-4 ml-auto opacity-0 group-hover:opacity-100 transition-opacity" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* Security Tips */}
            <Card className="relative overflow-hidden bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border-gray-200/50 dark:border-gray-700/50 shadow-xl animate-slide-up" style={{animationDelay: '0.8s'}}>
              <div className="absolute top-0 left-0 w-24 h-24 bg-gradient-to-br from-yellow-500/20 to-orange-500/20 rounded-full blur-xl transform -translate-x-8 -translate-y-8"></div>
              <CardHeader className="relative">
                <CardTitle className="flex items-center gap-3 text-xl">
                  <div className="p-2 rounded-lg bg-gradient-to-br from-yellow-500 to-orange-500 text-white">
                    <Target className="h-5 w-5" />
                  </div>
                  Pro Tips
                </CardTitle>
              </CardHeader>
              <CardContent className="relative space-y-4">
                <div className="p-4 rounded-xl bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border border-blue-200/50 dark:border-blue-800/50 group hover:shadow-lg transition-all duration-300">
                  <div className="flex items-start space-x-3">
                    <div className="p-1 rounded bg-blue-500/10 mt-1">
                      <Shield className="h-4 w-4 text-blue-600" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm text-blue-900 dark:text-blue-100 mb-1">Always Get Permission</h4>
                      <p className="text-xs text-blue-700 dark:text-blue-300 leading-relaxed">Never test on systems you don't own without explicit written authorization.</p>
                    </div>
                  </div>
                </div>
                <div className="p-4 rounded-xl bg-gradient-to-br from-green-50 to-emerald-50 dark:from-green-900/20 dark:to-emerald-900/20 border border-green-200/50 dark:border-green-800/50 group hover:shadow-lg transition-all duration-300">
                  <div className="flex items-start space-x-3">
                    <div className="p-1 rounded bg-green-500/10 mt-1">
                      <Eye className="h-4 w-4 text-green-600" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm text-green-900 dark:text-green-100 mb-1">Document Everything</h4>
                      <p className="text-xs text-green-700 dark:text-green-300 leading-relaxed">Keep detailed logs of your testing methodology and findings.</p>
                    </div>
                  </div>
                </div>
                <div className="p-4 rounded-xl bg-gradient-to-br from-purple-50 to-violet-50 dark:from-purple-900/20 dark:to-violet-900/20 border border-purple-200/50 dark:border-purple-800/50 group hover:shadow-lg transition-all duration-300">
                  <div className="flex items-start space-x-3">
                    <div className="p-1 rounded bg-purple-500/10 mt-1">
                      <Terminal className="h-4 w-4 text-purple-600" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm text-purple-900 dark:text-purple-100 mb-1">Start Simple</h4>
                      <p className="text-xs text-purple-700 dark:text-purple-300 leading-relaxed">Begin with basic reconnaissance before moving to advanced techniques.</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Learning Resources */}
            <Card className="relative overflow-hidden bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border-gray-200/50 dark:border-gray-700/50 shadow-xl animate-slide-up" style={{animationDelay: '0.9s'}}>
              <div className="absolute bottom-0 right-0 w-20 h-20 bg-gradient-to-br from-indigo-500/20 to-purple-500/20 rounded-full blur-xl transform translate-x-6 translate-y-6"></div>
              <CardHeader className="relative">
                <CardTitle className="flex items-center gap-3 text-xl">
                  <div className="p-2 rounded-lg bg-gradient-to-br from-indigo-500 to-purple-500 text-white">
                    <Activity className="h-5 w-5" />
                  </div>
                  Learning Hub
                </CardTitle>
              </CardHeader>
              <CardContent className="relative space-y-4">
                <div className="p-4 rounded-xl bg-gradient-to-br from-indigo-50 to-purple-50 dark:from-indigo-900/20 dark:to-purple-900/20 border border-indigo-200/50 dark:border-indigo-800/50 hover:shadow-lg transition-all duration-300 cursor-pointer group">
                  <div className="flex items-start space-x-3">
                    <div className="p-1 rounded bg-indigo-500/10 mt-1">
                      <FileText className="h-4 w-4 text-indigo-600" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm text-indigo-900 dark:text-indigo-100 mb-1 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors">Getting Started Guide</h4>
                      <p className="text-xs text-indigo-700 dark:text-indigo-300 leading-relaxed">Complete beginner's guide to ethical hacking and penetration testing fundamentals.</p>
                    </div>
                  </div>
                </div>
                <div className="p-4 rounded-xl bg-gradient-to-br from-cyan-50 to-blue-50 dark:from-cyan-900/20 dark:to-blue-900/20 border border-cyan-200/50 dark:border-cyan-800/50 hover:shadow-lg transition-all duration-300 cursor-pointer group">
                  <div className="flex items-start space-x-3">
                    <div className="p-1 rounded bg-cyan-500/10 mt-1">
                      <HardDrive className="h-4 w-4 text-cyan-600" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm text-cyan-900 dark:text-cyan-100 mb-1 group-hover:text-cyan-600 dark:group-hover:text-cyan-400 transition-colors">Tool Documentation</h4>
                      <p className="text-xs text-cyan-700 dark:text-cyan-300 leading-relaxed">Comprehensive guides and tutorials for each security testing tool.</p>
                    </div>
                  </div>
                </div>
                <div className="p-4 rounded-xl bg-gradient-to-br from-amber-50 to-orange-50 dark:from-amber-900/20 dark:to-orange-900/20 border border-amber-200/50 dark:border-amber-800/50 hover:shadow-lg transition-all duration-300 cursor-pointer group">
                  <div className="flex items-start space-x-3">
                    <div className="p-1 rounded bg-amber-500/10 mt-1">
                      <Users className="h-4 w-4 text-amber-600" />
                    </div>
                    <div>
                      <h4 className="font-semibold text-sm text-amber-900 dark:text-amber-100 mb-1 group-hover:text-amber-600 dark:group-hover:text-amber-400 transition-colors">Best Practices</h4>
                      <p className="text-xs text-amber-700 dark:text-amber-300 leading-relaxed">Professional methodologies and industry-standard security practices.</p>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Enhanced Footer */}
        <footer className="relative mt-20 py-12 border-t border-gray-200/50 dark:border-gray-800/50">
          <div className="absolute inset-0 bg-gradient-to-r from-blue-50/50 via-indigo-50/50 to-purple-50/50 dark:from-blue-900/10 dark:via-indigo-900/10 dark:to-purple-900/10"></div>
          <div className="relative">
            <div className="text-center">
              <div className="flex items-center justify-center space-x-4 mb-6">
                <div className="p-3 rounded-xl bg-gradient-to-br from-blue-600 to-indigo-600 text-white shadow-lg">
                  <Shield className="h-6 w-6" />
                </div>
                <div>
                  <h3 className="text-xl font-bold bg-gradient-to-r from-blue-600 to-indigo-600 bg-clip-text text-transparent">
                    cybersec-pro-platform
                  </h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Professional Security Testing Suite</p>
                </div>
              </div>
              
              <div className="grid grid-cols-1 md:grid-cols-3 gap-8 mb-8 max-w-4xl mx-auto">
                <div className="text-center">
                  <div className="p-3 rounded-lg bg-green-500/10 inline-block mb-3">
                    <Target className="h-6 w-6 text-green-600" />
                  </div>
                  <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Professional Tools</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Enterprise-grade security testing utilities</p>
                </div>
                <div className="text-center">
                  <div className="p-3 rounded-lg bg-blue-500/10 inline-block mb-3">
                    <Users className="h-6 w-6 text-blue-600" />
                  </div>
                  <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Expert Community</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Trusted by security professionals worldwide</p>
                </div>
                <div className="text-center">
                  <div className="p-3 rounded-lg bg-purple-500/10 inline-block mb-3">
                    <Lock className="h-6 w-6 text-purple-600" />
                  </div>
                  <h4 className="font-semibold text-gray-900 dark:text-white mb-2">Secure & Reliable</h4>
                  <p className="text-sm text-gray-600 dark:text-gray-400">Built with security and privacy in mind</p>
                </div>
              </div>
              
              <div className="flex items-center justify-center space-x-2 text-sm text-gray-500 dark:text-gray-400">
                <span>© 2025 cybersec-pro-platform</span>
                <span>•</span>
                <span>Developed by Suman Singh</span>
                <span>•</span>
                <span>Made with ❤️ for the Security Community</span>
              </div>
            </div>
          </div>
        </footer>
      </main>
    </div>
  )
}
