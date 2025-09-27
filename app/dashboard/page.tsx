"use client"

import React, { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/src/auth/utils/AuthContext"
import { ThemeToggle } from "@/src/ui/components/ThemeToggle"
import { DashboardStats } from "@/src/ui/components/DashboardStats"
import RecentActivity from "@/src/ui/components/RecentActivity"
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Badge } from "@/src/ui/components/ui/badge"
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
  Brain,
  Settings,
  Mail,
  CreditCard,
  AlertTriangle,
  Video,
  Sparkles,
  Bot,
  ChevronRight,
} from "lucide-react"
import Link from "next/link"

const securityTools = {
  essential: [
    {
      name: "Network Scanner",
      description: "Comprehensive network discovery and port scanning with Nmap",
      icon: Globe,
      path: "/tools/network-scanner",
      color: "text-purple-500",
      bgColor: "bg-purple-500/10",
      borderColor: "border-purple-200 dark:border-purple-800",
      category: "Network",
      difficulty: "Beginner",
      status: "active"
    },
    {
      name: "Port Scanner",
      description: "Advanced port scanning with service detection",
      icon: Shield,
      path: "/tools/port-scanner",
      color: "text-blue-500",
      bgColor: "bg-blue-500/10",
      borderColor: "border-blue-200 dark:border-blue-800",
      category: "Network",
      difficulty: "Beginner",
      status: "active"
    },
    {
      name: "Subdomain Enumeration",
      description: "Discover hidden subdomains with multiple techniques",
      icon: Search,
      path: "/tools/subdomain-enum",
      color: "text-green-500",
      bgColor: "bg-green-500/10",
      borderColor: "border-green-200 dark:border-green-800",
      category: "Reconnaissance",
      difficulty: "Beginner",
      status: "active"
    },
    {
      name: "Vulnerability Scanner",
      description: "Automated vulnerability detection with Nikto and Nuclei",
      icon: AlertTriangle,
      path: "/tools/vuln-scanner",
      color: "text-red-500",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-200 dark:border-red-800",
      category: "Web Security",
      difficulty: "Intermediate",
      status: "active"
    },
    {
      name: "WHOIS Lookup",
      description: "Domain registration information and ownership details",
      icon: Info,
      path: "/tools/whois",
      color: "text-purple-500",
      bgColor: "bg-purple-500/10",
      borderColor: "border-purple-200 dark:border-purple-800",
      category: "OSINT",
      difficulty: "Beginner",
      status: "active"
    },
    {
      name: "DNS Lookup",
      description: "Complete DNS record analysis and zone information",
      icon: Dns,
      path: "/tools/dns-lookup",
      color: "text-yellow-500",
      bgColor: "bg-yellow-500/10",
      borderColor: "border-yellow-200 dark:border-yellow-800",
      category: "Network",
      difficulty: "Beginner",
      status: "active"
    }
  ],
  advanced: [
    {
      name: "Nmap Advanced",
      description: "Professional network mapping with stealth techniques",
      icon: Target,
      path: "/tools/nmap",
      color: "text-orange-500",
      bgColor: "bg-orange-500/10",
      borderColor: "border-orange-200 dark:border-orange-800",
      category: "Network",
      difficulty: "Advanced",
      status: "active"
    },
    {
      name: "Directory Buster",
      description: "Discover hidden directories and files on web servers",
      icon: Terminal,
      path: "/tools/advanced/dirbuster",
      color: "text-pink-500",
      bgColor: "bg-pink-500/10",
      borderColor: "border-pink-200 dark:border-pink-800",
      category: "Web Security",
      difficulty: "Intermediate",
      status: "active"
    },
    {
      name: "OSINT Toolkit",
      description: "Information gathering with TheHarvester and Shodan",
      icon: Eye,
      path: "/tools/advanced/osint",
      color: "text-indigo-500",
      bgColor: "bg-indigo-500/10",
      borderColor: "border-indigo-200 dark:border-indigo-800",
      category: "OSINT",
      difficulty: "Intermediate",
      status: "active"
    },
    {
      name: "Wireless Security",
      description: "WiFi network analysis and penetration testing",
      icon: Wifi,
      path: "/tools/advanced/wireless",
      color: "text-teal-500",
      bgColor: "bg-teal-500/10",
      borderColor: "border-teal-200 dark:border-teal-800",
      category: "Wireless",
      difficulty: "Advanced",
      status: "active"
    },
    {
      name: "HTTP Headers",
      description: "Analyze security headers and server configurations",
      icon: FileText,
      path: "/tools/http-headers",
      color: "text-cyan-500",
      bgColor: "bg-cyan-500/10",
      borderColor: "border-cyan-200 dark:border-cyan-800",
      category: "Web Security",
      difficulty: "Beginner",
      status: "active"
    },
    {
      name: "Mobile Security",
      description: "Android APK analysis with MobSF framework",
      icon: Smartphone,
      path: "/tools/advanced/mobile",
      color: "text-emerald-500",
      bgColor: "bg-emerald-500/10",
      borderColor: "border-emerald-200 dark:border-emerald-800",
      category: "Mobile",
      difficulty: "Advanced",
      status: "active"
    }
  ],
  expert: [
    {
      name: "Metasploit Framework",
      description: "Professional exploitation framework for penetration testing",
      icon: Zap,
      path: "/tools/expert/metasploit",
      color: "text-red-500",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-200 dark:border-red-800",
      category: "Exploitation",
      difficulty: "Expert",
      status: "active"
    },
    {
      name: "Burp Suite Professional",
      description: "Advanced web application security testing platform",
      icon: Shield,
      path: "/tools/expert/burpsuite",
      color: "text-orange-500",
      bgColor: "bg-orange-500/10",
      borderColor: "border-orange-200 dark:border-orange-800",
      category: "Web Security",
      difficulty: "Expert",
      status: "active"
    },
    {
      name: "Digital Forensics",
      description: "Memory analysis and forensic investigation with Volatility",
      icon: HardDrive,
      path: "/tools/advanced/forensics",
      color: "text-rose-500",
      bgColor: "bg-rose-500/10",
      borderColor: "border-rose-200 dark:border-rose-800",
      category: "Forensics",
      difficulty: "Expert",
      status: "active"
    },
    {
      name: "Cryptography Tools",
      description: "Hash cracking and cryptographic analysis suite",
      icon: Lock,
      path: "/tools/advanced/crypto",
      color: "text-violet-500",
      bgColor: "bg-violet-500/10",
      borderColor: "border-violet-200 dark:border-violet-800",
      category: "Cryptography",
      difficulty: "Advanced",
      status: "active"
    }
  ],
  ai: [
    {
      name: "AI Phishing Detection",
      description: "Advanced AI-powered phishing and scam email detection",
      icon: Mail,
      path: "/tools/ai/phishing-detection",
      color: "text-emerald-500",
      bgColor: "bg-emerald-500/10",
      borderColor: "border-emerald-200 dark:border-emerald-800",
      category: "AI Security",
      difficulty: "Advanced",
      status: "active",
      isNew: true
    },
    {
      name: "AI Fraud Detection",
      description: "Machine learning fraud detection for financial systems",
      icon: CreditCard,
      path: "/tools/ai/fraud-detection",
      color: "text-violet-500",
      bgColor: "bg-violet-500/10",
      borderColor: "border-violet-200 dark:border-violet-800",
      category: "AI Security",
      difficulty: "Advanced",
      status: "active"
    },
    {
      name: "AI Intrusion Detection",
      description: "Real-time AI network intrusion detection system",
      icon: Brain,
      path: "/tools/ai/intrusion-detection",
      color: "text-indigo-500",
      bgColor: "bg-indigo-500/10",
      borderColor: "border-indigo-200 dark:border-indigo-800",
      category: "AI Security",
      difficulty: "Advanced",
      status: "active"
    },
    {
      name: "AI Threat Intelligence",
      description: "Automated threat intelligence gathering and analysis",
      icon: AlertTriangle,
      path: "/tools/ai/threat-intelligence",
      color: "text-red-500",
      bgColor: "bg-red-500/10",
      borderColor: "border-red-200 dark:border-red-800",
      category: "AI Security",
      difficulty: "Advanced",
      status: "active"
    },
    {
      name: "AI Security Assistant",
      description: "Intelligent security advisory with automated recommendations",
      icon: Bot,
      path: "/tools/ai/security-assistant",
      color: "text-blue-500",
      bgColor: "bg-blue-500/10",
      borderColor: "border-blue-200 dark:border-blue-800",
      category: "AI Security",
      difficulty: "Intermediate",
      status: "active"
    }
  ]
}

const getDifficultyColor = (difficulty: string) => {
  switch (difficulty) {
    case "Beginner":
      return "bg-green-500/10 text-green-500 border-green-200 dark:border-green-800"
    case "Intermediate":
      return "bg-yellow-500/10 text-yellow-500 border-yellow-200 dark:border-yellow-800"
    case "Advanced":
      return "bg-orange-500/10 text-orange-500 border-orange-200 dark:border-orange-800"
    case "Expert":
      return "bg-red-500/10 text-red-500 border-red-200 dark:border-red-800"
    default:
      return "bg-gray-500/10 text-gray-500 border-gray-200 dark:border-gray-800"
  }
}

export default function DashboardPage() {
  const { user, logout, isAuthenticated, isLoading } = useAuth()
  const router = useRouter()
  const [search, setSearch] = React.useState("")

  useEffect(() => {
    if (!isLoading && !isAuthenticated) {
      router.push("/login")
    }
  }, [isAuthenticated, isLoading, router])

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900">
        <div className="flex flex-col items-center gap-4">
          <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-blue-600"></div>
          <p className="text-muted-foreground">Loading your security dashboard...</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return null
  }

  const totalTools = Object.values(securityTools).reduce((acc, category) => acc + category.length, 0)

  // Filter logic for all tool categories
  const filterTools = (tools: any[]) => {
    if (!search.trim()) return tools
    const s = search.trim().toLowerCase()
    return tools.filter(tool =>
      tool.name.toLowerCase().includes(s) ||
      tool.description.toLowerCase().includes(s) ||
      (tool.category && tool.category.toLowerCase().includes(s)) ||
      (tool.difficulty && tool.difficulty.toLowerCase().includes(s))
    )
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900">
      {/* Animated Background */}
      <div className="fixed inset-0 overflow-hidden pointer-events-none">
        <div className="absolute -top-40 -right-40 w-80 h-80 bg-purple-500/10 rounded-full blur-3xl animate-pulse"></div>
        <div className="absolute -bottom-40 -left-40 w-80 h-80 bg-blue-500/10 rounded-full blur-3xl animate-pulse delay-200"></div>
        <div className="absolute top-1/2 left-1/2 transform -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-indigo-500/5 rounded-full blur-3xl animate-pulse delay-400"></div>
      </div>

      {/* Header */}
      <header className="sticky top-0 z-50 border-b border-white/10 dark:border-gray-800/30 bg-white/80 dark:bg-slate-900/80 backdrop-blur-2xl shadow-xl">
        <div className="container mx-auto px-3 sm:px-6 lg:px-8 py-3 sm:py-4 lg:py-6">
          <div className="flex items-center justify-between">
            {/* Brand Section */}
            <div className="flex items-center space-x-2 sm:space-x-4 lg:space-x-6">
              <div className="flex items-center space-x-2 sm:space-x-3 lg:space-x-4">
                <div className="relative group">
                  <div className="absolute inset-0 rounded-lg sm:rounded-xl lg:rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-600 animate-pulse opacity-75 group-hover:opacity-100 transition-opacity"></div>
                  <div className="relative p-1.5 sm:p-3 lg:p-4 rounded-lg sm:rounded-xl lg:rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-600 shadow-2xl transform group-hover:scale-110 transition-transform duration-300">
                    <Shield className="h-5 w-5 sm:h-6 sm:w-6 lg:h-8 lg:w-8 text-white" />
                  </div>
                </div>
                <div className="hidden sm:block">
                  <h1 className="text-lg sm:text-xl lg:text-2xl xl:text-3xl font-bold bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 bg-clip-text text-transparent">
                    CyberShield
                  </h1>
                  <p className="text-xs sm:text-sm lg:text-base font-semibold text-gray-600 dark:text-gray-400 tracking-wide hidden md:block">
                    Professional Cybersecurity Platform
                  </p>
                </div>
                {/* Mobile Brand */}
                <div className="sm:hidden">
                  <h1 className="text-base font-bold bg-gradient-to-r from-blue-600 via-indigo-600 to-purple-600 bg-clip-text text-transparent">
                    CyberShield
                  </h1>
                </div>
              </div>
            </div>
            
            {/* Right Section */}
            <div className="flex items-center space-x-1 sm:space-x-3 lg:space-x-6">
              {/* Theme Toggle */}
              <div className="p-1.5 sm:p-2 lg:p-3 rounded-md sm:rounded-lg lg:rounded-xl bg-white/90 dark:bg-slate-800/90 backdrop-blur-sm border border-gray-200/60 dark:border-gray-700/60 hover:shadow-lg hover:scale-105 transition-all duration-300">
                <ThemeToggle />
              </div>
              
              {/* Settings - Hidden on mobile, shown on tablet+ */}
              <Link href="/settings" className="hidden md:block">
                <Button className="p-2 lg:p-4 rounded-lg lg:rounded-xl bg-white/90 dark:bg-slate-800/90 backdrop-blur-sm border border-gray-200/60 dark:border-gray-700/60 hover:shadow-lg hover:scale-105 transition-all duration-300 group">
                  <Settings className="h-4 w-4 lg:h-5 lg:w-5 text-gray-600 dark:text-gray-400 group-hover:text-blue-600 dark:group-hover:text-blue-400 group-hover:rotate-90 transition-all duration-300" />
                </Button>
              </Link>
              
              {/* User Profile - Enhanced Responsive */}
              <Link href="/profile">
                <div className="flex items-center space-x-1 sm:space-x-2 lg:space-x-4 px-2 sm:px-3 lg:px-6 py-1.5 sm:py-2 lg:py-3 rounded-lg lg:rounded-xl bg-white/90 dark:bg-slate-800/90 backdrop-blur-sm border border-gray-200/60 dark:border-gray-700/60 hover:shadow-lg hover:scale-105 transition-all duration-300 cursor-pointer group">
                  <div className="relative">
                    <div className="p-1 sm:p-2 lg:p-3 rounded-full bg-gradient-to-br from-blue-500 via-indigo-500 to-purple-500 shadow-lg group-hover:shadow-xl group-hover:scale-110 transition-all duration-300">
                      <User className="h-3 w-3 sm:h-4 sm:w-4 lg:h-5 lg:w-5 text-white" />
                    </div>
                    <div className="absolute -top-0.5 sm:-top-1 -right-0.5 sm:-right-1 w-3 h-3 sm:w-4 sm:h-4 bg-green-500 rounded-full border-2 border-white dark:border-slate-800 animate-pulse"></div>
                  </div>
                  {/* User Info - Hidden on mobile */}
                  <div className="text-left hidden sm:block">
                    <div className="flex items-center gap-2 sm:gap-3">
                      <p className="font-semibold text-gray-900 dark:text-white group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors text-sm sm:text-base">
                        {user?.username?.includes('_') ? user.username.split('_')[0] : user?.username}
                      </p>
                      <Badge className="bg-gradient-to-r from-emerald-500 to-green-500 text-white border-0 px-2 sm:px-3 py-1 text-xs font-bold shadow-lg">
                        PREMIUM
                      </Badge>
                    </div>
                    <p className="text-xs sm:text-sm text-gray-500 dark:text-gray-400 capitalize font-medium">
                      {user?.role} • Security Professional
                    </p>
                  </div>
                </div>
              </Link>
              
              {/* Logout Button - Mobile Icon, Desktop Text */}
              <Button
                variant="outline"
                onClick={logout}
                className="flex items-center space-x-1 sm:space-x-3 px-3 sm:px-6 py-2 sm:py-3 bg-red-50 dark:bg-red-900/20 border-red-200 dark:border-red-800 text-red-600 dark:text-red-400 hover:bg-red-100 dark:hover:bg-red-900/40 hover:shadow-lg hover:scale-105 transition-all duration-300 rounded-lg sm:rounded-xl font-semibold text-sm sm:text-base"
              >
                <LogOut className="h-4 w-4 sm:h-5 sm:w-5" />
                <span className="hidden sm:inline">Logout</span>
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content */}
      <main className="relative container mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 lg:py-12">
        {/* Welcome Hero Section */}
        <div className="mb-8 sm:mb-16">
          <div className="relative overflow-hidden rounded-2xl sm:rounded-3xl bg-gradient-to-br from-slate-900 via-blue-900 to-indigo-900 p-6 sm:p-12 lg:p-16 shadow-2xl border border-white/10">
            {/* Animated background elements */}
            <div className="absolute inset-0">
              <div className="absolute top-0 right-0 w-48 sm:w-80 lg:w-96 h-48 sm:h-80 lg:h-96 bg-gradient-to-br from-blue-500/20 to-purple-500/20 rounded-full blur-3xl transform translate-x-24 sm:translate-x-48 -translate-y-24 sm:-translate-y-48 animate-pulse"></div>
              <div className="absolute bottom-0 left-0 w-40 sm:w-64 lg:w-80 h-40 sm:h-64 lg:h-80 bg-gradient-to-tr from-cyan-500/15 to-blue-500/15 rounded-full blur-3xl transform -translate-x-16 sm:-translate-x-32 translate-y-16 sm:translate-y-32 animate-pulse delay-700"></div>
              <div className="absolute top-1/2 left-1/2 w-32 sm:w-48 lg:w-64 h-32 sm:h-48 lg:h-64 bg-gradient-to-r from-purple-500/10 to-pink-500/10 rounded-full blur-3xl transform -translate-x-1/2 -translate-y-1/2 animate-pulse delay-1000"></div>
            </div>
            
            {/* Grid pattern overlay */}
            <div className="absolute inset-0 bg-grid-white/[0.02] bg-[size:30px_30px] sm:bg-[size:60px_60px]"></div>
            
            {/* Content */}
            <div className="relative text-center max-w-7xl mx-auto">
              {/* Header Badge */}
              <div className="inline-flex items-center px-3 sm:px-6 py-2 sm:py-3 rounded-full bg-gradient-to-r from-blue-500/20 to-purple-500/20 backdrop-blur-sm border border-white/20 mb-6 sm:mb-8">
                <Shield className="h-4 w-4 sm:h-5 sm:w-5 text-blue-300 mr-2" />
                <span className="text-blue-200 text-xs sm:text-sm font-semibold tracking-wide uppercase">
                  Professional Cybersecurity Command Center
                </span>
              </div>
              
              {/* Main Heading */}
              <div className="mb-6 sm:mb-8">
                <h1 className="text-2xl sm:text-3xl md:text-4xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-white via-blue-100 to-white leading-tight mb-2 sm:mb-4">
                  Welcome back,
                </h1>
                <div className="relative">
                  <h2 className="text-2xl sm:text-3xl md:text-4xl lg:text-5xl font-bold text-transparent bg-clip-text bg-gradient-to-r from-blue-400 via-cyan-400 to-blue-500 leading-tight">
                    {user?.firstName || (user?.username?.includes('_') ? user.username.split('_')[0] : user?.username)}!
                  </h2>
                  <div className="absolute -top-1 -right-4 sm:-top-2 sm:-right-8 text-xl sm:text-2xl animate-bounce">🛡️</div>
                </div>
              </div>
              
              {/* Enhanced Description */}
              <p className="text-blue-100 text-sm sm:text-base lg:text-lg leading-relaxed mb-8 sm:mb-10 lg:mb-16 max-w-2xl sm:max-w-3xl lg:max-w-4xl mx-auto font-normal px-4 sm:px-6 lg:px-0">
                Your enterprise cybersecurity command center is operational. Access professional penetration testing tools, 
                AI-powered threat analysis, and comprehensive security assessments with our toolkit 
                trusted by security professionals worldwide.
              </p>
              
              {/* Professional Stats Grid */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4 lg:gap-6 mb-8 sm:mb-12 lg:mb-16 max-w-6xl mx-auto px-4 sm:px-6 lg:px-0">
                <div className="group relative">
                  <div className="absolute inset-0 rounded-2xl sm:rounded-3xl bg-gradient-to-br from-blue-500/30 to-purple-500/30 blur-xl group-hover:blur-2xl transition-all duration-300"></div>
                  <div className="relative text-center p-4 sm:p-8 rounded-2xl sm:rounded-3xl bg-gradient-to-br from-white/15 to-white/5 backdrop-blur-xl border border-white/20 hover:border-white/40 transition-all duration-500 hover:transform hover:scale-110">
                    <div className="text-xl sm:text-2xl font-bold text-white mb-1 sm:mb-2 group-hover:scale-105 transition-transform duration-300">{totalTools}</div>
                    <div className="text-blue-200 text-xs font-semibold uppercase tracking-wide">Security Tools</div>
                    <div className="w-8 sm:w-16 h-0.5 sm:h-1 bg-gradient-to-r from-blue-400 via-cyan-400 to-blue-500 rounded-full mx-auto mt-2 sm:mt-3"></div>
                  </div>
                </div>
                
                <div className="group relative">
                  <div className="absolute inset-0 rounded-2xl sm:rounded-3xl bg-gradient-to-br from-emerald-500/30 to-teal-500/30 blur-xl group-hover:blur-2xl transition-all duration-300"></div>
                  <div className="relative text-center p-4 sm:p-8 rounded-2xl sm:rounded-3xl bg-gradient-to-br from-white/15 to-white/5 backdrop-blur-xl border border-white/20 hover:border-white/40 transition-all duration-500 hover:transform hover:scale-110">
                    <div className="text-xl sm:text-2xl font-bold text-white mb-1 sm:mb-2 group-hover:scale-105 transition-transform duration-300">{securityTools.ai.length}</div>
                    <div className="text-emerald-200 text-xs font-semibold uppercase tracking-wide">AI-Powered</div>
                    <div className="w-8 sm:w-16 h-0.5 sm:h-1 bg-gradient-to-r from-emerald-400 via-teal-400 to-emerald-500 rounded-full mx-auto mt-2 sm:mt-3"></div>
                  </div>
                </div>
                
                <div className="group relative">
                  <div className="absolute inset-0 rounded-2xl sm:rounded-3xl bg-gradient-to-br from-orange-500/30 to-red-500/30 blur-xl group-hover:blur-2xl transition-all duration-300"></div>
                  <div className="relative text-center p-4 sm:p-8 rounded-2xl sm:rounded-3xl bg-gradient-to-br from-white/15 to-white/5 backdrop-blur-xl border border-white/20 hover:border-white/40 transition-all duration-500 hover:transform hover:scale-110">
                    <div className="text-xl sm:text-2xl font-bold text-white mb-1 sm:mb-2 group-hover:scale-105 transition-transform duration-300">24/7</div>
                    <div className="text-orange-200 text-xs font-semibold uppercase tracking-wide">Available</div>
                    <div className="w-8 sm:w-16 h-0.5 sm:h-1 bg-gradient-to-r from-orange-400 via-red-400 to-orange-500 rounded-full mx-auto mt-2 sm:mt-3"></div>
                  </div>
                </div>
                
                <div className="group relative">
                  <div className="absolute inset-0 rounded-2xl sm:rounded-3xl bg-gradient-to-br from-purple-500/30 to-pink-500/30 blur-xl group-hover:blur-2xl transition-all duration-300"></div>
                  <div className="relative text-center p-4 sm:p-8 rounded-2xl sm:rounded-3xl bg-gradient-to-br from-white/15 to-white/5 backdrop-blur-xl border border-white/20 hover:border-white/40 transition-all duration-500 hover:transform hover:scale-110">
                    <div className="text-xl sm:text-2xl font-bold text-white mb-1 sm:mb-2 group-hover:scale-105 transition-transform duration-300">∞</div>
                    <div className="text-purple-200 text-xs font-semibold uppercase tracking-wide">No Limits</div>
                    <div className="w-8 sm:w-16 h-0.5 sm:h-1 bg-gradient-to-r from-purple-400 via-pink-400 to-purple-500 rounded-full mx-auto mt-2 sm:mt-3"></div>
                  </div>
                </div>
              </div>

              {/* Professional CTA Buttons */}
              <div className="flex flex-col sm:flex-row items-center justify-center gap-4 sm:gap-6 px-4 sm:px-0">
                <Link href="/tools/ai/phishing-detection" className="w-full sm:w-auto">
                  <Button className="group relative overflow-hidden bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white border-0 shadow-2xl transition-all duration-300 px-6 sm:px-8 py-3 sm:py-4 text-sm sm:text-base font-semibold rounded-xl hover:scale-105 hover:shadow-blue-500/25 w-full sm:w-auto">
                    <div className="absolute inset-0 bg-gradient-to-r from-blue-400 to-purple-400 opacity-0 group-hover:opacity-30 transition-opacity duration-300"></div>
                    <div className="relative flex items-center justify-center">
                      <Bot className="h-5 w-5 sm:h-6 sm:w-6 mr-2 sm:mr-3 group-hover:rotate-12 transition-transform duration-300" />
                      Launch AI Security Suite
                      <Sparkles className="h-5 w-5 ml-3 group-hover:scale-125 transition-transform duration-300" />
                    </div>
                  </Button>
                </Link>
                
                <Link href="/tools">
                  <Button variant="outline" className="group relative overflow-hidden bg-transparent border-2 border-white/30 text-white hover:bg-white/10 hover:border-white/60 backdrop-blur-xl transition-all duration-300 px-8 py-4 text-base font-semibold rounded-xl hover:scale-105 shadow-2xl">
                    <div className="absolute inset-0 bg-gradient-to-r from-white/10 to-white/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                    <div className="relative flex items-center">
                      <Globe className="h-6 w-6 mr-3 group-hover:rotate-180 transition-transform duration-500" />
                      Explore Security Arsenal
                      <ChevronRight className="h-5 w-5 ml-3 group-hover:translate-x-2 transition-transform duration-300" />
                    </div>
                  </Button>
                </Link>
              </div>
              
              {/* Professional Badge */}
              <div className="mt-8 sm:mt-12 flex flex-col sm:flex-row items-center justify-center gap-3 sm:gap-6 lg:gap-8 text-blue-200/80 px-4">
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full bg-green-400 animate-pulse"></div>
                  <span className="text-xs sm:text-sm font-medium">All Systems Operational</span>
                </div>
                <div className="hidden sm:block h-4 w-px bg-white/20"></div>
                <div className="flex items-center gap-2">
                  <Shield className="w-4 h-4" />
                  <span className="text-xs sm:text-sm font-medium">Enterprise Security</span>
                </div>
                <div className="hidden sm:block h-4 w-px bg-white/20"></div>
                <div className="flex items-center gap-2">
                  <Lock className="w-4 h-4" />
                  <span className="text-xs sm:text-sm font-medium">Zero-Trust Architecture</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Dashboard Stats */}
        <div className="mb-6 sm:mb-8 px-4 sm:px-6 lg:px-8">
          <DashboardStats />
        </div>

        {/* Search/Filter Bar */}
        <div className="mb-6 sm:mb-8 px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center gap-4 justify-between">
          <div className="w-full sm:w-1/2">
            <input
              type="text"
              className="w-full px-4 py-3 rounded-xl border border-gray-200 dark:border-gray-700 bg-white dark:bg-slate-900 text-gray-900 dark:text-white focus:outline-none focus:ring-2 focus:ring-blue-500 text-sm sm:text-base font-medium placeholder:text-gray-500 dark:placeholder:text-gray-400"
              placeholder="🔍 Search tools by name, category, or difficulty..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
          </div>
          <div className="hidden sm:block text-sm text-gray-500 dark:text-gray-400">
            Showing {filterTools(securityTools.essential).length + filterTools(securityTools.advanced).length + filterTools(securityTools.expert).length + filterTools(securityTools.ai).length} of {totalTools} tools
          </div>
        </div>

        {/* Tools Grid */}
        <div className="grid grid-cols-1 xl:grid-cols-4 gap-6 sm:gap-8 px-4 sm:px-6 lg:px-8">
          {/* Enhanced Tools Sections */}
          <div className="xl:col-span-3 space-y-12 sm:space-y-16">
            {/* Essential Tools Section */}
            <section>
              <div className="text-center mb-8 sm:mb-12">
                <div className="inline-flex items-center justify-center p-2 sm:p-3 rounded-2xl bg-gradient-to-r from-green-100 to-emerald-100 mb-4 sm:mb-6">
                  <Shield className="h-6 w-6 sm:h-8 sm:w-8 text-green-600 mr-2 sm:mr-3" />
                  <div className="text-left">
                    <h3 className="text-lg sm:text-xl font-bold bg-gradient-to-r from-green-600 to-emerald-600 bg-clip-text text-transparent">
                      Essential Security Tools
                    </h3>
                    <p className="text-green-700 text-sm sm:text-base font-medium mt-1 hidden sm:block">Perfect for beginners and daily security tasks</p>
                  </div>
                </div>
                <div className="flex justify-center">
                  <Badge className="bg-green-500/10 text-green-600 border border-green-200 dark:border-green-800 px-4 sm:px-6 py-2 text-sm font-semibold">
                    <Shield className="w-4 h-4 mr-2" />
                    {securityTools.essential.length} Tools • All Unlocked
                  </Badge>
                </div>
              </div>

              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-2 xl:grid-cols-3 gap-4 sm:gap-6 lg:gap-8">
                {filterTools(securityTools.essential).map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card className="group h-full relative overflow-hidden bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm border-2 border-gray-100 dark:border-gray-700 hover:border-green-300 dark:hover:border-green-700 hover:shadow-2xl hover:shadow-green-500/20 transition-all duration-500 cursor-pointer transform hover:-translate-y-3 hover:scale-105">
                        <div className="absolute inset-0 bg-gradient-to-br from-green-500/5 to-emerald-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                        <CardHeader className="relative p-6">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start space-x-4">
                              <div className={`p-4 rounded-2xl ${tool.bgColor} group-hover:scale-110 transition-transform duration-300 shadow-lg`}>
                                <IconComponent className={`h-8 w-8 ${tool.color}`} />
                              </div>
                              <div className="flex-1">
                                <CardTitle className="text-lg font-semibold text-gray-900 dark:text-white group-hover:text-green-600 dark:group-hover:text-green-400 transition-colors duration-300 mb-3">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-3">
                                  <Badge variant="secondary" className="text-xs font-semibold px-3 py-1">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs font-semibold px-3 py-1 ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="relative">
                              <div className="w-3 h-3 rounded-full bg-green-500 animate-pulse"></div>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent className="px-6 pb-6">
                          <CardDescription className="text-gray-600 dark:text-gray-400 group-hover:text-gray-700 dark:group-hover:text-gray-300 transition-colors duration-300 text-base leading-relaxed mb-4">
                            {tool.description}
                          </CardDescription>
                          <div className="flex justify-between items-center opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                            <span className="text-green-600 dark:text-green-400 text-sm font-semibold">Ready to Launch</span>
                            <div className="flex items-center text-green-600 dark:text-green-400 text-sm font-medium">
                              Start Tool
                              <ChevronRight className="w-4 h-4 ml-1 group-hover:translate-x-1 transition-transform" />
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </section>

            {/* Advanced Tools Section */}
            <section>
              <div className="text-center mb-12">
                <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-gradient-to-r from-orange-100 to-red-100 mb-6">
                  <Target className="h-8 w-8 text-orange-600 mr-3" />
                  <div className="text-left">
                    <h3 className="text-lg sm:text-xl font-bold bg-gradient-to-r from-orange-600 to-red-600 bg-clip-text text-transparent">
                      Advanced Security Arsenal
                    </h3>
                    <p className="text-orange-700 text-sm font-medium mt-1">Professional-grade security and analysis tools</p>
                  </div>
                </div>
                <div className="flex justify-center">
                  <Badge className="bg-orange-500/10 text-orange-600 border border-orange-200 dark:border-orange-800 px-6 py-2 text-sm">
                    <Target className="w-4 h-4 mr-2" />
                    {securityTools.advanced.length} Tools • All Unlocked
                  </Badge>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-8">
                {filterTools(securityTools.advanced).map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card className="group h-full relative overflow-hidden bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm border-2 border-gray-100 dark:border-gray-700 hover:border-orange-300 dark:hover:border-orange-700 hover:shadow-2xl hover:shadow-orange-500/20 transition-all duration-500 cursor-pointer transform hover:-translate-y-3 hover:scale-105">
                        <div className="absolute inset-0 bg-gradient-to-br from-orange-500/5 to-red-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                        
                        <CardHeader className="relative p-6">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start space-x-4">
                              <div className={`p-4 rounded-2xl ${tool.bgColor} group-hover:scale-110 transition-transform duration-300 shadow-lg`}>
                                <IconComponent className={`h-8 w-8 ${tool.color}`} />
                              </div>
                              <div className="flex-1">
                                <CardTitle className="text-xl font-bold text-gray-900 dark:text-white group-hover:text-orange-600 dark:group-hover:text-orange-400 transition-colors duration-300 mb-3">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-2 mt-2">
                                  <Badge variant="secondary" className="text-xs">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="relative">
                              <div className="w-2 h-2 rounded-full bg-orange-500"></div>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <CardDescription className="text-gray-600 dark:text-gray-400 group-hover:text-gray-700 dark:group-hover:text-gray-300 transition-colors duration-300">
                            {tool.description}
                          </CardDescription>
                          
                          <div className="flex justify-end mt-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                            <div className="flex items-center text-orange-600 dark:text-orange-400 text-sm font-medium">
                              Launch Tool
                              <ChevronRight className="w-4 h-4 ml-1" />
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </section>

            {/* Expert Tools */}
            <section>
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h3 className="text-lg sm:text-xl font-bold bg-gradient-to-r from-red-600 to-purple-600 bg-clip-text text-transparent">
                    Expert Arsenal
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400 mt-2">Elite-level exploitation and analysis frameworks</p>
                </div>
                <Badge className="bg-red-500/10 text-red-600 border border-red-200 dark:border-red-800 px-3 py-1">
                  <Zap className="w-3 h-3 mr-1" />
                  {securityTools.expert.length} Tools • All Unlocked
                </Badge>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filterTools(securityTools.expert).map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card className="group h-full relative overflow-hidden bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border hover:shadow-2xl hover:shadow-red-500/10 transition-all duration-500 cursor-pointer transform hover:-translate-y-2">
                        <div className="absolute inset-0 bg-gradient-to-br from-red-500/5 to-purple-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                        
                        <CardHeader className="relative">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start space-x-3">
                              <div className={`p-3 rounded-xl ${tool.bgColor} group-hover:scale-110 transition-transform duration-300`}>
                                <IconComponent className={`h-6 w-6 ${tool.color}`} />
                              </div>
                              <div className="flex-1">
                                <CardTitle className="text-lg font-bold text-gray-900 dark:text-white group-hover:text-red-600 dark:group-hover:text-red-400 transition-colors duration-300">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-2 mt-2">
                                  <Badge variant="secondary" className="text-xs">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                </div>
                              </div>
                            </div>
                            <div className="relative">
                              <div className="w-2 h-2 rounded-full bg-red-500"></div>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <CardDescription className="text-gray-600 dark:text-gray-400 group-hover:text-gray-700 dark:group-hover:text-gray-300 transition-colors duration-300">
                            {tool.description}
                          </CardDescription>
                          
                          <div className="flex justify-end mt-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                            <div className="flex items-center text-red-600 dark:text-red-400 text-sm font-medium">
                              Launch Tool
                              <ChevronRight className="w-4 h-4 ml-1" />
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </section>

            {/* AI Cybersecurity Tools */}
            <section>
              <div className="flex items-center justify-between mb-8">
                <div>
                  <h3 className="text-lg sm:text-xl font-bold bg-gradient-to-r from-emerald-600 to-teal-600 bg-clip-text text-transparent">
                    AI-Powered Cybersecurity
                  </h3>
                  <p className="text-gray-600 dark:text-gray-400 mt-2">Next-generation artificial intelligence security solutions</p>
                </div>
                <Badge className="bg-emerald-500/10 text-emerald-600 border border-emerald-200 dark:border-emerald-800 px-3 py-1">
                  <Brain className="w-3 h-3 mr-1" />
                  {securityTools.ai.length} AI Tools • All Unlocked
                </Badge>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {filterTools(securityTools.ai).map((tool, index) => {
                  const IconComponent = tool.icon
                  return (
                    <Link key={tool.name} href={tool.path}>
                      <Card className="group h-full relative overflow-hidden bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border hover:shadow-2xl hover:shadow-emerald-500/10 transition-all duration-500 cursor-pointer transform hover:-translate-y-2">
                        <div className="absolute inset-0 bg-gradient-to-br from-emerald-500/5 to-teal-500/5 opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                        
                        <CardHeader className="relative">
                          <div className="flex items-start justify-between">
                            <div className="flex items-start space-x-3">
                              <div className={`relative p-3 rounded-xl ${tool.bgColor} group-hover:scale-110 transition-transform duration-300`}>
                                <IconComponent className={`h-6 w-6 ${tool.color}`} />
                                <div className="absolute -top-1 -right-1 w-4 h-4 bg-gradient-to-br from-emerald-500 to-teal-500 rounded-full flex items-center justify-center">
                                  <Sparkles className="w-2.5 h-2.5 text-white" />
                                </div>
                              </div>
                              <div className="flex-1">
                                <CardTitle className="text-lg font-bold text-gray-900 dark:text-white group-hover:text-emerald-600 dark:group-hover:text-emerald-400 transition-colors duration-300">
                                  {tool.name}
                                </CardTitle>
                                <div className="flex items-center gap-2 mt-2">
                                  <Badge variant="secondary" className="text-xs">
                                    {tool.category}
                                  </Badge>
                                  <Badge className={`text-xs ${getDifficultyColor(tool.difficulty)}`}>
                                    {tool.difficulty}
                                  </Badge>
                                  {tool.isNew && (
                                    <Badge className="text-xs bg-emerald-500 text-white">
                                      NEW
                                    </Badge>
                                  )}
                                </div>
                              </div>
                            </div>
                            <div className="relative">
                              <div className="w-2 h-2 rounded-full bg-emerald-500"></div>
                            </div>
                          </div>
                        </CardHeader>
                        <CardContent>
                          <CardDescription className="text-gray-600 dark:text-gray-400 group-hover:text-gray-700 dark:group-hover:text-gray-300 transition-colors duration-300">
                            {tool.description}
                          </CardDescription>
                          
                          <div className="flex justify-end mt-4 opacity-0 group-hover:opacity-100 transition-opacity duration-300">
                            <div className="flex items-center text-emerald-600 dark:text-emerald-400 text-sm font-medium">
                              Launch AI Tool
                              <ChevronRight className="w-4 h-4 ml-1" />
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    </Link>
                  )
                })}
              </div>
            </section>
          </div>

          {/* Sidebar */}
          <div className="space-y-6">
            <RecentActivity />
            
            {/* Quick Launch */}
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5 text-blue-600" />
                  Quick Launch
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <Link href="/tools/network-scan">
                  <Button variant="outline" className="w-full justify-start">
                    <Globe className="h-4 w-4 mr-2" />
                    Network Scan
                  </Button>
                </Link>
                <Link href="/tools/ai/phishing-detection">
                  <Button variant="outline" className="w-full justify-start">
                    <Mail className="h-4 w-4 mr-2" />
                    AI Phishing Detection
                  </Button>
                </Link>
                <Link href="/tools/vuln-scanner">
                  <Button variant="outline" className="w-full justify-start">
                    <AlertTriangle className="h-4 w-4 mr-2" />
                    Vulnerability Scanner
                  </Button>
                </Link>
              </CardContent>
            </Card>

            {/* System Status */}
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Activity className="h-5 w-5 text-green-600" />
                  System Status
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm">All Tools</span>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-green-500"></div>
                    <span className="text-sm text-green-600">Active</span>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">AI Systems</span>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-green-500"></div>
                    <span className="text-sm text-green-600">Online</span>
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm">Database</span>
                  <div className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full bg-green-500"></div>
                    <span className="text-sm text-green-600">Connected</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Professional Footer */}
        <footer className="relative mt-32 border-t border-white/10 dark:border-gray-800/30">
          {/* Background Effects */}
          <div className="absolute inset-0 bg-gradient-to-t from-slate-950 via-slate-900 to-transparent dark:from-slate-950 dark:via-slate-900 dark:to-transparent opacity-95"></div>
          <div className="absolute inset-0 bg-[radial-gradient(circle_at_center,rgba(59,130,246,0.1),transparent_50%)]"></div>
          
          <div className="relative container mx-auto px-6 py-20">
            {/* Main Footer Content */}
            <div className="text-center mb-16">
              <div className="inline-flex items-center justify-center space-x-6 mb-8">
                <div className="relative group">
                  <div className="absolute inset-0 rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-600 animate-pulse opacity-75 group-hover:opacity-100 transition-opacity"></div>
                  <div className="relative p-4 rounded-2xl bg-gradient-to-br from-blue-600 to-indigo-600 shadow-2xl">
                    <Shield className="h-10 w-10 text-white" />
                  </div>
                </div>
                <div className="text-left">
                  <h3 className="text-xl sm:text-2xl font-bold bg-gradient-to-r from-blue-400 via-indigo-400 to-purple-400 bg-clip-text text-transparent mb-2">
                    CyberShield
                  </h3>
                  <p className="text-base sm:text-lg font-semibold text-gray-300 dark:text-gray-400 tracking-wide">
                    Professional Cybersecurity Platform
                  </p>
                </div>
              </div>
              
              <p className="text-base sm:text-lg text-gray-300 dark:text-gray-300 leading-relaxed font-normal max-w-3xl mx-auto mb-12">
                Empowering cybersecurity professionals with enterprise-grade tools, 
                AI-powered intelligence, and comprehensive security solutions.
              </p>
            </div>
            
            {/* Feature Grid */}
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-8 mb-16">
              <div className="group text-center">
                <div className="relative mb-6">
                  <div className="inline-flex items-center justify-center p-6 rounded-3xl bg-gradient-to-br from-green-500/20 to-emerald-500/20 border border-green-500/30 backdrop-blur-sm group-hover:scale-110 transition-transform duration-300">
                    <Target className="h-10 w-10 text-green-400" />
                  </div>
                  <div className="absolute -top-2 -right-2 w-6 h-6 bg-green-500 rounded-full border-2 border-slate-900 animate-pulse"></div>
                </div>
                <h4 className="text-base sm:text-lg font-semibold text-white mb-3">24+ Professional Tools</h4>
                <p className="text-gray-400 leading-relaxed text-sm sm:text-base">
                  Comprehensive suite of enterprise-grade security testing utilities
                </p>
              </div>
              
              <div className="group text-center">
                <div className="relative mb-6">
                  <div className="inline-flex items-center justify-center p-6 rounded-3xl bg-gradient-to-br from-blue-500/20 to-indigo-500/20 border border-blue-500/30 backdrop-blur-sm group-hover:scale-110 transition-transform duration-300">
                    <Brain className="h-10 w-10 text-blue-400" />
                  </div>
                  <div className="absolute -top-2 -right-2 w-6 h-6 bg-blue-500 rounded-full border-2 border-slate-900 animate-pulse"></div>
                </div>
                <h4 className="text-base sm:text-lg font-semibold text-white mb-3">AI-Powered Intelligence</h4>
                <p className="text-gray-400 leading-relaxed text-sm sm:text-base">
                  Next-generation artificial intelligence for advanced threat detection
                </p>
              </div>
              
              <div className="group text-center">
                <div className="relative mb-6">
                  <div className="inline-flex items-center justify-center p-6 rounded-3xl bg-gradient-to-br from-purple-500/20 to-pink-500/20 border border-purple-500/30 backdrop-blur-sm group-hover:scale-110 transition-transform duration-300">
                    <Lock className="h-10 w-10 text-purple-400" />
                  </div>
                  <div className="absolute -top-2 -right-2 w-6 h-6 bg-purple-500 rounded-full border-2 border-slate-900 animate-pulse"></div>
                </div>
                <h4 className="text-base sm:text-lg font-semibold text-white mb-3">Enterprise Security</h4>
                <p className="text-gray-400 leading-relaxed text-sm sm:text-base">
                  Military-grade encryption and security protocols for data protection
                </p>
              </div>
              
              <div className="group text-center">
                <div className="relative mb-6">
                  <div className="inline-flex items-center justify-center p-6 rounded-3xl bg-gradient-to-br from-orange-500/20 to-red-500/20 border border-orange-500/30 backdrop-blur-sm group-hover:scale-110 transition-transform duration-300">
                    <Zap className="h-10 w-10 text-orange-400" />
                  </div>
                  <div className="absolute -top-2 -right-2 w-6 h-6 bg-orange-500 rounded-full border-2 border-slate-900 animate-pulse"></div>
                </div>
                <h4 className="text-base sm:text-lg font-semibold text-white mb-3">Real-time Analysis</h4>
                <p className="text-gray-400 leading-relaxed text-sm sm:text-base">
                  Instant vulnerability assessment and continuous security monitoring
                </p>
              </div>
            </div>
            
            {/* Bottom Footer */}
            <div className="border-t border-gray-800/50 pt-8">
              <div className="flex flex-col md:flex-row items-center justify-between space-y-4 md:space-y-0">
                <div className="flex items-center space-x-6 text-gray-400">
                  <span className="text-sm sm:text-base font-semibold">© 2025 CyberShield</span>
                  <span className="hidden md:block">•</span>
                  <span className="text-xs sm:text-sm font-medium">Professional Cybersecurity Platform</span>
                  <span className="hidden md:block">•</span>
                  <div className="flex items-center space-x-2">
                    <div className="w-3 h-3 bg-green-500 rounded-full animate-pulse"></div>
                    <span className="text-sm font-semibold text-green-400">All Systems Operational</span>
                  </div>
                </div>
                
                <div className="flex items-center space-x-3">
                  <Badge className="bg-gradient-to-r from-blue-500/20 to-indigo-500/20 text-blue-300 border-blue-500/30 px-3 py-2 text-xs font-semibold backdrop-blur-sm">
                    <Shield className="w-3 h-3 mr-1" />
                    PREMIUM UNLOCKED
                  </Badge>
                  <Badge className="bg-gradient-to-r from-green-500/20 to-emerald-500/20 text-green-300 border-green-500/30 px-3 py-2 text-xs font-semibold backdrop-blur-sm">
                    <Zap className="w-3 h-3 mr-1" />
                    ALL TOOLS ACTIVE
                  </Badge>
                </div>
              </div>
            </div>
          </div>
          
          {/* Animated Background Elements */}
          <div className="absolute bottom-0 left-0 w-full h-1 bg-gradient-to-r from-blue-500 via-indigo-500 to-purple-500 opacity-60 animate-pulse"></div>
        </footer>
      </main>
    </div>
  )
}
