"use client"

import { useState } from "react"
import { useAuth } from "@/src/auth/utils/AuthContext"
import { ThemeToggle } from "@/src/ui/components/ThemeToggle"
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Badge } from "@/src/ui/components/ui/badge"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/src/ui/components/ui/dialog"
import {
  Shield,
  Search,
  Info,
  NetworkIcon as Dns,
  FileText,
  LogOut,
  User,
  Globe,
  Target,
  Terminal,
  Eye,
  Zap,
  Lock,
  Crown,
  Star,
  ArrowRight,
  CheckCircle,
  X
} from "lucide-react"
import Link from "next/link"

// All tools are now FREE and UNLOCKED - no restrictions!
const ALL_UNLOCKED_TOOLS = [
  {
    name: "WHOIS Lookup",
    path: "/tools/whois",
    category: "OSINT",
    difficulty: "Beginner",
    description: "Get domain registration information",
    icon: Info,
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  },
  {
    name: "DNS Information",
    path: "/tools/dns-lookup",
    category: "Network",
    difficulty: "Beginner",
    description: "Retrieve DNS records and zone information",
    icon: Dns,
    color: "text-yellow-500",
    bgColor: "bg-yellow-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  },
  {
    name: "HTTP Headers",
    path: "/tools/http-headers",
    category: "Web Security",
    difficulty: "Beginner",
    description: "Analyze HTTP response headers",
    icon: FileText,
    color: "text-cyan-500",
    bgColor: "bg-cyan-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  },
  {
    name: "Network Scanner",
    path: "/tools/network-scanner",
    category: "Network",
    difficulty: "Beginner",
    description: "Comprehensive network discovery and port scanning",
    icon: Globe,
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  },
  {
    name: "Port Scanner",
    path: "/tools/port-scanner",
    category: "Network",
    difficulty: "Beginner",
    description: "Scan for open ports on target systems using Nmap",
    icon: Shield,
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  },
  {
    name: "Subdomain Enumeration",
    path: "/tools/subdomain-enum",
    category: "Reconnaissance",
    difficulty: "Beginner",
    description: "Discover subdomains using Sublist3r and AssetFinder",
    icon: Search,
    color: "text-green-500",
    bgColor: "bg-green-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  },
  {
    name: "Ping Sweep",
    path: "/tools/ping-sweep",
    category: "Network",
    difficulty: "Beginner",
    description: "Discover live hosts using ICMP ping sweeps",
    icon: Target,
    color: "text-indigo-500",
    bgColor: "bg-indigo-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  },
  {
    name: "Masscan",
    path: "/tools/masscan",
    category: "Network",
    difficulty: "Advanced",
    description: "High-speed port scanner for large networks",
    icon: Target,
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  },
  {
    name: "Directory Buster",
    path: "/tools/directory-buster",
    category: "Web Security",
    difficulty: "Intermediate",
    description: "Discover hidden directories and files",
    icon: Terminal,
    color: "text-pink-500",
    bgColor: "bg-pink-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  },
  {
    name: "Metasploit Framework",
    path: "/tools/metasploit",
    category: "Exploitation",
    difficulty: "Expert",
    description: "Advanced exploitation framework for penetration testing",
    icon: Zap,
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    accessLevel: "free" as const,
    isUnlocked: true
  }
]

type ToolConfig = typeof ALL_UNLOCKED_TOOLS[0]

// Helper functions
function getDifficultyColor(difficulty: string): string {
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

interface ToolCardProps {
  tool: ToolConfig
}

function ToolCard({ tool }: ToolCardProps) {
  const IconComponent = tool.icon
  
  return (
    <Link href={tool.path}>
      <Card className="group relative overflow-hidden h-full bg-white/60 dark:bg-slate-900/60 backdrop-blur-sm border-0 shadow-lg hover:shadow-2xl transition-all duration-500 hover:scale-[1.02] cursor-pointer">
        {/* Gradient Background */}
        <div className="absolute inset-0 bg-gradient-to-br from-white via-slate-50 to-blue-50 dark:from-slate-900 dark:via-slate-800 dark:to-indigo-900/50 opacity-0 group-hover:opacity-100 transition-opacity duration-500"></div>
        
        {/* Animated Border */}
        <div className="absolute inset-0 bg-gradient-to-r from-blue-500/20 via-purple-500/20 to-indigo-500/20 opacity-0 group-hover:opacity-100 transition-opacity duration-500 rounded-lg"></div>
        
        {/* Content */}
        <div className="relative z-10">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between mb-3">
              <div className="flex items-center space-x-4">
                <div className={`relative p-4 rounded-2xl ${tool.bgColor} group-hover:scale-110 transition-all duration-300`}>
                  <div className="absolute inset-0 bg-gradient-to-r from-blue-500/10 to-purple-500/10 rounded-2xl opacity-0 group-hover:opacity-100 transition-opacity duration-300"></div>
                  <IconComponent className={`h-6 w-6 ${tool.color} relative z-10`} />
                </div>
              </div>
              <div className="flex items-center space-x-2">
                <Badge className="bg-green-500/10 text-green-600 dark:text-green-400 border-green-500/20 text-xs px-2 py-1">
                  <CheckCircle className="h-3 w-3 mr-1" />
                  FREE
                </Badge>
              </div>
            </div>
            
            <CardTitle className="text-lg font-semibold group-hover:text-blue-600 dark:group-hover:text-blue-400 transition-colors duration-200 mb-2">
              {tool.name}
            </CardTitle>
            
            <div className="flex items-center gap-2 mb-3">
              <Badge variant="outline" className="text-xs px-2 py-1 bg-slate-100 dark:bg-slate-800 border-slate-200 dark:border-slate-700">
                {tool.category}
              </Badge>
              <Badge className={`text-xs px-2 py-1 border-0 ${getDifficultyColor(tool.difficulty)}`}>
                {tool.difficulty}
              </Badge>
            </div>
          </CardHeader>
          
          <CardContent className="pt-0">
            <CardDescription className="text-slate-600 dark:text-slate-400 group-hover:text-slate-700 dark:group-hover:text-slate-300 transition-colors duration-200 text-sm leading-relaxed">
              {tool.description}
            </CardDescription>
            
            <div className="mt-4 flex items-center text-xs text-blue-600 dark:text-blue-400 opacity-0 group-hover:opacity-100 transition-all duration-300 font-medium">
              <span>Launch Tool</span>
              <ArrowRight className="h-3 w-3 ml-1 group-hover:translate-x-1 transition-transform duration-200" />
            </div>
          </CardContent>
        </div>
      </Card>
    </Link>
  )
}

export default function PublicDashboard() {
  const { user, logout, isAuthenticated } = useAuth()

  const getUserDisplayName = () => {
    if (!user) return ''
    if (user.firstName) {
      return user.firstName
    }
    // Extract first name from username if it contains underscore
    if (user.username?.includes('_')) {
      return user.username.split('_')[0]
    }
    return user.username
  }

  const getWelcomeMessage = () => {
    if (isAuthenticated) {
      return `Welcome back, ${getUserDisplayName()}! 👋`
    }
    return 'CyberShield'
  }

  // Categorize tools by difficulty for better organization
  const beginnerTools = ALL_UNLOCKED_TOOLS.filter(tool => tool.difficulty === 'Beginner')
  const intermediateTools = ALL_UNLOCKED_TOOLS.filter(tool => tool.difficulty === 'Intermediate')
  const advancedTools = ALL_UNLOCKED_TOOLS.filter(tool => tool.difficulty === 'Advanced')
  const expertTools = ALL_UNLOCKED_TOOLS.filter(tool => tool.difficulty === 'Expert')

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-50 dark:from-slate-950 dark:via-slate-900 dark:to-indigo-950">
      {/* Enhanced Header */}
      <header className="sticky top-0 z-50 backdrop-blur-xl bg-white/80 dark:bg-slate-900/80 border-b border-slate-200/50 dark:border-slate-800/50 shadow-lg">
        <div className="container mx-auto px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="relative">
                <div className="absolute inset-0 bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl blur opacity-75 animate-pulse"></div>
                <div className="relative p-3 bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl">
                  <Shield className="h-7 w-7 text-white" />
                </div>
              </div>
              <div>
                <h1 className="text-2xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
                  CyberShield
                </h1>
                <p className="text-sm text-slate-600 dark:text-slate-400">Professional Security Toolkit</p>
              </div>
            </div>
            
            <div className="flex items-center space-x-4">
              <ThemeToggle />
              {isAuthenticated ? (
                <>
                  <Link href="/dashboard">
                    <Button variant="outline" size="sm" className="hidden sm:flex">
                      <User className="h-4 w-4 mr-2" />
                      Dashboard
                    </Button>
                  </Link>
                  <div className="flex items-center space-x-3 px-4 py-2 rounded-lg bg-slate-100 dark:bg-slate-800">
                    <div className="p-1.5 rounded-full bg-gradient-to-r from-blue-500 to-purple-500">
                      <User className="h-3.5 w-3.5 text-white" />
                    </div>
                    <div className="text-sm">
                      <p className="font-medium">{user?.username}</p>
                      <p className="text-xs text-slate-600 dark:text-slate-400 capitalize">{user?.role}</p>
                    </div>
                  </div>
                  <Button variant="outline" size="sm" onClick={logout}>
                    <LogOut className="h-4 w-4" />
                  </Button>
                </>
              ) : (
                <div className="flex items-center space-x-3">
                  <Link href="/login">
                    <Button variant="ghost" size="sm" className="font-medium">
                      Sign In
                    </Button>
                  </Link>
                  <Link href="/register">
                    <Button size="sm" className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 shadow-lg">
                      Get Started
                    </Button>
                  </Link>
                </div>
              )}
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-600/10 via-purple-600/5 to-indigo-600/10"></div>
        <div className="relative container mx-auto px-6 py-16">
          <div className="text-center max-w-4xl mx-auto">
            <div className="inline-flex items-center px-4 py-2 rounded-full bg-blue-100 dark:bg-blue-900/30 text-blue-700 dark:text-blue-300 text-sm font-medium mb-6">
              <Shield className="h-4 w-4 mr-2" />
              Penetration Testing Platform
            </div>
            
            <h2 className="text-5xl md:text-6xl font-bold mb-6">
              <span className="bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                {getWelcomeMessage()}
              </span>
            </h2>
            
            <p className="text-xl text-slate-600 dark:text-slate-400 mb-8 leading-relaxed">
              {isAuthenticated 
                ? 'Professional cybersecurity tools for security assessments and penetration testing.'
                : 'Real-world security tools for penetration testers and ethical hackers.'
              }
            </p>

            <div className="flex flex-col sm:flex-row gap-4 justify-center items-center">
              <div className="flex items-center space-x-2 text-green-600 dark:text-green-400">
                <CheckCircle className="h-5 w-5" />
                <span className="font-medium">All Tools Free</span>
              </div>
              <div className="flex items-center space-x-2 text-blue-600 dark:text-blue-400">
                <Shield className="h-5 w-5" />
                <span className="font-medium">Professional Grade</span>
              </div>
              <div className="flex items-center space-x-2 text-purple-600 dark:text-purple-400">
                <Target className="h-5 w-5" />
                <span className="font-medium">Real Tools</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Enhanced Tools Grid */}
      <main className="container mx-auto px-6 py-12">
        <div className="space-y-16">
          {/* Essential Security Tools */}
          <div className="relative">
            <div className="text-center mb-12">
              <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-gradient-to-r from-green-500 to-emerald-500 shadow-lg mb-4">
                <CheckCircle className="h-6 w-6 text-white" />
              </div>
              <h3 className="text-3xl font-bold mb-3 bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                Security Tools
              </h3>
              <p className="text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
                Cybersecurity tools for security assessments and penetration testing
              </p>
              <div className="mt-4 inline-flex items-center px-4 py-2 rounded-full bg-green-100 dark:bg-green-900/30 text-green-700 dark:text-green-300">
                <span className="font-medium">{beginnerTools.length} Tools • All FREE</span>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6">
              {beginnerTools.map((tool) => (
                <div key={tool.name} className="animate-fade-in">
                  <ToolCard tool={tool} />
                </div>
              ))}
            </div>
          </div>

          {/* Advanced Security Tools */}
          {(intermediateTools.length > 0 || advancedTools.length > 0) && (
            <div className="relative">
              <div className="text-center mb-12">
                <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-gradient-to-r from-orange-500 to-red-500 shadow-lg mb-4">
                  <Target className="h-6 w-6 text-white" />
                </div>
                <h3 className="text-3xl font-bold mb-3 bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                  Advanced Tools
                </h3>
                <p className="text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
                  Advanced penetration testing and security analysis tools
                </p>
                <div className="mt-4 inline-flex items-center px-4 py-2 rounded-full bg-orange-100 dark:bg-orange-900/30 text-orange-700 dark:text-orange-300">
                  <span className="font-medium">{intermediateTools.length + advancedTools.length} Tools • All FREE</span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {[...intermediateTools, ...advancedTools].map((tool) => (
                  <div key={tool.name} className="animate-fade-in">
                    <ToolCard tool={tool} />
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Expert Exploitation Tools */}
          {expertTools.length > 0 && (
            <div className="relative">
              <div className="text-center mb-12">
                <div className="inline-flex items-center justify-center p-3 rounded-2xl bg-gradient-to-r from-red-600 to-purple-600 shadow-lg mb-4">
                  <Zap className="h-6 w-6 text-white" />
                </div>
                <h3 className="text-3xl font-bold mb-3 bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                  Expert Tools
                </h3>
                <p className="text-lg text-slate-600 dark:text-slate-400 max-w-2xl mx-auto">
                  Exploitation frameworks and advanced security testing tools
                </p>
                <div className="mt-4 inline-flex items-center px-4 py-2 rounded-full bg-red-100 dark:bg-red-900/30 text-red-700 dark:text-red-300">
                  <span className="font-medium">{expertTools.length} Tools • All FREE</span>
                </div>
              </div>

              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
                {expertTools.map((tool, index) => (
                  <div
                    key={tool.name}
                    className="animate-fade-in"
                    style={{ animationDelay: `${index * 100}ms` }}
                  >
                    <ToolCard tool={tool} />
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Enhanced Call to Action for Non-Authenticated Users */}
        {!isAuthenticated && (
          <section className="relative mt-20">
            <div className="absolute inset-0 bg-gradient-to-r from-blue-600/10 via-purple-600/5 to-indigo-600/10 rounded-3xl"></div>
            <div className="relative p-12 text-center">
              <div className="max-w-4xl mx-auto">
                <div className="inline-flex items-center justify-center p-4 rounded-3xl bg-gradient-to-r from-blue-600 to-purple-600 shadow-xl mb-6">
                  <Crown className="h-8 w-8 text-white" />
                </div>
                
                <h3 className="text-4xl font-bold mb-6 bg-gradient-to-r from-slate-900 to-slate-700 dark:from-white dark:to-slate-300 bg-clip-text text-transparent">
                  Join the Security Community
                </h3>
                
                <p className="text-xl text-slate-600 dark:text-slate-400 mb-8 max-w-3xl mx-auto leading-relaxed">
                  Get access to all penetration testing tools, save your security assessments, 
                  and join security professionals using CyberShield.
                </p>

                <div className="flex flex-col sm:flex-row gap-4 justify-center mb-8">
                  <Link href="/register">
                    <Button size="lg" className="bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white shadow-xl hover:shadow-2xl transition-all duration-300 px-8 py-4 text-lg font-semibold">
                      Create Free Account
                      <ArrowRight className="ml-2 h-5 w-5" />
                    </Button>
                  </Link>
                  <Link href="/login">
                    <Button variant="outline" size="lg" className="border-2 hover:bg-slate-50 dark:hover:bg-slate-800 px-8 py-4 text-lg">
                      Sign In
                    </Button>
                  </Link>
                </div>

                <div className="grid grid-cols-1 sm:grid-cols-3 gap-6 max-w-3xl mx-auto">
                  <div className="flex items-center justify-center space-x-3">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                    <span className="text-slate-700 dark:text-slate-300 font-medium">All Tools Free Forever</span>
                  </div>
                  <div className="flex items-center justify-center space-x-3">
                    <Shield className="h-5 w-5 text-blue-500" />
                    <span className="text-slate-700 dark:text-slate-300 font-medium">Professional Grade</span>
                  </div>
                  <div className="flex items-center justify-center space-x-3">
                    <Target className="h-5 w-5 text-purple-500" />
                    <span className="text-slate-700 dark:text-slate-300 font-medium">No Limitations</span>
                  </div>
                </div>
              </div>
            </div>
          </section>
        )}
      </main>

      {/* Enhanced Footer */}
      <footer className="relative mt-20 bg-slate-900 dark:bg-slate-950 text-white">
        <div className="absolute inset-0 bg-gradient-to-r from-blue-900/20 to-purple-900/20"></div>
        <div className="relative container mx-auto px-6 py-12">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-8">
            <div className="col-span-1 md:col-span-2">
              <div className="flex items-center space-x-3 mb-4">
                <div className="p-2 bg-gradient-to-r from-blue-600 to-purple-600 rounded-xl">
                  <Shield className="h-6 w-6 text-white" />
                </div>
                <div>
                  <h3 className="text-xl font-bold">CyberShield</h3>
                  <p className="text-slate-400 text-sm">Professional Security Platform</p>
                </div>
              </div>
              <p className="text-slate-400 mb-4 max-w-md">
                Cybersecurity toolkit for security professionals, penetration testers, and ethical hackers. 
                All tools are free and professionally maintained.
              </p>
              <div className="flex items-center space-x-4">
                <Badge className="bg-green-500/20 text-green-400 border-green-500/30">
                  <CheckCircle className="h-3 w-3 mr-1" />
                  All Free
                </Badge>
                <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">
                  <Shield className="h-3 w-3 mr-1" />
                  Professional
                </Badge>
              </div>
            </div>

            <div>
              <h4 className="font-semibold mb-4">Security Tools</h4>
              <ul className="space-y-2 text-sm text-slate-400">
                <li>Network Scanning</li>
                <li>Vulnerability Assessment</li>
                <li>Web Security Testing</li>
                <li>DNS & WHOIS Analysis</li>
                <li>Port Scanning</li>
                <li>Exploitation Frameworks</li>
              </ul>
            </div>

            <div>
              <h4 className="font-semibold mb-4">Platform</h4>
              <ul className="space-y-2 text-sm text-slate-400">
                <li>Free Forever</li>
                <li>No Registration Required</li>
                <li>Professional Grade</li>
                <li>Real-time Results</li>
                <li>Export Capabilities</li>
                <li>Ethical Hacking Only</li>
              </ul>
            </div>
          </div>

          <div className="border-t border-slate-800 mt-8 pt-6 text-center text-sm text-slate-400">
            <p>© 2025 CyberShield. Built for ethical security professionals. Use responsibly.</p>
          </div>
        </div>
      </footer>
    </div>
  )
}
