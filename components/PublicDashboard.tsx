"use client"

import { useState } from "react"
import { useAuth } from "@/contexts/AuthContext"
import { ThemeToggle } from "@/components/ThemeToggle"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog"
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

// Tool configurations
const FREE_TOOLS = [
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
    freeUsageLimit: 5
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
    freeUsageLimit: 5
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
    freeUsageLimit: 10
  }
]

const PREMIUM_TOOLS = [
  {
    name: "Network Scanner",
    path: "/tools/network-scan",
    category: "Network",
    difficulty: "Beginner",
    description: "Comprehensive network discovery and port scanning",
    icon: Globe,
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    accessLevel: "premium" as const
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
    accessLevel: "premium" as const
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
    accessLevel: "premium" as const
  }
]

const EXPERT_TOOLS = [
  {
    name: "Masscan",
    path: "/tools/advanced/masscan",
    category: "Network",
    difficulty: "Advanced",
    description: "High-speed port scanner for large networks",
    icon: Target,
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    accessLevel: "expert" as const
  },
  {
    name: "Directory Buster",
    path: "/tools/advanced/dirbuster",
    category: "Web Security",
    difficulty: "Intermediate",
    description: "Discover hidden directories and files",
    icon: Terminal,
    color: "text-pink-500",
    bgColor: "bg-pink-500/10",
    accessLevel: "expert" as const
  },
  {
    name: "Metasploit Framework",
    path: "/tools/expert/metasploit",
    category: "Exploitation",
    difficulty: "Expert",
    description: "Advanced exploitation framework for penetration testing",
    icon: Zap,
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    accessLevel: "expert" as const
  }
]

type ToolConfig = typeof FREE_TOOLS[0] | typeof PREMIUM_TOOLS[0] | typeof EXPERT_TOOLS[0]

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

function canUserAccessTool(tool: ToolConfig, isAuthenticated: boolean): boolean {
  if (tool.accessLevel === 'free') return true
  return isAuthenticated
}

function getToolUsageCount(toolPath: string): number {
  if (typeof window === 'undefined') return 0
  const key = `tool_usage_${toolPath.replace(/\//g, '_')}`
  return parseInt(sessionStorage.getItem(key) || '0', 10)
}

function hasExceededFreeLimit(tool: ToolConfig): boolean {
  if (tool.accessLevel !== 'free' || !tool.freeUsageLimit) return false
  return getToolUsageCount(tool.path) >= tool.freeUsageLimit
}

interface ToolCardProps {
  tool: ToolConfig
  isAuthenticated: boolean
  onAccessDenied: (tool: ToolConfig) => void
}

function ToolCard({ tool, isAuthenticated, onAccessDenied }: ToolCardProps) {
  const canAccess = canUserAccessTool(tool, isAuthenticated)
  const IconComponent = tool.icon
  const isLocked = !canAccess
  const usageCount = getToolUsageCount(tool.path)
  const hasExceededLimit = hasExceededFreeLimit(tool)
  
  const handleClick = (e: React.MouseEvent) => {
    if (isLocked || (tool.accessLevel === 'free' && !isAuthenticated && hasExceededLimit)) {
      e.preventDefault()
      onAccessDenied(tool)
    }
  }

  // Use proper typing for wrapper component
  const wrapperProps = isLocked || hasExceededLimit ? {} : { href: tool.path }
  const WrapperComponent = isLocked || hasExceededLimit ? 'div' : Link

  return (
    <WrapperComponent {...wrapperProps}>
      <Card 
        className={`h-full glass-card transition-all duration-300 cursor-pointer group relative overflow-hidden ${
          isLocked || hasExceededLimit ? 'opacity-75' : 'hover:glow-hover'
        }`}
        onClick={handleClick}
      >
        {/* Access Level Indicator */}
        <div className="absolute top-3 right-3">
          {tool.accessLevel === 'free' ? (
            <Badge className="bg-green-500/10 text-green-500 text-xs">
              Free
            </Badge>
          ) : tool.accessLevel === 'premium' ? (
            <Badge className="bg-blue-500/10 text-blue-500 text-xs">
              <Crown className="h-3 w-3 mr-1" />
              Premium
            </Badge>
          ) : (
            <Badge className="bg-red-500/10 text-red-500 text-xs">
              <Star className="h-3 w-3 mr-1" />
              Expert
            </Badge>
          )}
        </div>

        {/* Lock Overlay for Premium/Expert Tools */}
        {isLocked && (
          <div className="absolute inset-0 bg-background/80 backdrop-blur-sm flex items-center justify-center z-10">
            <div className="text-center">
              <Lock className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
              <p className="text-sm text-muted-foreground font-medium">
                {tool.accessLevel === 'premium' ? 'Login Required' : 'Expert Access'}
              </p>
            </div>
          </div>
        )}

        {/* Free Tool Usage Limit Indicator */}
        {tool.accessLevel === 'free' && !isAuthenticated && tool.freeUsageLimit && (
          <div className="absolute top-12 right-3">
            <Badge variant="outline" className="text-xs">
              {usageCount}/{tool.freeUsageLimit}
            </Badge>
          </div>
        )}

        <CardHeader className="pb-3">
          <div className="flex items-start justify-between">
            <div className="flex items-center space-x-3">
              <div className={`p-3 rounded-lg ${tool.bgColor} group-hover:scale-110 transition-transform duration-200`}>
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
          </div>
        </CardHeader>
        <CardContent>
          <CardDescription className="group-hover:text-foreground/80 transition-colors duration-200 text-sm">
            {tool.description}
          </CardDescription>
        </CardContent>
      </Card>
    </WrapperComponent>
  )
}

interface AccessDeniedDialogProps {
  open: boolean
  onClose: () => void
  tool: ToolConfig | null
  isAuthenticated: boolean
}

function AccessDeniedDialog({ open, onClose, tool, isAuthenticated }: AccessDeniedDialogProps) {
  if (!tool) return null

  const isFreeLimitExceeded = tool.accessLevel === 'free' && !isAuthenticated && hasExceededFreeLimit(tool)

  let dialogIcon = <Lock className="h-5 w-5 text-orange-500" />
  let dialogTitle = 'Access Required'
  
  if (tool.accessLevel === 'premium') {
    dialogIcon = <Crown className="h-5 w-5 text-blue-500" />
    dialogTitle = 'Premium Tool'
  } else if (tool.accessLevel === 'expert') {
    dialogIcon = <Star className="h-5 w-5 text-red-500" />
    dialogTitle = 'Expert Tool'
  }

  if (isFreeLimitExceeded) {
    dialogTitle = 'Usage Limit Reached'
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="glass-card max-w-md">
        <DialogHeader>
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className={`p-2 rounded-lg ${
                tool.accessLevel === 'premium' ? 'bg-blue-500/10' :
                tool.accessLevel === 'expert' ? 'bg-red-500/10' : 'bg-orange-500/10'
              }`}>
                {dialogIcon}
              </div>
              <DialogTitle>{dialogTitle}</DialogTitle>
            </div>
            <Button variant="ghost" size="sm" onClick={onClose}>
              <X className="h-4 w-4" />
            </Button>
          </div>
        </DialogHeader>
        
        <div className="space-y-4">
          <DialogDescription>
            {isFreeLimitExceeded ? (
              <>You've reached the free usage limit for <strong>{tool.name}</strong>. Create an account to get unlimited access to all tools!</>
            ) : tool.accessLevel === 'premium' ? (
              <>Access to <strong>{tool.name}</strong> requires a free account. Sign up or login to use this professional penetration testing tool.</>
            ) : (
              <>Access to <strong>{tool.name}</strong> requires expert-level privileges. This advanced tool is available to experienced users.</>
            )}
          </DialogDescription>

          {/* Benefits List */}
          <div className="bg-muted/20 rounded-lg p-4">
            <h4 className="font-medium mb-3 flex items-center gap-2">
              <CheckCircle className="h-4 w-4 text-green-500" />
              {isAuthenticated ? 'Expert Benefits' : 'Account Benefits'}
            </h4>
            <ul className="space-y-2 text-sm text-muted-foreground">
              {!isAuthenticated ? (
                <>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    Unlimited access to all free tools
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    Access to premium penetration testing tools
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    Save scan results and history
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    Personal dashboard and analytics
                  </li>
                </>
              ) : (
                <>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    Advanced exploitation frameworks
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    Professional security assessment tools
                  </li>
                  <li className="flex items-center gap-2">
                    <CheckCircle className="h-3 w-3 text-green-500" />
                    Priority support and documentation
                  </li>
                </>
              )}
            </ul>
          </div>

          {/* Action Buttons */}
          <div className="flex gap-3">
            {!isAuthenticated ? (
              <>
                <Link href="/register" className="flex-1">
                  <Button className="w-full glow-hover">
                    Create Free Account
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </Button>
                </Link>
                <Link href="/login" className="flex-1">
                  <Button variant="outline" className="w-full glass hover:glow-hover bg-transparent">
                    Sign In
                  </Button>
                </Link>
              </>
            ) : (
              <Button className="w-full" disabled>
                Contact Support for Expert Access
              </Button>
            )}
          </div>
        </div>
      </DialogContent>
    </Dialog>
  )
}

export default function PublicDashboard() {
  const { user, logout, isAuthenticated } = useAuth()
  const [selectedTool, setSelectedTool] = useState<ToolConfig | null>(null)
  const [showAccessDialog, setShowAccessDialog] = useState(false)

  const handleAccessDenied = (tool: ToolConfig) => {
    setSelectedTool(tool)
    setShowAccessDialog(true)
  }

  const getUserDisplayName = () => {
    if (!user) return ''
    if (user.firstName && user.lastName) {
      return `${user.firstName} ${user.lastName}`
    }
    return user.username
  }

  const getWelcomeMessage = () => {
    if (isAuthenticated) {
      return `Welcome back, ${getUserDisplayName()}! 👋`
    }
    return 'Welcome to Unified Toolkit! 🛡️'
  }

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
            {isAuthenticated ? (
              <>
                <Link href="/profile">
                  <div className="flex items-center space-x-3 px-3 py-2 rounded-lg glass hover:glow-hover transition-all duration-200 cursor-pointer">
                    <div className="p-1 rounded-full bg-primary/20">
                      <User className="h-3 w-3 text-primary" />
                    </div>
                    <div className="text-sm">
                      <div className="flex items-center gap-2">
                        <p className="font-medium">{user?.username}</p>
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
              </>
            ) : (
              <div className="flex items-center space-x-2">
                <Link href="/login">
                  <Button variant="ghost" size="sm">
                    Sign In
                  </Button>
                </Link>
                <Link href="/register">
                  <Button size="sm" className="glow-hover">
                    Get Started
                  </Button>
                </Link>
              </div>
            )}
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
                  {getWelcomeMessage()}
                </h2>
                <p className="text-muted-foreground">
                  {isAuthenticated 
                    ? 'Choose a security tool to get started with your penetration testing and cybersecurity work.'
                    : 'Try our free penetration testing tools, or create an account for full access to our professional toolkit.'
                  }
                </p>
              </div>
              <div className="hidden md:block">
                <div className="p-4 rounded-full bg-primary/10 glow animate-pulse-glow">
                  <Shield className="h-8 w-8 text-primary" />
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Tools Sections */}
        <div className="space-y-12">
          {/* Free Tools */}
          <div>
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-2xl font-bold flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-green-500/10">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                  </div>
                  Free Tools
                </h3>
                <p className="text-muted-foreground">
                  {isAuthenticated 
                    ? 'Essential tools available to all users' 
                    : 'Try these tools with limited usage (create account for unlimited access)'
                  }
                </p>
              </div>
              <Badge variant="outline" className="bg-green-500/10 text-green-500">
                {FREE_TOOLS.length} Tools
              </Badge>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {FREE_TOOLS.map((tool) => (
                <ToolCard
                  key={tool.name}
                  tool={tool}
                  isAuthenticated={isAuthenticated}
                  onAccessDenied={handleAccessDenied}
                />
              ))}
            </div>
          </div>

          {/* Premium Tools */}
          <div>
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-2xl font-bold flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-blue-500/10">
                    <Crown className="h-5 w-5 text-blue-500" />
                  </div>
                  Premium Tools
                </h3>
                <p className="text-muted-foreground">
                  Professional penetration testing tools {!isAuthenticated && '(requires free account)'}
                </p>
              </div>
              <Badge variant="outline" className="bg-blue-500/10 text-blue-500">
                {PREMIUM_TOOLS.length} Tools
              </Badge>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {PREMIUM_TOOLS.map((tool) => (
                <ToolCard
                  key={tool.name}
                  tool={tool}
                  isAuthenticated={isAuthenticated}
                  onAccessDenied={handleAccessDenied}
                />
              ))}
            </div>
          </div>

          {/* Expert Tools */}
          <div>
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-2xl font-bold flex items-center gap-2">
                  <div className="p-2 rounded-lg bg-red-500/10">
                    <Star className="h-5 w-5 text-red-500" />
                  </div>
                  Expert Tools
                </h3>
                <p className="text-muted-foreground">
                  Advanced exploitation and analysis tools for security professionals
                </p>
              </div>
              <Badge variant="outline" className="bg-red-500/10 text-red-500">
                {EXPERT_TOOLS.length} Tools
              </Badge>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {EXPERT_TOOLS.map((tool) => (
                <ToolCard
                  key={tool.name}
                  tool={tool}
                  isAuthenticated={isAuthenticated}
                  onAccessDenied={handleAccessDenied}
                />
              ))}
            </div>
          </div>
        </div>

        {/* Call to Action for Non-Authenticated Users */}
        {!isAuthenticated && (
          <div className="mt-16">
            <div className="glass-card p-8 text-center">
              <div className="flex justify-center mb-4">
                <div className="p-3 rounded-full bg-primary/10 glow">
                  <Crown className="h-8 w-8 text-primary" />
                </div>
              </div>
              <h3 className="text-2xl font-bold mb-4">Unlock Full Access</h3>
              <p className="text-muted-foreground mb-6 max-w-2xl mx-auto">
                Create a free account to get unlimited access to all premium penetration testing tools, 
                save your scan results, and track your security assessments.
              </p>
              <div className="flex flex-col sm:flex-row gap-4 justify-center">
                <Link href="/register">
                  <Button size="lg" className="w-full sm:w-auto glow-hover group">
                    Create Free Account
                    <ArrowRight className="ml-2 h-4 w-4 group-hover:translate-x-1 transition-transform" />
                  </Button>
                </Link>
                <Link href="/login">
                  <Button variant="outline" size="lg" className="w-full sm:w-auto glass hover:glow-hover bg-transparent">
                    Sign In
                  </Button>
                </Link>
              </div>
            </div>
          </div>
        )}
      </main>

      {/* Access Denied Dialog */}
      <AccessDeniedDialog
        open={showAccessDialog}
        onClose={() => setShowAccessDialog(false)}
        tool={selectedTool}
        isAuthenticated={isAuthenticated}
      />
    </div>
  )
}