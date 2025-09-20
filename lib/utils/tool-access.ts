export type ToolAccessLevel = 'free' | 'premium' | 'expert'

export interface ToolConfig {
  name: string
  path: string
  accessLevel: ToolAccessLevel
  category: string
  difficulty: string
  description: string
  icon: string
  color: string
  bgColor: string
  freeUsageLimit?: number // For free tools with usage limits
  requiresAuth: boolean
}

// Free tools - accessible to everyone (limited usage for non-registered users)
export const FREE_TOOLS: ToolConfig[] = [
  {
    name: "WHOIS Lookup",
    path: "/tools/whois",
    accessLevel: "free",
    category: "OSINT",
    difficulty: "Beginner",
    description: "Get domain registration information",
    icon: "Info",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    freeUsageLimit: 5, // 5 lookups per session for non-registered users
    requiresAuth: false
  },
  {
    name: "DNS Information",
    path: "/tools/dns-lookup",
    accessLevel: "free",
    category: "Network",
    difficulty: "Beginner", 
    description: "Retrieve DNS records and zone information",
    icon: "Dns",
    color: "text-yellow-500",
    bgColor: "bg-yellow-500/10",
    freeUsageLimit: 5,
    requiresAuth: false
  },
  {
    name: "HTTP Headers",
    path: "/tools/http-headers",
    accessLevel: "free",
    category: "Web Security",
    difficulty: "Beginner",
    description: "Analyze HTTP response headers",
    icon: "FileText",
    color: "text-cyan-500",
    bgColor: "bg-cyan-500/10",
    freeUsageLimit: 10,
    requiresAuth: false
  }
]

// Premium tools - require user registration and login
export const PREMIUM_TOOLS: ToolConfig[] = [
  {
    name: "Network Scanner",
    path: "/tools/network-scan",
    accessLevel: "premium",
    category: "Network",
    difficulty: "Beginner",
    description: "Comprehensive network discovery and port scanning",
    icon: "Globe",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    requiresAuth: true
  },
  {
    name: "Port Scanner",
    path: "/tools/port-scanner",
    accessLevel: "premium",
    category: "Network",
    difficulty: "Beginner",
    description: "Scan for open ports on target systems using Nmap",
    icon: "Shield",
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    requiresAuth: true
  },
  {
    name: "Subdomain Enumeration",
    path: "/tools/subdomain-enum",
    accessLevel: "premium",
    category: "Reconnaissance",
    difficulty: "Beginner",
    description: "Discover subdomains using Sublist3r and AssetFinder",
    icon: "Search",
    color: "text-green-500",
    bgColor: "bg-green-500/10",
    requiresAuth: true
  },
  {
    name: "Vulnerability Scanner",
    path: "/tools/vuln-scanner",
    accessLevel: "premium",
    category: "Web Security",
    difficulty: "Intermediate",
    description: "Scan for vulnerabilities using Nikto and Nuclei",
    icon: "Shield",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    requiresAuth: true
  }
]

// Expert tools - require premium account or special access
export const EXPERT_TOOLS: ToolConfig[] = [
  {
    name: "Masscan",
    path: "/tools/advanced/masscan",
    accessLevel: "expert",
    category: "Network",
    difficulty: "Advanced",
    description: "High-speed port scanner for large networks",
    icon: "Target",
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    requiresAuth: true
  },
  {
    name: "Directory Buster",
    path: "/tools/advanced/dirbuster",
    accessLevel: "expert",
    category: "Web Security",
    difficulty: "Intermediate",
    description: "Discover hidden directories and files",
    icon: "Terminal",
    color: "text-pink-500",
    bgColor: "bg-pink-500/10",
    requiresAuth: true
  },
  {
    name: "OSINT Toolkit",
    path: "/tools/advanced/osint",
    accessLevel: "expert",
    category: "OSINT",
    difficulty: "Intermediate",
    description: "Information gathering using TheHarvester and Shodan",
    icon: "Eye",
    color: "text-indigo-500",
    bgColor: "bg-indigo-500/10",
    requiresAuth: true
  },
  {
    name: "Metasploit Framework",
    path: "/tools/expert/metasploit",
    accessLevel: "expert",
    category: "Exploitation",
    difficulty: "Expert",
    description: "Advanced exploitation framework for penetration testing",
    icon: "Zap",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    requiresAuth: true
  },
  {
    name: "Burp Suite Pro",
    path: "/tools/expert/burpsuite",
    accessLevel: "expert",
    category: "Web Security",
    difficulty: "Expert",
    description: "Professional web application security testing platform",
    icon: "Shield",
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    requiresAuth: true
  }
]

// All tools combined
export const ALL_TOOLS = [...FREE_TOOLS, ...PREMIUM_TOOLS, ...EXPERT_TOOLS]

// Helper functions
export function getToolByPath(path: string): ToolConfig | undefined {
  return ALL_TOOLS.find(tool => tool.path === path)
}

export function getToolsByAccessLevel(level: ToolAccessLevel): ToolConfig[] {
  return ALL_TOOLS.filter(tool => tool.accessLevel === level)
}

export function canUserAccessTool(toolPath: string, isAuthenticated: boolean, userRole?: string): boolean {
  const tool = getToolByPath(toolPath)
  if (!tool) return false

  // Free tools are accessible to everyone
  if (tool.accessLevel === 'free') {
    return true
  }

  // Premium and expert tools require authentication
  if (tool.accessLevel === 'premium' || tool.accessLevel === 'expert') {
    return isAuthenticated
  }

  return false
}

export function getAccessLevelColor(level: ToolAccessLevel): string {
  switch (level) {
    case 'free':
      return 'bg-green-500/10 text-green-500'
    case 'premium':
      return 'bg-blue-500/10 text-blue-500'
    case 'expert':
      return 'bg-red-500/10 text-red-500'
    default:
      return 'bg-gray-500/10 text-gray-500'
  }
}

export function getDifficultyColor(difficulty: string): string {
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

// Usage tracking for free tools (client-side session storage)
export function trackToolUsage(toolPath: string): void {
  if (typeof window === 'undefined') return
  
  const tool = getToolByPath(toolPath)
  if (!tool || tool.accessLevel !== 'free') return

  const key = `tool_usage_${toolPath.replace(/\//g, '_')}`
  const currentCount = parseInt(sessionStorage.getItem(key) || '0', 10)
  sessionStorage.setItem(key, (currentCount + 1).toString())
}

export function getToolUsageCount(toolPath: string): number {
  if (typeof window === 'undefined') return 0
  
  const key = `tool_usage_${toolPath.replace(/\//g, '_')}`
  return parseInt(sessionStorage.getItem(key) || '0', 10)
}

export function hasExceededFreeLimit(toolPath: string): boolean {
  const tool = getToolByPath(toolPath)
  if (!tool || !tool.freeUsageLimit) return false
  
  return getToolUsageCount(toolPath) >= tool.freeUsageLimit
}