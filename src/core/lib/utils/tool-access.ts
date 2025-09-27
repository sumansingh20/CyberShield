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
  },
  {
    name: "AI Phishing Detector",
    path: "/tools/ai-phishing-detector",
    accessLevel: "free",
    category: "AI Security",
    difficulty: "Intermediate",
    description: "AI-powered phishing email and URL detection with machine learning",
    icon: "Brain",
    color: "text-emerald-500",
    bgColor: "bg-emerald-500/10",
    freeUsageLimit: 10,
    requiresAuth: false
  },
  {
    name: "AI Fraud Detector",
    path: "/tools/ai-fraud-detector",
    accessLevel: "free",
    category: "AI Security",
    difficulty: "Intermediate",
    description: "Machine learning-based fraud detection for transactions and user behavior analysis",
    icon: "CreditCard",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    freeUsageLimit: 8,
    requiresAuth: false
  },
  {
    name: "AI Intrusion Detector",
    path: "/tools/ai-intrusion-detector",
    accessLevel: "free",
    category: "AI Security",
    difficulty: "Advanced",
    description: "Real-time network intrusion detection using AI pattern recognition and behavioral analysis",
    icon: "Shield",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    freeUsageLimit: 5,
    requiresAuth: false
  },
  {
    name: "AI Mental Health Companion",
    path: "/tools/ai-mental-health",
    accessLevel: "free",
    category: "AI Wellness",
    difficulty: "Beginner",
    description: "AI-powered mental health companion with mood tracking, therapy suggestions, and wellness insights",
    icon: "Heart",
    color: "text-pink-500",
    bgColor: "bg-pink-500/10",
    freeUsageLimit: 15,
    requiresAuth: false
  },
  {
    name: "AI Lecture Summarizer",
    path: "/tools/ai-lecture-summarizer",
    accessLevel: "free",
    category: "AI Education",
    difficulty: "Beginner",
    description: "Transform lectures into smart notes with AI-powered summarization and study guide generation",
    icon: "BookOpen",
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    freeUsageLimit: 10,
    requiresAuth: false
  }
]

// Premium tools - NOW ALL UNLOCKED AND FREE TO USE
export const PREMIUM_TOOLS: ToolConfig[] = [

  {
    name: "Network Scanner",
    path: "/tools/network-scan",
    accessLevel: "free", // Changed from premium to free
    category: "Network",
    difficulty: "Beginner",
    description: "Comprehensive network discovery and port scanning",
    icon: "Globe",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    requiresAuth: false // No auth required
  },
  {
    name: "Port Scanner",
    path: "/tools/port-scanner",
    accessLevel: "free", // Changed from premium to free
    category: "Network",
    difficulty: "Beginner",
    description: "Scan for open ports on target systems using Nmap",
    icon: "Shield",
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    requiresAuth: false // No auth required
  },
  {
    name: "Subdomain Enumeration",
    path: "/tools/subdomain-enum",
    accessLevel: "free", // Changed from premium to free
    category: "Reconnaissance",
    difficulty: "Beginner",
    description: "Discover subdomains using Sublist3r and AssetFinder",
    icon: "Search",
    color: "text-green-500",
    bgColor: "bg-green-500/10",
    requiresAuth: false // No auth required
  },
  {
    name: "Vulnerability Scanner",
    path: "/tools/vuln-scanner",
    accessLevel: "free", // Changed from premium to free
    category: "Web Security",
    difficulty: "Intermediate",
    description: "Scan for vulnerabilities using Nikto and Nuclei",
    icon: "Shield",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    requiresAuth: false // No auth required
  },
  {
    name: "AI Healthcare Diagnostics",
    path: "/tools/ai-healthcare",
    accessLevel: "free",
    category: "AI Healthcare",
    difficulty: "Intermediate",
    description: "AI-powered medical imaging analysis and diagnostic assistance with treatment recommendations",
    icon: "Stethoscope",
    color: "text-green-500",
    bgColor: "bg-green-500/10",
    requiresAuth: false
  },
  {
    name: "Agentic AI Research Assistant",
    path: "/tools/ai-research-assistant",
    accessLevel: "free",
    category: "AI Research",
    difficulty: "Advanced",
    description: "Autonomous AI research agent with comprehensive analysis and report generation",
    icon: "BookOpenCheck",
    color: "text-indigo-500",
    bgColor: "bg-indigo-500/10",
    requiresAuth: false
  },
  {
    name: "AI Coding Copilot",
    path: "/tools/ai-coding-copilot",
    accessLevel: "free",
    category: "AI Development",
    difficulty: "Advanced",
    description: "AI-powered coding assistant with multi-language support and code optimization",
    icon: "Code",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    requiresAuth: false
  },
  {
    name: "AI Music Composition",
    path: "/tools/music-composition-ai",
    accessLevel: "free",
    category: "AI Creative",
    difficulty: "Intermediate",
    description: "Create original music compositions using AI with multiple genres and instruments",
    icon: "Music",
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    requiresAuth: false
  },
  {
    name: "AI Art Generation",
    path: "/tools/art-generation-ai",
    accessLevel: "free",
    category: "AI Creative",
    difficulty: "Intermediate",
    description: "Generate stunning artwork using AI with style analysis and artistic techniques",
    icon: "Palette",
    color: "text-pink-500",
    bgColor: "bg-pink-500/10",
    requiresAuth: false
  },
  {
    name: "Creative Writing AI",
    path: "/tools/creative-writing-ai",
    accessLevel: "free",
    category: "AI Creative",
    difficulty: "Beginner",
    description: "AI-powered creative writing assistant with genre-specific templates and literary analysis",
    icon: "PenTool",
    color: "text-cyan-500",
    bgColor: "bg-cyan-500/10",
    requiresAuth: false
  }
]

// Expert tools - NOW ALL UNLOCKED AND FREE TO USE
export const EXPERT_TOOLS: ToolConfig[] = [
  {
    name: "SQL Injection Testing",
    path: "/tools/sql-injection",
    accessLevel: "free",
    category: "Web Security",
    difficulty: "Advanced",
    description: "Advanced SQL injection vulnerability scanner with comprehensive payload testing",
    icon: "Database",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    requiresAuth: false
  },
  {
    name: "XSS Vulnerability Scanner",
    path: "/tools/xss-scanner",
    accessLevel: "free",
    category: "Web Security",
    difficulty: "Advanced",
    description: "Cross-site scripting detection with payload injection testing",
    icon: "AlertTriangle",
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    requiresAuth: false
  },
  {
    name: "WAF Bypass Tool",
    path: "/tools/waf-bypass",
    accessLevel: "free",
    category: "Web Security",
    difficulty: "Expert",
    description: "Web Application Firewall bypass techniques and payload encoding",
    icon: "Shield",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    requiresAuth: false
  },
  {
    name: "Directory Brute Force",
    path: "/tools/directory-bruteforce",
    accessLevel: "free",
    category: "Web Security",
    difficulty: "Intermediate",
    description: "Advanced directory and file discovery with custom wordlists",
    icon: "FolderOpen",
    color: "text-yellow-500",
    bgColor: "bg-yellow-500/10",
    requiresAuth: false
  },
  {
    name: "Password Cracking Tool",
    path: "/tools/password-cracking",
    accessLevel: "free",
    category: "Cryptography",
    difficulty: "Advanced",
    description: "Hash cracking and password analysis with multiple attack methods",
    icon: "Key",
    color: "text-green-500",
    bgColor: "bg-green-500/10",
    requiresAuth: false
  },
  {
    name: "Reverse Shell Generator",
    path: "/tools/reverse-shell",
    accessLevel: "free",
    category: "Exploitation",
    difficulty: "Expert",
    description: "Multi-platform reverse shell payload generator with listener commands",
    icon: "Terminal",
    color: "text-red-600",
    bgColor: "bg-red-600/10",
    requiresAuth: false
  },
  {
    name: "Masscan",
    path: "/tools/advanced/masscan",
    accessLevel: "free", // Changed from expert to free
    category: "Network",
    difficulty: "Advanced",
    description: "High-speed port scanner for large networks",
    icon: "Target",
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    requiresAuth: false // No auth required
  },
  {
    name: "Directory Buster",
    path: "/tools/advanced/dirbuster",
    accessLevel: "free", // Changed from expert to free
    category: "Web Security",
    difficulty: "Intermediate",
    description: "Discover hidden directories and files",
    icon: "Terminal",
    color: "text-pink-500",
    bgColor: "bg-pink-500/10",
    requiresAuth: false // No auth required
  },
  {
    name: "OSINT Toolkit",
    path: "/tools/advanced/osint",
    accessLevel: "free", // Changed from expert to free
    category: "OSINT",
    difficulty: "Intermediate",
    description: "Information gathering using TheHarvester and Shodan",
    icon: "Eye",
    color: "text-indigo-500",
    bgColor: "bg-indigo-500/10",
    requiresAuth: false // No auth required
  },
  {
    name: "Metasploit Framework",
    path: "/tools/expert/metasploit",
    accessLevel: "free", // Changed from expert to free
    category: "Exploitation",
    difficulty: "Expert",
    description: "Advanced exploitation framework for penetration testing",
    icon: "Zap",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    requiresAuth: false // No auth required
  },
  {
    name: "Burp Suite Pro",
    path: "/tools/expert/burpsuite",
    accessLevel: "free", // Changed from expert to free
    category: "Web Security",
    difficulty: "Expert",
    description: "Professional web application security testing platform",
    icon: "Shield",
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    requiresAuth: false // No auth required
  },
  {
    name: "Smart Document Analysis AI",
    path: "/tools/document-analysis-ai",
    accessLevel: "free",
    category: "AI Productivity",
    difficulty: "Advanced",
    description: "Intelligent document processing with content extraction and compliance checking",
    icon: "FileCheck",
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    requiresAuth: false
  },
  {
    name: "Meeting Transcription AI",
    path: "/tools/meeting-transcription-ai",
    accessLevel: "free",
    category: "AI Productivity",
    difficulty: "Advanced",
    description: "Real-time meeting transcription with speaker identification and action item extraction",
    icon: "Mic",
    color: "text-green-500",
    bgColor: "bg-green-500/10",
    requiresAuth: false
  },
  {
    name: "Task Optimization AI",
    path: "/tools/task-optimization-ai",
    accessLevel: "free",
    category: "AI Productivity",
    difficulty: "Expert",
    description: "AI-powered task management with priority scoring and workflow automation",
    icon: "CheckSquare",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    requiresAuth: false
  },
  {
    name: "Wireless Network Scanner",
    path: "/tools/wireless-scanner",
    accessLevel: "free",
    category: "Network Security",
    difficulty: "Advanced",
    description: "WiFi network analysis and security assessment with handshake capture",
    icon: "Wifi",
    color: "text-blue-500",
    bgColor: "bg-blue-500/10",
    requiresAuth: false
  },
  {
    name: "Exploit Database Search",
    path: "/tools/exploit-database",
    accessLevel: "free",
    category: "Vulnerability Research",
    difficulty: "Expert",
    description: "Search CVE database and exploit repository for security vulnerabilities",
    icon: "Database",
    color: "text-red-500",
    bgColor: "bg-red-500/10",
    requiresAuth: false
  },
  {
    name: "Payload Generator",
    path: "/tools/payload-generator",
    accessLevel: "free",
    category: "Exploitation",
    difficulty: "Expert",
    description: "Generate custom payloads for various attack vectors and platforms",
    icon: "Code",
    color: "text-purple-500",
    bgColor: "bg-purple-500/10",
    requiresAuth: false
  },
  {
    name: "Social Engineering Toolkit",
    path: "/tools/social-engineering",
    accessLevel: "free",
    category: "Social Engineering",
    difficulty: "Advanced",
    description: "Educational templates for social engineering awareness and authorized testing",
    icon: "Users",
    color: "text-orange-500",
    bgColor: "bg-orange-500/10",
    requiresAuth: false
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
  // ALL TOOLS ARE NOW FREE AND ACCESSIBLE - NO RESTRICTIONS!
  return true
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
  if (!tool?.freeUsageLimit) return false
  
  return getToolUsageCount(toolPath) >= tool.freeUsageLimit
}
