"use client"

import { useState } from "react"
import Link from "next/link"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Badge } from "@/src/ui/components/ui/badge"
import { Input } from "@/src/ui/components/ui/input"
import { Button } from "@/src/ui/components/ui/button"
import { 
  Shield, 
  Search, 
  Globe, 
  Network, 
  Lock,
  Terminal,
  Eye,
  Zap,
  Bug,
  Database,
  Wifi,
  Phone,
  Mail,
  Key,
  FileText,
  Cpu,
  HardDrive,
  UserCheck,
  Settings,
  Code,
  Layers,
  Activity
} from "lucide-react"

interface Tool {
  id: string
  name: string
  description: string
  category: string
  icon: any
  path: string
  difficulty: 'beginner' | 'intermediate' | 'advanced' | 'expert'
}

const securityTools: Tool[] = [
  // Reconnaissance Tools
  {
    id: 'dns-lookup',
    name: 'DNS Lookup',
    description: 'Perform comprehensive DNS record lookups and analysis',
    category: 'reconnaissance',
    icon: Globe,
    path: '/tools/dns-lookup',
    difficulty: 'beginner'
  },
  {
    id: 'whois',
    name: 'WHOIS Lookup',
    description: 'Gather domain registration and ownership information',
    category: 'reconnaissance', 
    icon: Search,
    path: '/tools/whois',
    difficulty: 'beginner'
  },
  {
    id: 'subdomain-enum',
    name: 'Subdomain Enumeration',
    description: 'Discover subdomains and map attack surface',
    category: 'reconnaissance',
    icon: Network,
    path: '/tools/subdomain-enum',
    difficulty: 'intermediate'
  },
  
  // Network Tools
  {
    id: 'port-scanner',
    name: 'Port Scanner',
    description: 'Scan for open ports and running services',
    category: 'network',
    icon: Shield,
    path: '/tools/port-scanner',
    difficulty: 'intermediate'
  },
  {
    id: 'ping-sweep',
    name: 'Ping Sweep',
    description: 'Discover live hosts on a network range',
    category: 'network',
    icon: Activity,
    path: '/tools/ping-sweep',
    difficulty: 'beginner'
  },
  
  // Web Security Tools
  {
    id: 'http-headers',
    name: 'HTTP Headers',
    description: 'Analyze HTTP security headers and configuration',
    category: 'web',
    icon: FileText,
    path: '/tools/http-headers',
    difficulty: 'beginner'
  },
  {
    id: 'ssl-analyzer',
    name: 'SSL/TLS Analyzer',
    description: 'Check SSL certificate and security configuration',
    category: 'web',
    icon: Lock,
    path: '/tools/ssl-analyzer', 
    difficulty: 'intermediate'
  },
  
  // Coming Soon Tools
  {
    id: 'vuln-scan',
    name: 'Vulnerability Scanner',
    description: 'Automated vulnerability assessment and reporting',
    category: 'forensics',
    icon: Bug,
    path: '#',
    difficulty: 'advanced'
  },
  {
    id: 'payload-gen',
    name: 'Payload Generator',
    description: 'Generate various payloads for penetration testing',
    category: 'exploitation',
    icon: Code,
    path: '#',
    difficulty: 'expert'
  }
]

const categories = [
  { name: 'All', value: 'all' },
  { name: 'Reconnaissance', value: 'reconnaissance' },
  { name: 'Network', value: 'network' },
  { name: 'Web Security', value: 'web' },
  { name: 'Forensics', value: 'forensics' },
  { name: 'Exploitation', value: 'exploitation' }
]

const difficultyColors = {
  beginner: 'bg-green-100 text-green-800 dark:bg-green-900 dark:text-green-200',
  intermediate: 'bg-blue-100 text-blue-800 dark:bg-blue-900 dark:text-blue-200', 
  advanced: 'bg-orange-100 text-orange-800 dark:bg-orange-900 dark:text-orange-200',
  expert: 'bg-red-100 text-red-800 dark:bg-red-900 dark:text-red-200'
}

export default function ToolsPage() {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')

  const filteredTools = securityTools.filter(tool => {
    const matchesSearch = tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         tool.description.toLowerCase().includes(searchTerm.toLowerCase())
    const matchesCategory = selectedCategory === 'all' || tool.category === selectedCategory
    return matchesSearch && matchesCategory
  })

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent mb-4">
            CyberShield Security Tools
          </h1>
          <p className="text-gray-600 dark:text-gray-300 text-lg max-w-2xl mx-auto">
            Professional penetration testing and cybersecurity assessment tools
          </p>
        </div>

        {/* Search and Filter */}
        <div className="max-w-4xl mx-auto mb-8 space-y-4">
          <div className="relative">
            <Search className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
            <Input
              placeholder="Search tools..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-10 h-12 bg-white dark:bg-gray-800 border-gray-200 dark:border-gray-700"
            />
          </div>
          
          <div className="flex flex-wrap gap-2 justify-center">
            {categories.map((category) => (
              <Button
                key={category.value}
                variant={selectedCategory === category.value ? "default" : "outline"}
                onClick={() => setSelectedCategory(category.value)}
                className="rounded-full"
              >
                {category.name}
              </Button>
            ))}
          </div>
        </div>

        {/* Tools Grid */}
        <div className="max-w-6xl mx-auto">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {filteredTools.map((tool) => {
              const Icon = tool.icon
              const isComingSoon = tool.path === '#'
              
              return (
                <Card key={tool.id} className="group hover:shadow-lg transition-all duration-200 border-0 bg-white dark:bg-gray-800">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between mb-2">
                      <Icon className="h-8 w-8 text-blue-500" />
                      <Badge className={difficultyColors[tool.difficulty]}>
                        {tool.difficulty}
                      </Badge>
                    </div>
                    <CardTitle className="text-xl group-hover:text-blue-600 transition-colors">
                      {tool.name}
                    </CardTitle>
                  </CardHeader>
                  
                  <CardContent>
                    <CardDescription className="text-gray-600 dark:text-gray-300 mb-4 line-clamp-2">
                      {tool.description}
                    </CardDescription>
                    
                    <div className="flex items-center justify-between">
                      <Badge variant="outline" className="capitalize">
                        {tool.category}
                      </Badge>
                      
                      {isComingSoon ? (
                        <Badge variant="secondary">
                          Coming Soon
                        </Badge>
                      ) : (
                        <Link href={tool.path}>
                          <Button size="sm" className="group-hover:scale-105 transition-transform">
                            Launch Tool
                          </Button>
                        </Link>
                      )}
                    </div>
                  </CardContent>
                </Card>
              )
            })}
          </div>
          
          {filteredTools.length === 0 && (
            <div className="text-center py-12">
              <Search className="h-12 w-12 text-gray-400 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-gray-600 dark:text-gray-300 mb-2">
                No tools found
              </h3>
              <p className="text-gray-500 dark:text-gray-400">
                Try adjusting your search or filter criteria
              </p>
            </div>
          )}
        </div>

        {/* Stats */}
        <div className="max-w-4xl mx-auto mt-12 grid grid-cols-2 md:grid-cols-4 gap-4 text-center">
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg">
            <div className="text-2xl font-bold text-blue-600">{securityTools.length}+</div>
            <div className="text-sm text-gray-600 dark:text-gray-300">Security Tools</div>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg">
            <div className="text-2xl font-bold text-green-600">100%</div>
            <div className="text-sm text-gray-600 dark:text-gray-300">Free & Open</div>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg">
            <div className="text-2xl font-bold text-purple-600">24/7</div>
            <div className="text-sm text-gray-600 dark:text-gray-300">Available</div>
          </div>
          <div className="bg-white dark:bg-gray-800 p-4 rounded-lg">
            <div className="text-2xl font-bold text-orange-600">Pro</div>
            <div className="text-sm text-gray-600 dark:text-gray-300">Grade Tools</div>
          </div>
        </div>
      </div>
    </div>
  )
}
