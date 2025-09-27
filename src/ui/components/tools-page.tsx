"use client"

import { useEffect, useState, useMemo } from "react"
// ...existing code...
import { useAuth } from "@/src/auth/utils/AuthContext"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import Link from "next/link"
import { Shield, Search, ArrowLeft } from "lucide-react"

import { FREE_TOOLS, PREMIUM_TOOLS, EXPERT_TOOLS, getAccessLevelColor, getDifficultyColor } from "@/src/core/lib/utils/tool-access"

function ToolCard({ tool }: { tool: ToolConfig }) {
  const difficultyColor = getDifficultyColor(tool.difficulty)
  const IconComponent = typeof tool.icon === 'string' ? lucideIcons[tool.icon as keyof typeof lucideIcons] as React.ComponentType<{ className?: string }> : undefined

  return (
    <Link href={tool.path}>
      <Card className={`hover:border-${tool.color} transition-colors hover:shadow-lg`}>
        <CardHeader>
          <div className="flex items-center gap-2">
            {IconComponent && <IconComponent className={`h-5 w-5 ${tool.color}`} />}
            <div>
              <CardTitle className="flex items-center gap-2">
                {tool.name}
                <span className="px-2 py-1 rounded-full text-xs bg-green-500/10 text-green-500">
                  FREE
                </span>
              </CardTitle>
              <CardDescription>{tool.description}</CardDescription>
            </div>
          </div>
        </CardHeader>
        <CardContent>
          <div className="flex gap-2">
            <span className={`px-2 py-1 rounded-full text-xs ${tool.bgColor} ${tool.color}`}>
              {tool.category}
            </span>
            <span className={`px-2 py-1 rounded-full text-xs ${difficultyColor}`}>
              {tool.difficulty}
            </span>
          </div>
        </CardContent>
      </Card>
    </Link>
  )
}

import * as lucideIcons from "lucide-react"
import type { ToolConfig } from "@/src/core/lib/utils/tool-access"

export default function ToolsPage() {
  const auth = useAuth()
  const [searchTerm, setSearchTerm] = useState("")
  
  // ALL HOOKS MUST BE AT THE TOP - before any conditional returns
  const allTools = [...FREE_TOOLS, ...PREMIUM_TOOLS, ...EXPERT_TOOLS]
  const tools = allTools // Show ALL tools to everyone - no restrictions!

  const filteredTools = useMemo(() => tools.filter((tool: ToolConfig) =>
    tool.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
    tool.description.toLowerCase().includes(searchTerm.toLowerCase()) ||
    tool.category.toLowerCase().includes(searchTerm.toLowerCase())
  ), [tools, searchTerm])

  // All tools are now free - but keep categories for organization
  const freeTools = useMemo(() => filteredTools.filter((tool: ToolConfig) => tool.accessLevel === "free"), [filteredTools])
  const beginnerTools = useMemo(() => filteredTools.filter((tool: ToolConfig) => tool.difficulty === "Beginner"), [filteredTools])
  const advancedTools = useMemo(() => filteredTools.filter((tool: ToolConfig) => tool.difficulty === "Advanced" || tool.difficulty === "Intermediate"), [filteredTools])
  const expertTools = useMemo(() => filteredTools.filter((tool: ToolConfig) => tool.difficulty === "Expert"), [filteredTools])

  useEffect(() => {
    console.log('Auth state in tools page:', {
      isLoading: auth.isLoading,
      isAuthenticated: auth.isAuthenticated,
      user: auth.user,
      accessToken: auth.accessToken ? 'present' : 'none',
      refreshToken: auth.refreshToken ? 'present' : 'none'
    })
  }, [auth])

  // Remove authentication check - show loading only briefly
  if (auth.isLoading) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-slate-900 to-slate-800 p-4 flex items-center justify-center">
        <Card className="max-w-md w-full">
          <CardHeader>
            <CardTitle>Loading CyberShield Tools...</CardTitle>
            <CardDescription>Preparing your security arsenal...</CardDescription>
          </CardHeader>
        </Card>
      </div>
    )
  }

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
              <CardTitle className="text-sm font-medium text-muted-foreground">All Tools FREE</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-green-600">{tools.length}</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">No Login Required</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-blue-600">✓</div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">Fully Unlocked</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-purple-600">🔓</div>
            </CardContent>
          </Card>
        </div>

        {/* Tools Grid */}
        <Tabs defaultValue="all" className="w-full">
          <TabsList className="grid w-full grid-cols-4">
            <TabsTrigger value="all">All Tools ({filteredTools.length})</TabsTrigger>
            <TabsTrigger value="beginner">Beginner ({beginnerTools.length})</TabsTrigger>
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

          <TabsContent value="beginner" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {beginnerTools.map((tool: ToolConfig) => (
                <ToolCard key={tool.path} tool={tool} />
              ))}
            </div>
          </TabsContent>

          <TabsContent value="advanced" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {advancedTools.map((tool: ToolConfig) => (
                <ToolCard key={tool.path} tool={tool} />
              ))}
            </div>
          </TabsContent>

          <TabsContent value="expert" className="mt-6">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
              {expertTools.map((tool: ToolConfig) => (
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
