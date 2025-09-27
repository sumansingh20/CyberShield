"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Badge } from "@/src/ui/components/ui/badge"
import { ScrollArea } from "@/src/ui/components/ui/scroll-area"
import { Button } from "@/src/ui/components/ui/button"
import { Clock, CheckCircle, XCircle, AlertTriangle, Shield, Search, Globe, Terminal, RefreshCw } from "lucide-react"

interface ActivityResponse {
  activities: ActivityItem[]
  pagination: {
    total: number
    limit: number
    skip: number
    hasMore: boolean
  }
}

interface ActivityItem {
  id: string
  tool: string
  toolName?: string // Make this optional to match API response
  category: string
  target: string
  status: string
  summary: string
  findings: {
    total: number
    critical: number
    high: number
  }
  executionTime: number
  timestamp: string
}

export default function RecentActivity() {
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [retryCount, setRetryCount] = useState(0)

  useEffect(() => {
    console.log('RecentActivity component mounted')
    
    const fetchRecentActivity = async (retryAttempt = 0) => {
      console.log(`Fetching recent activity... (attempt ${retryAttempt + 1})`)
      
      try {
        console.log('Making fetch request to:', '/api/dashboard/activity')
        
        // Multiple retry strategies
        const maxRetries = 3
        const baseUrl = window.location.origin
        const fullUrl = `${baseUrl}/api/dashboard/activity`
        
        console.log('Full URL:', fullUrl)
        console.log('Window location:', window.location.href)
        
        // Add timeout and better error handling for the fetch
        const controller = new AbortController()
        const timeoutId = setTimeout(() => {
          console.log('Request timeout triggered')
          controller.abort()
        }, 15000) // Increased to 15 seconds
        
        // Try different fetch configurations
        let response: Response
        
        try {
          // First attempt with full configuration
          response = await fetch(fullUrl, {
            credentials: 'include',
            headers: {
              'Content-Type': 'application/json',
              'Accept': 'application/json',
              'Cache-Control': 'no-cache',
              'Pragma': 'no-cache'
            },
            method: 'GET',
            signal: controller.signal,
            cache: 'no-store'
          })
        } catch (fetchError) {
          console.log('First fetch attempt failed, trying simplified request...')
          
          // Fallback: try with minimal configuration
          response = await fetch('/api/dashboard/activity', {
            method: 'GET',
            signal: controller.signal
          })
        }

        clearTimeout(timeoutId)
        console.log('Response received:', response.status, response.statusText)

        // Check if response is ok before reading
        if (!response.ok) {
          const errorText = await response.text()
          console.error('HTTP Error:', response.status, errorText)
          
          // Retry for certain error codes
          if ((response.status === 500 || response.status === 502 || response.status === 503) && retryAttempt < maxRetries) {
            console.log(`Retrying due to server error... (attempt ${retryAttempt + 1}/${maxRetries})`)
            await new Promise(resolve => setTimeout(resolve, 1000 * (retryAttempt + 1))) // Exponential backoff
            return fetchRecentActivity(retryAttempt + 1)
          }
          
          throw new Error(`HTTP ${response.status}: ${errorText || 'Failed to fetch recent activity'}`)
        }

        // Read response as JSON directly
        const data = await response.json()
        console.log('Response data received:', data)

        if (!data || typeof data !== 'object') {
          console.error('Invalid response format:', data)
          throw new Error('Invalid response format - not an object')
        }

        if (data.success === false) {
          console.error('API returned error:', data)
          throw new Error(data.message || data.error || 'API returned error')
        }

        if (!data.activities || !Array.isArray(data.activities)) {
          console.error('Invalid activities format:', data)
          throw new Error('Invalid response format - activities not found or not array')
        }

        console.log('Activities fetched successfully:', data.activities.length, 'items')
        setActivities(data.activities)
        setError(null) // Clear any previous errors
        
      } catch (error) {
        console.error('Failed to fetch recent activity:', error)
        
        // Retry logic for network errors
        const maxRetries = 3
        if (retryAttempt < maxRetries && error instanceof Error) {
          if (error.name === 'AbortError' || error.message.includes('Failed to fetch') || error.message.includes('NetworkError')) {
            console.log(`Network error, retrying... (attempt ${retryAttempt + 1}/${maxRetries})`)
            await new Promise(resolve => setTimeout(resolve, 2000 * (retryAttempt + 1))) // Exponential backoff
            return fetchRecentActivity(retryAttempt + 1)
          }
        }
        
        // Provide more specific error messages
        let errorMessage = 'Failed to fetch recent activity'
        
        if (error instanceof Error) {
          if (error.name === 'AbortError') {
            errorMessage = 'Request timed out - please check your connection and try again'
          } else if (error.message.includes('Failed to fetch')) {
            errorMessage = 'Network connection failed - please check if the server is running and try again'
          } else if (error.message.includes('NetworkError')) {
            errorMessage = 'Network error occurred - please check your internet connection'
          } else {
            errorMessage = error.message
          }
        }
        
        console.error('Final error after retries:', errorMessage)
        setError(errorMessage)
        
        // Set fallback data to show component is functional
        setActivities([
          {
            id: 'fallback-1',
            tool: 'System Status',
            category: 'System',
            target: 'localhost',
            status: 'error',
            summary: 'API connection failed - showing fallback data',
            findings: { total: 0, critical: 0, high: 0 },
            executionTime: 0,
            timestamp: new Date().toISOString()
          }
        ])
      } finally {
        setLoading(false)
      }
    }

    // Initial fetch
    fetchRecentActivity()

    // Set up refresh interval - every 30 seconds for activity feed (reduced frequency to avoid overwhelming)
    const intervalId = setInterval(fetchRecentActivity, 30000)
    console.log('Set interval for activity refresh:', intervalId)

    // Cleanup interval on component unmount
    return () => {
      console.log('Cleaning up RecentActivity interval:', intervalId)
      clearInterval(intervalId)
    }
  }, [retryCount]) // Add retryCount as dependency

  const getStatusIcon = (status: string) => {
    switch (status) {
      case "success":
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case "error":
        return <XCircle className="h-4 w-4 text-red-500" />
      case "warning":
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  const getToolIcon = (tool: string) => {
    if (!tool || typeof tool !== 'string') return Terminal
    
    if (tool.includes("Port") || tool.includes("Network")) return Globe
    if (tool.includes("WHOIS") || tool.includes("DNS")) return Search
    if (tool.includes("Subdomain")) return Globe
    if (tool.includes("Vulnerability") || tool.includes("Scanner")) return Shield
    return Terminal
  }

  const getStatusColor = (status: string) => {
    if (!status || typeof status !== 'string') {
      return "bg-gray-500/10 text-gray-500"
    }
    
    switch (status.toLowerCase()) {
      case "success":
        return "bg-green-500/10 text-green-500"
      case "error":
        return "bg-red-500/10 text-red-500"
      case "warning":
        return "bg-yellow-500/10 text-yellow-500"
      default:
        return "bg-gray-500/10 text-gray-500"
    }
  }

  if (loading) {
    return (
      <Card className="glass-card">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Recent Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {['loading1', 'loading2', 'loading3'].map((id) => (
              <div key={id} className="animate-pulse">
                <div className="h-4 bg-muted rounded w-3/4 mb-2"></div>
                <div className="h-3 bg-muted rounded w-1/2"></div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    )
  }

  if (error) {
    return (
      <Card className="glass-card border-red-200 dark:border-red-800">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Clock className="h-5 w-5" />
            Recent Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-col items-center justify-center h-32 space-y-3">
            <XCircle className="h-12 w-12 text-destructive" />
            <div className="text-center space-y-2">
              <h3 className="font-semibold text-gray-900 dark:text-white">Connection Failed</h3>
              <p className="text-destructive text-sm">{error}</p>
              <p className="text-xs text-gray-500 dark:text-gray-400">
                This might be a browser cache issue. Try refreshing the page.
              </p>
            </div>
            <div className="flex gap-2">
              <Button 
                onClick={() => {
                  setError(null)
                  setLoading(true)
                  setRetryCount(prev => prev + 1)
                }}
                variant="outline"
                size="sm"
                className="flex items-center gap-2"
              >
                <RefreshCw className="h-4 w-4" />
                Retry
              </Button>
              <Button 
                onClick={() => {
                  window.location.reload()
                }}
                variant="default"
                size="sm"
                className="flex items-center gap-2"
              >
                <RefreshCw className="h-4 w-4" />
                Refresh Page
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>
    )
  }

  return (
    <Card className="glass-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <Clock className="h-5 w-5" />
          Recent Activity
        </CardTitle>
        <CardDescription>
          Your latest security tool usage
        </CardDescription>
      </CardHeader>
      <CardContent>
        <ScrollArea className="h-64">
          <div className="space-y-3">
            {activities.length > 0 ? (
              activities.map((activity) => {
                const ToolIcon = getToolIcon(activity.toolName || activity.tool)
                return (
                  <div
                    key={activity.id}
                    className="flex items-start gap-3 p-3 rounded-lg hover:bg-muted/20 transition-colors duration-200"
                  >
                    <div className="p-1.5 rounded-full bg-primary/10">
                      <ToolIcon className="h-3 w-3 text-primary" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <p className="text-sm font-medium truncate">
                          {activity.toolName || activity.tool || 'Unknown Tool'}
                        </p>
                        <Badge variant="secondary" className="text-xs">
                          {activity.category || 'General'}
                        </Badge>
                        <Badge className={`text-xs ${getStatusColor(activity.status)}`}>
                          {activity.status}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground truncate">
                        Target: {activity.target}
                      </p>
                      {(() => {
                        // Debug log findings data
                        console.log('Rendering findings for activity:', {
                          id: activity.id,
                          findings: activity.findings
                        })

                        if (!activity.findings) {
                          console.log('No findings object for activity:', activity.id)
                          return null
                        }

                        const total = activity.findings.total || 0
                        console.log('Total findings:', total)

                        if (total <= 0) {
                          console.log('No findings to display')
                          return null
                        }

                        return (
                          <div className="flex items-center gap-2 mt-1">
                            <Badge variant="destructive" className="text-xs">
                              Critical: {activity.findings.critical || 0}
                            </Badge>
                            <Badge variant="destructive" className="text-xs">
                              High: {activity.findings.high || 0}
                            </Badge>
                            <Badge variant="outline" className="text-xs">
                              Total: {total}
                            </Badge>
                          </div>
                        )
                      })()}
                      {activity.summary && (
                        <p className="text-xs text-muted-foreground mt-1">
                          {activity.summary}
                        </p>
                      )}
                      <div className="flex items-center gap-1 mt-1">
                        {getStatusIcon(activity.status)}
                        <span className="text-xs text-muted-foreground">
                          {new Date(activity.timestamp).toLocaleString()}
                        </span>
                        <span className="text-xs text-muted-foreground ml-1">
                          ({(activity.executionTime / 1000).toFixed(1)}s)
                        </span>
                      </div>
                    </div>
                  </div>
                )
              })
            ) : (
              <div className="text-center py-8">
                <Terminal className="h-8 w-8 text-muted-foreground mx-auto mb-2" />
                <p className="text-sm text-muted-foreground">No recent activity</p>
                <p className="text-xs text-muted-foreground">
                  Start using tools to see your activity here
                </p>
              </div>
            )}
          </div>
        </ScrollArea>
      </CardContent>
    </Card>
  )
}
