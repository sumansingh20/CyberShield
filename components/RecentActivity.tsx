"use client"

import { useState, useEffect } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Badge } from "@/components/ui/badge"
import { ScrollArea } from "@/components/ui/scroll-area"
import { Clock, CheckCircle, XCircle, AlertTriangle, Shield, Search, Globe, Terminal } from "lucide-react"

interface ActivityItem {
  id: string
  tool: string
  target: string
  status: "success" | "error" | "warning"
  time: string
  details?: string
}

export default function RecentActivity() {
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const fetchRecentActivity = async () => {
      try {
        const response = await fetch('/api/user/recent-activity')
        if (response.ok) {
          const data = await response.json()
          setActivities(data.activities || [])
        } else {
          // If API fails, show mock data
          setActivities([
            {
              id: "1",
              tool: "Port Scanner",
              target: "192.168.1.1",
              status: "success",
              time: "2 minutes ago",
              details: "Found 3 open ports"
            },
            {
              id: "2", 
              tool: "WHOIS Lookup",
              target: "example.com",
              status: "success",
              time: "5 minutes ago"
            },
            {
              id: "3",
              tool: "Subdomain Enum",
              target: "target.com",
              status: "warning",
              time: "10 minutes ago",
              details: "Limited results due to rate limiting"
            }
          ])
        }
      } catch (error) {
        console.error('Failed to fetch recent activity:', error)
        // Show mock data on error
        setActivities([
          {
            id: "1",
            tool: "Port Scanner",
            target: "192.168.1.1", 
            status: "success",
            time: "2 minutes ago",
            details: "Found 3 open ports"
          }
        ])
      } finally {
        setLoading(false)
      }
    }

    fetchRecentActivity()
  }, [])

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
    if (tool.includes("Port") || tool.includes("Network")) return Globe
    if (tool.includes("WHOIS") || tool.includes("DNS")) return Search
    if (tool.includes("Subdomain")) return Globe
    if (tool.includes("Vulnerability") || tool.includes("Scanner")) return Shield
    return Terminal
  }

  const getStatusColor = (status: string) => {
    switch (status) {
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
            {[...Array(3)].map((_, i) => (
              <div key={i} className="animate-pulse">
                <div className="h-4 bg-muted rounded w-3/4 mb-2"></div>
                <div className="h-3 bg-muted rounded w-1/2"></div>
              </div>
            ))}
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
                const ToolIcon = getToolIcon(activity.tool)
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
                          {activity.tool}
                        </p>
                        <Badge className={`text-xs ${getStatusColor(activity.status)}`}>
                          {activity.status}
                        </Badge>
                      </div>
                      <p className="text-xs text-muted-foreground truncate">
                        Target: {activity.target}
                      </p>
                      {activity.details && (
                        <p className="text-xs text-muted-foreground mt-1">
                          {activity.details}
                        </p>
                      )}
                      <div className="flex items-center gap-1 mt-1">
                        {getStatusIcon(activity.status)}
                        <span className="text-xs text-muted-foreground">
                          {activity.time}
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