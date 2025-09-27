"use client"

import { Card, CardContent, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Badge } from "@/src/ui/components/ui/badge"
import { ScrollArea } from "@/src/ui/components/ui/scroll-area"
import { useState, useEffect } from "react"
import { formatDistanceToNow } from "date-fns"
import {
  ActivitySquare,
  AlertTriangle,
  CheckCircle,
  Clock,
  ShieldAlert,
  XCircle,
} from "lucide-react"

interface Activity {
  id: string
  toolName: string
  toolCategory: string
  status: string
  target: string
  timestamp: string
  duration: number
  vulnerabilities: {
    total: number
    critical: number
    high: number
    medium: number
    low: number
  }
}

export default function ActivityPage() {
  const [activities, setActivities] = useState<Activity[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    async function fetchActivities() {
      try {
        setLoading(true)
        const res = await fetch("/api/activity")
        
        if (!res.ok) {
          throw new Error("Failed to fetch activities")
        }
        
        const data = await res.json()
        console.log("API Response:", data)  // Debug log
        
        if (!data.activities || !Array.isArray(data.activities)) {
          throw new Error("Invalid response format")
        }
        
        setActivities(data.activities)
      } catch (err) {
        console.error("Error:", err)
        setError(err instanceof Error ? err.message : "An error occurred")
      } finally {
        setLoading(false)
      }
    }

    fetchActivities()
  }, [])

  if (loading) {
    return (
      <div className="container py-6">
        <Card>
          <CardHeader>
            <CardTitle>Loading activity...</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              {[1, 2, 3].map(i => (
                <div key={i} className="animate-pulse">
                  <div className="h-4 bg-muted rounded w-3/4 mb-2" />
                  <div className="h-3 bg-muted rounded w-1/2" />
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    )
  }

  if (error) {
    return (
      <div className="container py-6">
        <Card className="border-destructive">
          <CardHeader>
            <CardTitle className="text-destructive">Error</CardTitle>
          </CardHeader>
          <CardContent>
            <p>{error}</p>
          </CardContent>
        </Card>
      </div>
    )
  }

  function getStatusIcon(status: string) {
    switch (status.toLowerCase()) {
      case "success":
        return <CheckCircle className="h-4 w-4 text-green-500" />
      case "error":
        return <XCircle className="h-4 w-4 text-red-500" />
      case "warning":
      case "in-progress":
        return <AlertTriangle className="h-4 w-4 text-yellow-500" />
      default:
        return <Clock className="h-4 w-4 text-gray-500" />
    }
  }

  function getStatusColor(status: string) {
    switch (status.toLowerCase()) {
      case "success":
        return "bg-green-500/10 text-green-500"
      case "error":
        return "bg-red-500/10 text-red-500"
      case "warning":
      case "in-progress":
        return "bg-yellow-500/10 text-yellow-500"
      default:
        return "bg-gray-500/10 text-gray-500"
    }
  }

  return (
    <div className="container py-6">
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <ActivitySquare className="h-5 w-5" />
            Recent Activity
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ScrollArea className="h-[500px] pr-4">
            <div className="space-y-4">
              {activities.length === 0 ? (
                <div className="text-center py-8">
                  <Clock className="h-8 w-8 mx-auto mb-2 text-muted-foreground" />
                  <p className="text-muted-foreground">No activity yet</p>
                </div>
              ) : (
                activities.map((activity) => (
                  <Card key={activity.id} className="hover:bg-accent/50 transition-colors">
                    <CardContent className="p-4">
                      <div className="flex justify-between items-start mb-2">
                        <div>
                          <h3 className="font-medium">{activity.toolName}</h3>
                          <p className="text-sm text-muted-foreground">
                            Target: {activity.target}
                          </p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant="secondary">
                            {activity.toolCategory}
                          </Badge>
                          <Badge className={getStatusColor(activity.status)}>
                            {activity.status}
                          </Badge>
                        </div>
                      </div>
                      
                      {activity.vulnerabilities.total > 0 && (
                        <div className="flex flex-wrap gap-2 mt-2">
                          {activity.vulnerabilities.critical > 0 && (
                            <Badge variant="destructive" className="flex items-center gap-1">
                              <ShieldAlert className="h-3 w-3" />
                              {activity.vulnerabilities.critical} Critical
                            </Badge>
                          )}
                          {activity.vulnerabilities.high > 0 && (
                            <Badge variant="destructive" className="flex items-center gap-1">
                              <AlertTriangle className="h-3 w-3" />
                              {activity.vulnerabilities.high} High
                            </Badge>
                          )}
                          {activity.vulnerabilities.total > 0 && (
                            <Badge variant="outline">
                              {activity.vulnerabilities.total} Total Findings
                            </Badge>
                          )}
                        </div>
                      )}
                      
                      <div className="flex items-center gap-2 mt-2 text-sm text-muted-foreground">
                        {getStatusIcon(activity.status)}
                        <span>
                          {formatDistanceToNow(new Date(activity.timestamp), { addSuffix: true })}
                        </span>
                        <span>•</span>
                        <span>{(activity.duration / 1000).toFixed(1)}s</span>
                      </div>
                    </CardContent>
                  </Card>
                ))
              )}
            </div>
          </ScrollArea>
        </CardContent>
      </Card>
    </div>
  )
}
