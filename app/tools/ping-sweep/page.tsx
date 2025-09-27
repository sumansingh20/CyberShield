"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Activity, CheckCircle, AlertCircle, Loader2 } from "lucide-react"
import { useApi } from "@/src/ui/hooks/useApi"
import { useToast } from "@/src/ui/hooks/use-toast"

export default function PingSweepPage() {
  const [network, setNetwork] = useState("")
  const [results, setResults] = useState<any>(null)
  const [isLoading, setIsLoading] = useState(false)
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleSweep = async () => {
    if (!network.trim()) {
      toast({
        title: "Error",
        description: "Please enter a network range to scan",
        variant: "destructive"
      })
      return
    }

    setIsLoading(true)
    setResults(null)

    try {
      const response = await apiCall("/api/tools/ping-sweep", {
        method: "POST",
        body: { network: network.trim() },
        requiresAuth: false
      })

      if (response) {
        setResults(response)
        toast({
          title: "Success",
          description: `Found ${response.liveHosts?.length || 0} live hosts`
        })
      }
    } catch (error) {
      toast({
        title: "Error", 
        description: "Failed to perform ping sweep",
        variant: "destructive"
      })
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-900 dark:to-gray-800 p-4">
      <div className="container mx-auto max-w-4xl">
        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-4">
            <Activity className="h-12 w-12 text-blue-500 mr-4" />
            <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              Ping Sweep
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-300 text-lg">
            Discover live hosts on a network range
          </p>
          <Badge className="mt-2" variant="outline">Beginner</Badge>
        </div>

        {/* Input Form */}
        <Card className="mb-8">
          <CardHeader>
            <CardTitle className="flex items-center">
              <Activity className="h-5 w-5 mr-2" />
              Network Range
            </CardTitle>
            <CardDescription>
              Enter the network range to perform ping sweep
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div>
                <Label htmlFor="network">Network Range</Label>
                <Input
                  id="network"
                  placeholder="192.168.1.0/24 or 192.168.1.1-192.168.1.254"
                  value={network}
                  onChange={(e) => setNetwork(e.target.value)}
                  className="mt-1"
                />
                <p className="text-sm text-gray-500 mt-1">
                  Examples: 192.168.1.0/24, 10.0.0.1-10.0.0.50, 172.16.1.0/28
                </p>
              </div>
              <Button 
                onClick={handleSweep}
                disabled={isLoading}
                className="w-full"
              >
                {isLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Activity className="h-4 w-4 mr-2" />
                    Start Ping Sweep
                  </>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Results */}
        {results && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center">
                <CheckCircle className="h-5 w-5 mr-2 text-green-500" />
                Live Hosts
              </CardTitle>
              <CardDescription>
                Discovered {results.liveHosts?.length || 0} live hosts in {results.network}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {results.liveHosts && results.liveHosts.length > 0 ? (
                <div className="space-y-3">
                  {results.liveHosts.map((host: any, index: number) => (
                    <div key={index} className="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700 rounded-lg">
                      <div className="flex items-center">
                        <div className="font-mono text-lg font-semibold mr-4">
                          {host.ip}
                        </div>
                        <div>
                          {host.hostname && (
                            <div className="font-medium">{host.hostname}</div>
                          )}
                          <div className="text-sm text-gray-500">
                            Response time: {host.responseTime || 'N/A'}ms
                          </div>
                        </div>
                      </div>
                      <Badge className="text-green-600 bg-green-100 dark:bg-green-900">
                        Active
                      </Badge>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center py-8 text-gray-500">
                  <AlertCircle className="h-8 w-8 mx-auto mb-2" />
                  <p>No live hosts found in this network range</p>
                </div>
              )}
            </CardContent>
          </Card>
        )}

        {/* Info */}
        <Card className="mt-8">
          <CardHeader>
            <CardTitle>About Ping Sweep</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="prose dark:prose-invert max-w-none">
              <p>
                A ping sweep is a network reconnaissance technique used to discover live hosts 
                within a specified IP range. It sends ICMP echo requests (pings) to determine 
                which hosts are active and responsive.
              </p>
              <h4>Common network formats:</h4>
              <ul>
                <li><strong>CIDR notation:</strong> 192.168.1.0/24 (256 addresses)</li>
                <li><strong>Range notation:</strong> 192.168.1.1-192.168.1.50</li>
                <li><strong>Single host:</strong> 192.168.1.100</li>
              </ul>
              <div className="mt-4 p-4 bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg">
                <p className="text-sm text-yellow-800 dark:text-yellow-200">
                  <strong>Note:</strong> Only scan networks you own or have explicit permission to test.
                </p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}