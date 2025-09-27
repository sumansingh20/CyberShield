"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { Wifi, Shield, AlertTriangle, Lock, Unlock, Radio, Clock, Zap } from "lucide-react"

interface WirelessNetwork {
  ssid: string
  bssid: string
  channel: number
  signal: number
  encryption: string
  wps: boolean
  clients: number
  vendor: string
}

export default function WirelessPage() {
  const [isScanning, setIsScanning] = useState(false)
  const [progress, setProgress] = useState(0)
  const [networks, setNetworks] = useState<WirelessNetwork[]>([])

  const handleScan = async () => {
    setIsScanning(true)
    setProgress(0)
    setNetworks([])

    const mockNetworks: WirelessNetwork[] = [
      {
        ssid: "HomeNetwork_5G",
        bssid: "AA:BB:CC:DD:EE:FF",
        channel: 36,
        signal: -45,
        encryption: "WPA2-PSK",
        wps: false,
        clients: 5,
        vendor: "Netgear"
      },
      {
        ssid: "OpenWiFi",
        bssid: "11:22:33:44:55:66",
        channel: 6,
        signal: -62,
        encryption: "Open",
        wps: false,
        clients: 0,
        vendor: "Linksys"
      },
      {
        ssid: "CorporateNet",
        bssid: "77:88:99:AA:BB:CC",
        channel: 11,
        signal: -38,
        encryption: "WPA3-Enterprise",
        wps: false,
        clients: 12,
        vendor: "Cisco"
      }
    ]

    for (let i = 0; i <= 100; i += 10) {
      setProgress(i)
      await new Promise(resolve => setTimeout(resolve, 200))
    }

    setNetworks(mockNetworks)
    setIsScanning(false)
  }

  const getSignalStrength = (signal: number) => {
    if (signal > -50) return "Excellent"
    if (signal > -60) return "Good"
    if (signal > -70) return "Fair"
    return "Poor"
  }

  const getEncryptionColor = (encryption: string) => {
    if (encryption === "Open") return "text-red-600 bg-red-100"
    if (encryption.includes("WEP")) return "text-orange-600 bg-orange-100"
    if (encryption.includes("WPA3")) return "text-green-600 bg-green-100"
    return "text-blue-600 bg-blue-100"
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 p-4">
      <div className="container mx-auto max-w-6xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-3">
            <div className="p-3 rounded-xl bg-gradient-to-br from-teal-600 to-blue-600 text-white shadow-xl">
              <Wifi className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-teal-600 to-blue-600 bg-clip-text text-transparent">
                Wireless Security Scanner
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                WiFi network analysis and security assessment
              </p>
            </div>
          </div>
          
          <div className="flex items-center justify-center space-x-4">
            <Badge className="bg-teal-500/10 text-teal-600 border-teal-200 dark:border-teal-800">
              <Wifi className="w-3 h-3 mr-1" />
              Advanced
            </Badge>
            <Badge className="bg-blue-500/10 text-blue-600 border-blue-200 dark:border-blue-800">
              <Shield className="w-3 h-3 mr-1" />
              Wireless Security
            </Badge>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          {/* Control Panel */}
          <div className="lg:col-span-1">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Radio className="h-5 w-5" />
                  Scanner Control
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <Button 
                  onClick={handleScan} 
                  disabled={isScanning}
                  className="w-full"
                >
                  {isScanning ? (
                    <>
                      <Clock className="mr-2 h-4 w-4 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Wifi className="mr-2 h-4 w-4" />
                      Start WiFi Scan
                    </>
                  )}
                </Button>

                {isScanning && (
                  <div className="space-y-2">
                    <Progress value={progress} className="w-full" />
                    <p className="text-sm text-center">{progress}%</p>
                  </div>
                )}

                <div className="text-xs text-gray-500 space-y-2">
                  <p><strong>Scan Features:</strong></p>
                  <ul className="list-disc list-inside space-y-1">
                    <li>Network Discovery</li>
                    <li>Signal Strength</li>
                    <li>Encryption Analysis</li>
                    <li>WPS Detection</li>
                    <li>Client Enumeration</li>
                  </ul>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Results Panel */}
          <div className="lg:col-span-3">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Discovered Networks ({networks.length})
                </CardTitle>
                <CardDescription>
                  Wireless networks in range
                </CardDescription>
              </CardHeader>
              <CardContent>
                {networks.length > 0 ? (
                  <div className="space-y-4">
                    {networks.map((network, index) => (
                      <div key={index} className="p-4 rounded-lg border bg-white/50 dark:bg-slate-700/50">
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center space-x-3">
                            <div className="p-2 rounded-lg bg-teal-500/10">
                              <Wifi className="h-4 w-4 text-teal-600" />
                            </div>
                            <div>
                              <h3 className="font-semibold text-lg">{network.ssid || "Hidden Network"}</h3>
                              <p className="text-sm text-gray-500 font-mono">{network.bssid}</p>
                            </div>
                          </div>
                          <div className="flex items-center space-x-2">
                            {network.encryption === "Open" ? (
                              <Unlock className="h-4 w-4 text-red-500" />
                            ) : (
                              <Lock className="h-4 w-4 text-green-500" />
                            )}
                            <Badge className={getEncryptionColor(network.encryption)}>
                              {network.encryption}
                            </Badge>
                          </div>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                          <div>
                            <span className="text-gray-500">Channel:</span>
                            <div className="font-semibold">{network.channel}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">Signal:</span>
                            <div className="font-semibold">{network.signal} dBm ({getSignalStrength(network.signal)})</div>
                          </div>
                          <div>
                            <span className="text-gray-500">Clients:</span>
                            <div className="font-semibold">{network.clients}</div>
                          </div>
                          <div>
                            <span className="text-gray-500">Vendor:</span>
                            <div className="font-semibold">{network.vendor}</div>
                          </div>
                        </div>

                        {network.wps && (
                          <div className="mt-3 p-2 rounded bg-orange-100 dark:bg-orange-900/20">
                            <div className="flex items-center space-x-2 text-orange-600">
                              <AlertTriangle className="h-4 w-4" />
                              <span className="text-sm font-medium">WPS Enabled - Potential Security Risk</span>
                            </div>
                          </div>
                        )}

                        {network.encryption === "Open" && (
                          <div className="mt-3 p-2 rounded bg-red-100 dark:bg-red-900/20">
                            <div className="flex items-center space-x-2 text-red-600">
                              <AlertTriangle className="h-4 w-4" />
                              <span className="text-sm font-medium">Open Network - No Encryption</span>
                            </div>
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                ) : (
                  <div className="text-center py-12 text-gray-500">
                    <Wifi className="h-12 w-12 mx-auto mb-4 opacity-50" />
                    <p>No wireless networks discovered.</p>
                    <p className="text-sm">Click "Start WiFi Scan" to discover nearby networks.</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </div>
      </div>
    </div>
  )
}