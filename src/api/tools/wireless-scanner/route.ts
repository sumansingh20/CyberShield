import { NextRequest, NextResponse } from "next/server"

interface WirelessScanRequest {
  target?: string
  scan_type: string
  interface: string
  channel?: number
  timeout: number
  capture_handshakes: boolean
  perform_deauth: boolean
  scan_hidden: boolean
}

interface WirelessNetwork {
  ssid: string
  bssid: string
  channel: number
  frequency: number
  signal_strength: number
  encryption: string
  security: string
  vendor: string
  vulnerability_score: number
  security_issues: string[]
  handshake_captured: boolean
  clients: number
  beacon_interval: number
  uptime: string
  country_code: string
  wps_enabled: boolean
  hidden: boolean
}

// Comprehensive wireless network database
const WIRELESS_NETWORKS_DB: WirelessNetwork[] = [
  {
    ssid: "NETGEAR_OpenNetwork",
    bssid: "00:14:22:01:23:45",
    channel: 6,
    frequency: 2437,
    signal_strength: -42,
    encryption: "Open",
    security: "None",
    vendor: "Netgear",
    vulnerability_score: 9.5,
    security_issues: [
      "No encryption - all traffic visible",
      "No authentication required",
      "Susceptible to man-in-the-middle attacks",
      "Easy target for rogue access point attacks"
    ],
    handshake_captured: false,
    clients: 8,
    beacon_interval: 100,
    uptime: "2d 14h 30m",
    country_code: "US",
    wps_enabled: false,
    hidden: false
  },
  {
    ssid: "LinkSys_WEP_Legacy",
    bssid: "00:18:39:7A:BC:DE",
    channel: 1,
    frequency: 2412,
    signal_strength: -55,
    encryption: "WEP",
    security: "WEP 64-bit",
    vendor: "Linksys",
    vulnerability_score: 8.5,
    security_issues: [
      "WEP encryption is easily crackable",
      "IV collision attacks possible",
      "Deprecated security protocol",
      "Can be cracked in minutes with enough traffic"
    ],
    handshake_captured: false,
    clients: 3,
    beacon_interval: 100,
    uptime: "7d 3h 15m",
    country_code: "US",
    wps_enabled: true,
    hidden: false
  },
  {
    ssid: "HOME_WiFi_WPA",
    bssid: "4C:ED:FB:12:34:56",
    channel: 11,
    frequency: 2462,
    signal_strength: -38,
    encryption: "WPA Personal",
    security: "WPA-PSK (TKIP)",
    vendor: "TP-Link",
    vulnerability_score: 6.5,
    security_issues: [
      "WPA (not WPA2) - weaker encryption",
      "TKIP protocol vulnerabilities",
      "Susceptible to dictionary attacks",
      "WPS enabled - PIN brute force possible"
    ],
    handshake_captured: true,
    clients: 12,
    beacon_interval: 100,
    uptime: "15d 8h 45m",
    country_code: "US",
    wps_enabled: true,
    hidden: false
  },
  {
    ssid: "Enterprise_Secure",
    bssid: "B0:48:7A:99:88:77",
    channel: 36,
    frequency: 5180,
    signal_strength: -45,
    encryption: "WPA2 Enterprise",
    security: "WPA2-Enterprise (AES)",
    vendor: "Cisco",
    vulnerability_score: 2.0,
    security_issues: [
      "Strong configuration detected",
      "Certificate validation recommended"
    ],
    handshake_captured: false,
    clients: 45,
    beacon_interval: 100,
    uptime: "30d 12h 20m",
    country_code: "US",
    wps_enabled: false,
    hidden: false
  },
  {
    ssid: "Modern_WPA3_Network",
    bssid: "E8:DE:27:45:67:89",
    channel: 149,
    frequency: 5745,
    signal_strength: -52,
    encryption: "WPA3 Personal",
    security: "WPA3-SAE",
    vendor: "ASUS",
    vulnerability_score: 1.5,
    security_issues: [],
    handshake_captured: false,
    clients: 6,
    beacon_interval: 100,
    uptime: "5d 16h 10m",
    country_code: "US",
    wps_enabled: false,
    hidden: false
  },
  {
    ssid: "",
    bssid: "A0:21:B7:33:44:55",
    channel: 6,
    frequency: 2437,
    signal_strength: -65,
    encryption: "WPA2 Personal",
    security: "WPA2-PSK (AES)",
    vendor: "D-Link",
    vulnerability_score: 4.0,
    security_issues: [
      "Hidden SSID - security through obscurity",
      "Still vulnerable to targeted attacks",
      "SSID can be revealed through association"
    ],
    handshake_captured: true,
    clients: 2,
    beacon_interval: 100,
    uptime: "3d 9h 25m",
    country_code: "US",
    wps_enabled: false,
    hidden: true
  },
  {
    ssid: "Coffee_Shop_Free",
    bssid: "2C:B0:5D:66:77:88",
    channel: 8,
    frequency: 2447,
    signal_strength: -48,
    encryption: "Open",
    security: "Captive Portal",
    vendor: "Ubiquiti",
    vulnerability_score: 7.5,
    security_issues: [
      "Open network with captive portal",
      "Traffic not encrypted over the air",
      "Susceptible to packet sniffing",
      "Man-in-the-middle attacks possible"
    ],
    handshake_captured: false,
    clients: 23,
    beacon_interval: 100,
    uptime: "1d 4h 15m",
    country_code: "US",
    wps_enabled: false,
    hidden: false
  },
  {
    ssid: "IOT_Device_Network",
    bssid: "68:FF:7B:AA:BB:CC",
    channel: 3,
    frequency: 2422,
    signal_strength: -72,
    encryption: "WPA2 Personal",
    security: "WPA2-PSK (AES)",
    vendor: "Generic",
    vulnerability_score: 5.5,
    security_issues: [
      "Default credentials likely in use",
      "IoT device - may have firmware vulnerabilities",
      "Weak password policy suspected",
      "Limited security updates"
    ],
    handshake_captured: true,
    clients: 4,
    beacon_interval: 100,
    uptime: "45d 2h 50m",
    country_code: "US",
    wps_enabled: true,
    hidden: false
  }
]

function simulateWirelessScan(params: WirelessScanRequest): {
  networks: WirelessNetwork[]
  handshakes_captured: number
  deauth_successful: number
} {
  let networks = [...WIRELESS_NETWORKS_DB]
  
  // Filter by channel if specified
  if (params.channel) {
    networks = networks.filter(network => network.channel === params.channel)
  }
  
  // Filter by scan type
  if (params.scan_type === "passive") {
    // Passive scan - might miss some hidden networks
    networks = networks.slice(0, 6)
  } else if (params.scan_type === "active") {
    // Active scan - better detection
    networks = networks.slice(0, 7)
  }
  // Aggressive scan shows all networks
  
  // Handle hidden network scanning
  if (!params.scan_hidden) {
    networks = networks.filter(network => !network.hidden)
  }
  
  // Simulate handshake capture
  let handshakes_captured = 0
  let deauth_successful = 0
  
  if (params.capture_handshakes) {
    networks.forEach(network => {
      if (network.encryption.includes("WPA") && Math.random() > 0.3) {
        network.handshake_captured = true
        handshakes_captured++
      }
    })
  }
  
  if (params.perform_deauth) {
    networks.forEach(network => {
      if (network.clients > 0 && Math.random() > 0.4) {
        deauth_successful++
      }
    })
  }
  
  return { networks, handshakes_captured, deauth_successful }
}

function generateRecommendations(networks: WirelessNetwork[]): string[] {
  const recommendations: string[] = []
  
  const openNetworks = networks.filter(n => n.encryption === "Open").length
  const wepNetworks = networks.filter(n => n.encryption.includes("WEP")).length
  const wpaNetworks = networks.filter(n => n.encryption.includes("WPA") && !n.encryption.includes("WPA2")).length
  const wpsEnabled = networks.filter(n => n.wps_enabled).length
  const hiddenNetworks = networks.filter(n => n.hidden).length
  
  if (openNetworks > 0) {
    recommendations.push("Enable WPA3 or WPA2 encryption on open networks")
    recommendations.push("Implement a captive portal for guest networks if needed")
  }
  
  if (wepNetworks > 0) {
    recommendations.push("Immediately upgrade WEP networks to WPA2/WPA3")
    recommendations.push("WEP can be cracked in minutes - critical security risk")
  }
  
  if (wpaNetworks > 0) {
    recommendations.push("Upgrade WPA networks to WPA2 or WPA3")
    recommendations.push("Use AES encryption instead of TKIP")
  }
  
  if (wpsEnabled > 0) {
    recommendations.push("Disable WPS on all networks to prevent PIN brute force attacks")
  }
  
  if (hiddenNetworks > 0) {
    recommendations.push("Hidden SSIDs provide minimal security - use proper encryption instead")
  }
  
  recommendations.push("Use strong, unique passwords for all wireless networks")
  recommendations.push("Regularly update router firmware and change default credentials")
  recommendations.push("Enable MAC address filtering for sensitive networks")
  recommendations.push("Monitor for unauthorized devices regularly")
  recommendations.push("Consider network segmentation for IoT devices")
  
  return recommendations
}

export async function POST(request: NextRequest) {
  try {
    const body: WirelessScanRequest = await request.json()
    
    // Validate required fields
    if (!body.interface || !body.scan_type) {
      return NextResponse.json(
        { error: "Interface and scan type are required" },
        { status: 400 }
      )
    }
    
    // Simulate scan delay
    await new Promise(resolve => setTimeout(resolve, 2000))
    
    const scanResult = simulateWirelessScan(body)
    const recommendations = generateRecommendations(scanResult.networks)
    
    const vulnerableNetworks = scanResult.networks.filter(n => n.vulnerability_score >= 6).length
    const openNetworks = scanResult.networks.filter(n => n.encryption === "Open").length
    
    const result = {
      target: body.target || "General Area Scan",
      scan_type: body.scan_type,
      duration: body.timeout,
      networks_found: scanResult.networks.length,
      vulnerable_networks: vulnerableNetworks,
      open_networks: openNetworks,
      networks: scanResult.networks,
      handshakes_captured: scanResult.handshakes_captured,
      deauth_successful: scanResult.deauth_successful,
      recommendations,
      timestamp: new Date().toISOString()
    }
    
    return NextResponse.json(result)
    
  } catch (error) {
    console.error("Wireless scan error:", error)
    return NextResponse.json(
      { error: "Failed to perform wireless scan" },
      { status: 500 }
    )
  }
}
