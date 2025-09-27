import { NextRequest, NextResponse } from "next/server"
import { exec } from "child_process"
import { promisify } from "util"

const execAsync = promisify(exec)

export async function POST(request: NextRequest) {
  try {
    const { target, scanType, timing, ports } = await request.json()

    if (!target) {
      return NextResponse.json(
        { error: "Target is required" },
        { status: 400 }
      )
    }

    // Validate target to prevent command injection
    const targetRegex = /^[0-9a-fA-F.:\/\-,\s]+$/
    if (!targetRegex.test(target)) {
      return NextResponse.json(
        { error: "Invalid target format" },
        { status: 400 }
      )
    }

    let nmapCommand = "nmap"
    
    // Add timing template
    if (timing) {
      nmapCommand += ` -${timing}`
    }

    // Configure scan type
    switch (scanType) {
      case "ping":
        nmapCommand += " -sn" // Ping scan only
        break
      case "basic":
        nmapCommand += " -F" // Fast scan (100 most common ports)
        break
      case "comprehensive":
        nmapCommand += " -p-" // All ports
        break
      case "stealth":
        nmapCommand += " -sS" // SYN stealth scan
        break
      case "service":
        nmapCommand += " -sV" // Service version detection
        break
      default:
        nmapCommand += " -F" // Default to fast scan
    }

    // Add custom ports if specified
    if (ports && ports.trim()) {
      const portsRegex = /^[0-9,\-\s]+$/
      if (!portsRegex.test(ports)) {
        return NextResponse.json(
          { error: "Invalid port format" },
          { status: 400 }
        )
      }
      nmapCommand += ` -p ${ports.trim()}`
    }

    // Add additional options for better output
    nmapCommand += " --open" // Only show open ports
    nmapCommand += " -oN -" // Normal output to stdout
    nmapCommand += ` ${target}`

    console.log("Executing network scan:", nmapCommand)

    try {
      const { stdout, stderr } = await execAsync(nmapCommand, {
        timeout: 300000, // 5 minutes timeout
        maxBuffer: 1024 * 1024 * 10, // 10MB buffer
      })

      let output = ""
      
      if (stdout) {
        output += stdout
      }
      
      if (stderr && stderr.trim()) {
        output += "\n\nWarnings/Errors:\n" + stderr
      }

      if (!output.trim()) {
        output = "No results found. The target may be down or filtered."
      }

      // Add scan summary
      const summary = generateScanSummary(stdout, scanType, target)
      
      return NextResponse.json({
        success: true,
        output: output,
        summary: summary,
        command: nmapCommand,
      })

    } catch (execError: any) {
      console.error("Nmap execution error:", execError)
      
      let errorOutput = "Network scan failed.\n\n"
      
      if (execError.code === 'ENOENT') {
        errorOutput += "Error: Nmap is not installed or not found in PATH.\n"
        errorOutput += "Please install nmap to use this feature.\n\n"
        errorOutput += "Installation instructions:\n"
        errorOutput += "• Ubuntu/Debian: sudo apt-get install nmap\n"
        errorOutput += "• CentOS/RHEL: sudo yum install nmap\n"
        errorOutput += "• macOS: brew install nmap\n"
        errorOutput += "• Windows: Download from https://nmap.org/download.html"
      } else if (execError.killed) {
        errorOutput += "Error: Scan timeout (5 minutes exceeded)\n"
        errorOutput += "Try using a faster timing template (T4 or T5) or smaller target range."
      } else {
        errorOutput += `Error: ${execError.message}\n`
        if (execError.stdout) {
          errorOutput += "\nPartial output:\n" + execError.stdout
        }
        if (execError.stderr) {
          errorOutput += "\nError details:\n" + execError.stderr
        }
      }

      return NextResponse.json({
        success: false,
        output: errorOutput,
        error: execError.message,
      })
    }

  } catch (error) {
    console.error("Network scan API error:", error)
    return NextResponse.json(
      { 
        error: "Internal server error",
        output: "Failed to process network scan request. Please check your input and try again."
      },
      { status: 500 }
    )
  }
}

function generateScanSummary(output: string, scanType: string, target: string): string {
  if (!output) return ""

  const lines = output.split('\n')
  let summary = `\n=== Scan Summary ===\n`
  summary += `Target: ${target}\n`
  summary += `Scan Type: ${scanType}\n`

  // Count hosts
  const hostLines = lines.filter(line => 
    line.includes('Nmap scan report for') || 
    line.includes('Host is up')
  )
  const hostCount = hostLines.length

  // Count open ports
  const portLines = lines.filter(line => 
    line.includes('/tcp') && line.includes('open')
  )
  const openPortCount = portLines.length

  summary += `Hosts Found: ${hostCount}\n`
  summary += `Open Ports: ${openPortCount}\n`

  // Extract common services
  const services = new Set<string>()
  portLines.forEach(line => {
    const match = line.match(/\d+\/tcp\s+open\s+(\w+)/)
    if (match) {
      services.add(match[1])
    }
  })

  if (services.size > 0) {
    summary += `Services Detected: ${Array.from(services).join(', ')}\n`
  }

  summary += `===================\n`
  
  return summary
}
