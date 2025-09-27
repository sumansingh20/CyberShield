import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'
import { verifyJWT } from '@/src/core/lib/utils/jwt'

// Tool access configuration
interface ToolConfig {
  accessLevel: 'free' | 'premium' | 'expert'
  freeUsageLimit?: number
}

const TOOL_ACCESS_CONFIG: Record<string, ToolConfig> = {
  // Free tools - accessible to everyone with usage limits for non-authenticated users
  '/tools/whois': { accessLevel: 'free', freeUsageLimit: 5 },
  '/tools/dns-lookup': { accessLevel: 'free', freeUsageLimit: 5 },
  '/tools/http-headers': { accessLevel: 'free', freeUsageLimit: 10 },
  
  // Premium tools - require authentication
  '/tools/network-scan': { accessLevel: 'premium' },
  '/tools/port-scanner': { accessLevel: 'premium' },
  '/tools/subdomain-enum': { accessLevel: 'premium' },
  '/tools/vuln-scanner': { accessLevel: 'premium' },
  '/tools/subdomain': { accessLevel: 'premium' },
  '/tools/nmap': { accessLevel: 'premium' },
  
  // Expert tools - require authentication and potentially special permissions
  '/tools/advanced/masscan': { accessLevel: 'expert' },
  '/tools/advanced/dirbuster': { accessLevel: 'expert' },
  '/tools/advanced/osint': { accessLevel: 'expert' },
  '/tools/advanced/wireless': { accessLevel: 'expert' },
  '/tools/advanced/mobile': { accessLevel: 'expert' },
  '/tools/advanced/crypto': { accessLevel: 'expert' },
  '/tools/advanced/forensics': { accessLevel: 'expert' },
  '/tools/advanced/social': { accessLevel: 'expert' },
  '/tools/expert/metasploit': { accessLevel: 'expert' },
  '/tools/expert/burpsuite': { accessLevel: 'expert' },
  '/tools/expert/cloud-security': { accessLevel: 'expert' },
  '/tools/expert/network-analysis': { accessLevel: 'expert' },
  '/tools/expert/binary-analysis': { accessLevel: 'expert' },
  '/tools/expert/container-security': { accessLevel: 'expert' },
}

async function isAuthenticated(request: NextRequest): Promise<boolean> {
  try {
    const accessToken = request.cookies.get('accessToken')?.value || 
                       request.headers.get('authorization')?.replace('Bearer ', '')
    
    if (!accessToken) return false

    await verifyJWT(accessToken)
    return true
  } catch {
    return false
  }
}

function getUsageCount(request: NextRequest, toolPath: string): number {
  // For server-side rate limiting, we'd use Redis or database
  // For now, rely on client-side session storage tracking
  return 0
}

function hasExceededUsageLimit(request: NextRequest, toolPath: string, limit: number): boolean {
  // In a real implementation, track usage server-side
  // For demo purposes, return false - client handles this
  return false
}

function createUnauthorizedResponse(message: string) {
  return NextResponse.json(
    { 
      error: 'Unauthorized', 
      message,
      requiresAuth: true 
    }, 
    { status: 401 }
  )
}

function createForbiddenResponse(message: string) {
  return NextResponse.json(
    { 
      error: 'Forbidden', 
      message,
      requiresUpgrade: true 
    }, 
    { status: 403 }
  )
}

export function middleware(request: NextRequest) {
  const pathname = request.nextUrl.pathname

  // Allow access to all tools
  return NextResponse.next()
}

export const config = {
  matcher: [
    // Match all tool routes
    '/tools/:path*',
    // Exclude static files and API routes from middleware
    '/((?!api|_next/static|_next/image|favicon.ico).*)',
  ],
}
