import { type NextRequest, NextResponse } from "next/server"

interface RateLimitStore {
  [key: string]: {
    count: number
    resetTime: number
  }
}

const store: RateLimitStore = {}

export function rateLimit(options: {
  windowMs?: number
  max?: number
  skipFailedRequests?: boolean
} = {}) {
  const {
    windowMs = 60 * 1000, // 1 minute default
    max = 5, // 5 requests per window default
    skipFailedRequests = false
  } = options

  return (handler: Function) => {
    return async (req: NextRequest, ...args: any[]) => {
      const key = req.headers.get('x-real-ip') || 
                req.headers.get('x-forwarded-for') || 
                'unknown'
      const now = Date.now()

      // Clean up old entries
      if (store[key] && store[key].resetTime <= now) {
        delete store[key]
      }

      // Initialize or get current window
      if (!store[key]) {
        store[key] = {
          count: 0,
          resetTime: now + windowMs
        }
      }

      // Check if limit is exceeded
      if (store[key].count >= max) {
        return NextResponse.json({
          error: "Too many requests",
          retryAfter: Math.ceil((store[key].resetTime - now) / 1000)
        }, { status: 429 })
      }

      // Increment counter
      store[key].count++

      // Process request
      try {
        const response = await handler(req, ...args)
        
        // Reset count on failure if skipFailedRequests is true
        if (skipFailedRequests && response.status >= 400) {
          store[key].count--
        }
        
        return response
      } catch (error) {
        // Reset count on error if skipFailedRequests is true
        if (skipFailedRequests) {
          store[key].count--
        }
        throw error
      }
    }
  }
}
