import { type NextRequest } from "next/server"
import { authMiddleware } from "@/src/core/lib/middleware/auth"
import User, { IUser } from "@/src/core/lib/models/User"

export interface SessionUser {
  id: string
  username: string
  email: string
  role: string
  firstName?: string
  lastName?: string
}

export async function getSessionUser(req?: NextRequest): Promise<SessionUser | null> {
  try {
    if (req) {
      // Server-side with request object
      const authResult = await authMiddleware(req)
      
      if (!authResult.success || !authResult.userId) {
        return null
      }

      const user = await User.findById(authResult.userId).select('-password -refreshToken')
      if (!user) {
        return null
      }

      return {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        role: user.role,
        firstName: user.firstName,
        lastName: user.lastName
      }
    }

    // Client-side or no request object provided
    return null
  } catch (error) {
    console.error('Error getting session user:', error)
    return null
  }
}

export async function requireAuth(req: NextRequest): Promise<SessionUser> {
  const user = await getSessionUser(req)
  
  if (!user) {
    throw new Error('Authentication required')
  }
  
  return user
}

export async function requireAdmin(req: NextRequest): Promise<SessionUser> {
  const user = await requireAuth(req)
  
  if (user.role !== 'admin') {
    throw new Error('Admin access required')
  }
  
  return user
}
