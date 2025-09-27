import jwt from 'jsonwebtoken'

function getJWTSecret(): string {
  const JWT_SECRET = process.env.JWT_SECRET
  
  // During build time, return a placeholder to avoid build errors
  if (process.env.NODE_ENV === 'production' && !JWT_SECRET) {
    return 'build-time-placeholder-secret'
  }
  
  if (!JWT_SECRET) {
    throw new Error('JWT_SECRET is not defined in environment variables')
  }
  return JWT_SECRET
}

export function verifyJWT<T = any>(token: string): T {
  const secret = getJWTSecret()
  
  // Prevent usage with placeholder secret at runtime
  if (secret === 'build-time-placeholder-secret') {
    throw new Error('JWT_SECRET is not properly configured for production')
  }
  
  return jwt.verify(token, secret) as T
}

export function signJWT(payload: object, options?: jwt.SignOptions): string {
  const secret = getJWTSecret()
  
  // Prevent usage with placeholder secret at runtime
  if (secret === 'build-time-placeholder-secret') {
    throw new Error('JWT_SECRET is not properly configured for production')
  }
  
  return jwt.sign(payload, secret, options)
}

export interface TokenPayload {
  userId: string
  email: string
  role?: string
  username?: string
}

export interface TempTokenPayload {
  userId: string
  email: string
  type: 'temp-2fa'
}
