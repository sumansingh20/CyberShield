import { type JWTPayload } from 'jose'

export interface ExtendedJWTPayload extends JWTPayload {
  userId: string
  email: string
  role: string
  type?: 'access' | 'refresh'
}
