import { SignJWT, jwtVerify } from 'jose';
import { type ExtendedJWTPayload } from '@/lib/types/jwt';

export function getJWTSecretKey(): string {
  const secret = process.env.JWT_SECRET || process.env.AUTH_SECRET;
  if (!secret) {
    throw new Error('JWT Secret key is not set in environment variables');
  }
  return secret;
}

export async function verifyJWT(token: string): Promise<ExtendedJWTPayload> {
  try {
    const { payload } = await jwtVerify(
      token,
      new TextEncoder().encode(getJWTSecretKey())
    );
    return payload as ExtendedJWTPayload;
  } catch (error) {
    if (process.env.NODE_ENV === 'development') {
      console.error('JWT Verification Error:', error);
    }
    throw new Error('Your token has expired.');
  }
}

export async function signJWT(
  payload: ExtendedJWTPayload,
  expiresIn: string | number = '24h'
) {
  try {
    const secret = new TextEncoder().encode(getJWTSecretKey());
    const token = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'HS256' })
      .setIssuedAt()
      .setExpirationTime(expiresIn)
      .sign(secret);
    return token;
  } catch (error) {
    console.error('JWT Signing Error:', error);
    throw new Error('Error signing JWT');
  }
}

export async function generateTokens(payload: Omit<ExtendedJWTPayload, 'type'>) {
  const basePayload = {
    userId: String(payload.userId),
    email: String(payload.email),
    role: String(payload.role)
  }
  
  const accessToken = await signJWT({ ...basePayload, type: 'access' } as ExtendedJWTPayload, '15m');
  const refreshToken = await signJWT({ ...basePayload, type: 'refresh' } as ExtendedJWTPayload, '7d');
  return { accessToken, refreshToken };
}

export function blacklistToken(token: string, expiresIn: number) {
  // This is a no-op for now.
  // A proper implementation requires a persistent blacklist (e.g., in a database).
  console.warn('Token blacklisting is not implemented.');
}

export async function verifyAccessToken(token: string): Promise<ExtendedJWTPayload> {
  const secret = new TextEncoder().encode(getJWTSecretKey());
  try {
    const { payload } = await jwtVerify(token, secret);
    const extendedPayload = payload as ExtendedJWTPayload;
    if (extendedPayload.type !== 'access') {
      throw new Error('Invalid token type');
    }
    return extendedPayload;
  } catch (error: any) {
    if (error.code === 'ERR_JWT_EXPIRED') {
      throw new Error('Access token has expired');
    }
    throw new Error('Invalid access token');
  }
}

export async function verifyRefreshToken(token: string): Promise<ExtendedJWTPayload> {
  const secret = new TextEncoder().encode(getJWTSecretKey());
  try {
    const { payload } = await jwtVerify(token, secret);
    const extendedPayload = payload as ExtendedJWTPayload;
    if (extendedPayload.type !== 'refresh') {
      throw new Error('Invalid token type');
    }
    return extendedPayload;
  } catch (error: any) {
    if (error.code === 'ERR_JWT_EXPIRED') {
      throw new Error('Refresh token has expired');
    }
    throw new Error('Invalid refresh token');
  }
}
