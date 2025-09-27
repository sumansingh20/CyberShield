import { type NextRequest, NextResponse } from "next/server"
import { verifyJWT } from "@/src/core/lib/utils/jwt"

interface AuthResult {
  success: boolean
  userId?: string
  error?: string
}

export async function authMiddleware(req: NextRequest): Promise<AuthResult> {
  try {
    // Try to get token from Authorization header
    let token = req.headers.get("authorization")?.replace("Bearer ", "");

    // If no token in header, try to get from cookies (NextRequest API)
    if (!token) {
      token = req.cookies.get("token")?.value;
    }

    // If still no token, try refresh token
    if (!token) {
      token = req.cookies.get("refreshToken")?.value;
    }

    if (!token) {
      console.log("No token found in request", {
        headers: req.headers.has("authorization"),
        cookies: {
          token: req.cookies.has("token"),
          refreshToken: req.cookies.has("refreshToken"),
        },
      });
      return {
        success: false,
        error: "No authentication token found",
      };
    }

    // Verify the token
    const payload = await verifyJWT(token);
    if (!payload?.userId) {
      return {
        success: false,
        error: "Invalid token",
      };
    }

    return {
      success: true,
      userId: payload.userId,
    };
  } catch (error) {
    console.error("Auth error:", error);
    return {
      success: false,
      error: error instanceof Error ? error.message : "Authentication failed",
    };
  }
}

export function withAuth(handler: (req: NextRequest) => Promise<Response>) {
  return async (req: NextRequest) => {
    const authResult = await authMiddleware(req);
    
    if (!authResult.success) {
      return NextResponse.json({ error: authResult.error }, { status: 401 });
    }

    // Attach user info to request for downstream handlers
    (req as any).user = { userId: authResult.userId };
    
    return handler(req);
  };
}

export function withAdminAuth(handler: Function) {
  return withAuth(async (req: NextRequest) => {
    const user = (req as any).user

    if (user.role !== "admin") {
      return NextResponse.json({ error: "Admin access required" }, { status: 403 })
    }

    return handler(req)
  })
}
