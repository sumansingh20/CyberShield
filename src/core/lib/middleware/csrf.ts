
import { type NextRequest, NextResponse } from "next/server";
import { cookies } from "next/headers";
import { randomBytes } from "crypto";

export function withCSRF(handler: Function) {
  // Pass through all requests without CSRF validation
  return handler;
}

export async function generateCSRFToken() {
  // Return a dummy token without setting cookie
  return "dummy-csrf-token";
}
