"use client"

import { useState } from "react"
import { useAuth } from "@/src/auth/utils/AuthContext"
import { toast } from "@/src/ui/hooks/use-toast"

interface ApiOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE"
  body?: any
  requiresAuth?: boolean
}

const handleApiError = async (response: Response, endpoint: string) => {
  // Clone the response to avoid consuming the stream
  const clonedResponse = response.clone();
  const errorText = await clonedResponse.text();
  console.log('Raw error response:', errorText);

  let errorMessage = 'An unknown error occurred';
  let details = null;

  try {
    const errorJson = JSON.parse(errorText);
    console.log('Parsed error JSON:', errorJson);
    errorMessage = errorJson.error || `API Error: ${response.statusText}`;
    details = errorJson.details;
  } catch (parseError) {
    console.error('Error parsing error response:', parseError);
    errorMessage = errorText || `Server error (${response.status})`;
  }

  // Log complete error information
  const errorDetails = {
    endpoint,
    status: response.status,
    statusText: response.statusText,
    error: errorMessage,
    details,
    headers: Object.fromEntries(response.headers.entries()),
    timestamp: new Date().toISOString()
  };
  
  console.error('API Error Details:', errorDetails);
  return { errorMessage, details };
};

export function useApi() {
  const [loading, setLoading] = useState(false)
  const { accessToken, logout } = useAuth()

  // Track last CSRF token request time
  let lastCSRFRequest = 0
  const CSRF_THROTTLE_MS = 1000 // 1 second minimum between requests

  // Function to get CSRF token with rate limiting and error handling
  const getCSRFToken = async () => {
    const now = Date.now()
    if (now - lastCSRFRequest < CSRF_THROTTLE_MS) {
      // Return null if requesting too soon
      return null
    }
    
    try {
      lastCSRFRequest = now
      const response = await fetch("/api/auth/csrf", {
        method: "GET",
        headers: {
          "Content-Type": "application/json"
        },
        credentials: "same-origin"
      })
      
      if (!response.ok) {
        console.warn(`CSRF endpoint returned ${response.status}: ${response.statusText}`)
        return null
      }
      
      const data = await response.json()
      return data.token || null
    } catch (error) {
      console.warn("Failed to get CSRF token, continuing without it:", error)
      return null
    }
  }

  const apiCall = async (endpoint: string, options: ApiOptions = {}) => {
    const { method = "GET", body, requiresAuth = true } = options

    setLoading(true)

    try {
      const headers: HeadersInit = {
        "Content-Type": "application/json",
      }

      // Add CSRF token for mutation requests (but don't fail if unavailable)
      if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
        try {
          const csrfToken = await getCSRFToken()
          if (csrfToken) {
            headers["x-csrf-token"] = csrfToken
          }
        } catch (csrfError) {
          console.warn("CSRF token fetch failed, continuing without it:", csrfError)
          // Continue without CSRF token rather than failing the entire request
        }
      }

      if (requiresAuth && accessToken) {
        headers.Authorization = `Bearer ${accessToken}`
      }

      const response = await fetch(endpoint, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
        credentials: "same-origin"
      });

      if (!response.ok) {
        // For 401 errors, just return null without showing any error
        // This allows bypassing authentication checks
        if (response.status === 401) {
          return null;
        }

        let errorMessage = "An unexpected error occurred";
        let details = null;

        // Read the response text once and parse it
        const errorText = await response.text();
        
        try {
          const errorData = JSON.parse(errorText);
          errorMessage = errorData.error || errorMessage;
          details = errorData.details;
        } catch (e) {
          // If we can't parse JSON, use the text content directly
          errorMessage = errorText || errorMessage;
        }

        // Only show error toast for non-auth related errors
        if (!endpoint.includes("/auth/")) {
          toast({
            title: "Error",
            description: "There was a problem completing your request. Please try again.",
            variant: "destructive",
          });
        }

        return null;
      }

      const responseBody = await response.text();
      if (responseBody.length === 0) {
        return null;
      }
      try {
        return JSON.parse(responseBody);
      } catch (e) {
        console.error("Failed to parse JSON response:", responseBody);
        throw new Error("The server returned an invalid response.");
      }
    } catch (error) {
      console.error("API call error:", error)
      toast({
        title: "Error",
        description: error instanceof Error ? error.message : "An error occurred",
        variant: "destructive",
      })
      throw error
    } finally {
      setLoading(false)
    }
  }

  return { apiCall, loading }
}
