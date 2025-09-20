"use client"

import { useState } from "react"
import { useAuth } from "@/contexts/AuthContext"
import { toast } from "@/hooks/use-toast"

interface ApiOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE"
  body?: any
  requiresAuth?: boolean
}

export function useApi() {
  const [loading, setLoading] = useState(false)
  const { accessToken, logout } = useAuth()

  // Function to get CSRF token
  const getCSRFToken = async () => {
    try {
      const response = await fetch("/api/auth/csrf")
      const data = await response.json()
      return data.token
    } catch (error) {
      console.error("Failed to get CSRF token:", error)
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

      // Add CSRF token for mutation requests
      if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
        const csrfToken = await getCSRFToken()
        if (csrfToken) {
          headers["x-csrf-token"] = csrfToken
        }
      }

      if (requiresAuth && accessToken) {
        headers.Authorization = `Bearer ${accessToken}`
      }

      const response = await fetch(endpoint, {
        method,
        headers,
        body: body ? JSON.stringify(body) : undefined,
      })

      let data
      try {
        const text = await response.text()
        data = text ? JSON.parse(text) : {}
      } catch (parseError) {
        console.error("Failed to parse response as JSON:", parseError)
        throw new Error("Invalid response format from server")
      }

      if (!response.ok) {
        if (response.status === 401) {
          logout()
          toast({
            title: "Session Expired",
            description: "Please log in again.",
            variant: "destructive",
          })
          return null
        }
        if (data?.error) {
          throw new Error(data.error)
        }
        throw new Error(`Server error: ${response.status}`)
      }
      if (data?.error) {
        throw new Error(data.error)
      }

      return data
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
