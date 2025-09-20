"use client"

import type React from "react"
import { createContext, useContext, useState, useEffect, useMemo } from "react"

interface User {
  id: string
  username: string
  email: string
  role: string
  firstName: string
  lastName: string
  phone: string
}

interface AuthContextType {
  user: User | null
  accessToken: string | null
  refreshToken: string | null
  login: (tokens: { accessToken: string; refreshToken: string }, user: User) => void
  logout: () => void
  isAuthenticated: boolean
  isLoading: boolean
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null)
  const [accessToken, setAccessToken] = useState<string | null>(null)
  const [refreshToken, setRefreshToken] = useState<string | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [refreshingToken, setRefreshingToken] = useState(false)

  // Function to decode JWT and check if it's expired
  const isTokenExpired = (token: string): boolean => {
    try {
      const payload = JSON.parse(atob(token.split('.')[1]))
      return payload.exp * 1000 < Date.now()
    } catch {
      return true
    }
  }

  // Function to refresh access token
  const refreshAccessToken = async (currentRefreshToken: string): Promise<boolean> => {
    try {
      setRefreshingToken(true)
      const response = await fetch('/api/auth/refresh-token', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${currentRefreshToken}`,
        },
      })

      if (response.ok) {
        const data = await response.json()
        setAccessToken(data.accessToken)
        setRefreshToken(data.refreshToken)
        localStorage.setItem('accessToken', data.accessToken)
        localStorage.setItem('refreshToken', data.refreshToken)
        return true
      } else {
        // If refresh fails, log out
        logout()
        return false
      }
    } catch (error) {
      console.error('Token refresh failed:', error)
      logout()
      return false
    } finally {
      setRefreshingToken(false)
    }
  }

  useEffect(() => {
    // Only access localStorage on the client side
    if (typeof window !== 'undefined') {
      try {
        // Load auth data from localStorage on mount
        const storedUser = localStorage.getItem("user")
        const storedAccessToken = localStorage.getItem("accessToken")
        const storedRefreshToken = localStorage.getItem("refreshToken")

        if (storedUser && storedAccessToken && storedRefreshToken) {
          try {
            const parsedUser = JSON.parse(storedUser)
            // Validate the parsed user object
            if (parsedUser && typeof parsedUser === 'object' && parsedUser.id && parsedUser.email) {
              setUser(parsedUser)
              
              // Check if access token is expired
              if (isTokenExpired(storedAccessToken) && !isTokenExpired(storedRefreshToken)) {
                // Attempt to refresh the token
                refreshAccessToken(storedRefreshToken)
              } else if (!isTokenExpired(storedAccessToken)) {
                setAccessToken(storedAccessToken)
                setRefreshToken(storedRefreshToken)
              } else {
                // Both tokens expired, clear auth state
                console.warn('All tokens expired, logging out...')
                localStorage.removeItem("user")
                localStorage.removeItem("accessToken")
                localStorage.removeItem("refreshToken")
              }
            } else {
              console.warn('Invalid user data in localStorage, clearing...')
              localStorage.removeItem("user")
              localStorage.removeItem("accessToken")
              localStorage.removeItem("refreshToken")
            }
          } catch (parseError) {
            console.error('Failed to parse stored user data:', parseError)
            // Clear corrupted data
            localStorage.removeItem("user")
            localStorage.removeItem("accessToken")
            localStorage.removeItem("refreshToken")
          }
        }
      } catch (storageError) {
        console.error('Error accessing localStorage:', storageError)
      }
    }

    setIsLoading(false)
  }, [])

  const login = (tokens: { accessToken: string; refreshToken: string }, userData: User) => {
    setUser(userData)
    setAccessToken(tokens.accessToken)
    setRefreshToken(tokens.refreshToken)

    // Only access localStorage on the client side
    if (typeof window !== 'undefined') {
      localStorage.setItem("user", JSON.stringify(userData))
      localStorage.setItem("accessToken", tokens.accessToken)
      localStorage.setItem("refreshToken", tokens.refreshToken)
    }
  }

  const logout = () => {
    setUser(null)
    setAccessToken(null)
    setRefreshToken(null)

    // Only access localStorage on the client side
    if (typeof window !== 'undefined') {
      localStorage.removeItem("user")
      localStorage.removeItem("accessToken")
      localStorage.removeItem("refreshToken")
    }
  }

  const value = useMemo(() => ({
    user,
    accessToken,
    refreshToken,
    login,
    logout,
    isAuthenticated: !!user && !!accessToken,
    isLoading,
  }), [user, accessToken, refreshToken, isLoading])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) {
    // Provide more specific error information
    throw new Error("useAuth must be used within an AuthProvider. Make sure your component is wrapped in <AuthProvider>.")
  }
  return context
}
