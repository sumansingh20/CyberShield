"use client"

import type React from "react"
import { createContext, useContext, useState, useEffect, useMemo } from "react"

interface User {
  id: string
  username: string
  email: string
  role: string
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

  useEffect(() => {
    // Only access localStorage on the client side
    if (typeof window !== 'undefined') {
      // Load auth data from localStorage on mount
      const storedUser = localStorage.getItem("user")
      const storedAccessToken = localStorage.getItem("accessToken")
      const storedRefreshToken = localStorage.getItem("refreshToken")

      if (storedUser && storedAccessToken && storedRefreshToken) {
        try {
          setUser(JSON.parse(storedUser))
          setAccessToken(storedAccessToken)
          setRefreshToken(storedRefreshToken)
        } catch (error) {
          console.error('Failed to parse stored user data:', error)
          // Clear corrupted data
          localStorage.removeItem("user")
          localStorage.removeItem("accessToken")
          localStorage.removeItem("refreshToken")
        }
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
    throw new Error("useAuth must be used within an AuthProvider")
  }
  return context
}
