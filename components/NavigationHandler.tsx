"use client"

import { useEffect } from "react"
import { useRouter, usePathname } from "next/navigation"
import { useAuth } from "@/contexts/AuthContext"

export function NavigationHandler() {
  const { isAuthenticated, isLoading } = useAuth()
  const router = useRouter()
  const pathname = usePathname()

  useEffect(() => {
    if (isLoading) return

    // If user is authenticated and on home page, redirect to dashboard
    if (isAuthenticated && pathname === "/") {
      router.push("/dashboard")
    }
  }, [isAuthenticated, isLoading, pathname, router])

  return null
}

export default NavigationHandler