"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { useApi } from "@/hooks/useApi"
import { useAuth } from "@/contexts/AuthContext"
import { toast } from "@/hooks/use-toast"
import { Shield, Mail, Lock, Eye, EyeOff } from "lucide-react"

export default function LoginPage() {
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  })
  const [showPassword, setShowPassword] = useState(false)
  const { apiCall, loading } = useApi()
  const { login } = useAuth()
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.email || !formData.password) {
      toast({
        title: "Missing Information",
        description: "Please fill in all fields",
        variant: "destructive",
      })
      return
    }

    try {
      const response = await apiCall("/api/auth/login", {
        method: "POST",
        body: formData,
        requiresAuth: false,
      })

      if (response) {
        if (response.requiresOTP) {
          toast({
            title: "Security Verification",
            description: "OTP sent to your email. Please check for verification code.",
          })
          router.push(`/verify-otp?userId=${response.userId}&purpose=login`)
        } else if (response.accessToken && response.user) {
          login(
            { accessToken: response.accessToken, refreshToken: response.refreshToken }, 
            response.user
          )
          toast({
            title: "Welcome back!",
            description: `Logged in successfully as ${response.user.email}`,
          })
          router.push("/dashboard")
        }
      }
    } catch (error) {
      console.error("Login failed:", error)
      // Error is handled by useApi hook and shown via toast
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData(prev => ({
      ...prev,
      [e.target.name]: e.target.value
    }))
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 dark:from-gray-900 dark:to-gray-800 flex items-center justify-center p-4">
      <Card className="w-full max-w-md shadow-xl">
        <CardHeader className="text-center pb-2">
          <div className="mx-auto mb-4 w-12 h-12 bg-blue-600 rounded-full flex items-center justify-center">
            <Shield className="w-6 h-6 text-white" />
          </div>
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Welcome Back
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Sign in to your CyberSec Pro account
          </p>
        </CardHeader>

        <CardContent className="space-y-4">
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email" className="text-sm font-medium">
                Email Address
              </Label>
              <div className="relative">
                <Mail className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="email"
                  name="email"
                  type="email"
                  value={formData.email}
                  onChange={handleChange}
                  className="pl-10"
                  placeholder="Enter your email"
                  required
                />
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium">
                Password
              </Label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  value={formData.password}
                  onChange={handleChange}
                  className="pl-10 pr-10"
                  placeholder="Enter your password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <Button 
              type="submit" 
              className="w-full bg-blue-600 hover:bg-blue-700" 
              disabled={loading}
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  Signing in...
                </>
              ) : (
                "Sign In"
              )}
            </Button>
          </form>

          <div className="space-y-4 pt-2">
            <div className="text-center">
              <Link 
                href="/forgot-password" 
                className="text-sm text-blue-600 hover:text-blue-800 dark:text-blue-400"
              >
                Forgot your password?
              </Link>
            </div>
            
            <div className="text-center text-sm text-gray-600 dark:text-gray-400">
              Don&apos;t have an account?{" "}
              <Link 
                href="/register" 
                className="text-blue-600 hover:text-blue-800 dark:text-blue-400 font-medium"
              >
                Sign up
              </Link>
            </div>
          </div>

          {process.env.NODE_ENV === 'development' && (
            <div className="text-center mt-4">
              <div className="text-xs text-green-600 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-2 rounded">
                 Development Mode Active
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}