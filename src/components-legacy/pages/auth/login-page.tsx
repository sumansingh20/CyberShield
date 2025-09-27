"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Card, CardContent, CardHeader } from "@/src/ui/components/ui/card"
import { useApi } from "@/src/ui/hooks/useApi"
import { useAuth } from "@/src/auth/utils/AuthContext"
import { useToast } from "@/src/ui/hooks/use-toast"
import TwoFactorVerify from "@/src/auth/utils/TwoFactorVerify"
import { Mail, Lock, Eye, EyeOff, Shield, ArrowRight, AlertCircle } from "lucide-react"

export default function LoginPage() {
  const [formData, setFormData] = useState({
    email: "",
    password: "",
    rememberMe: false,
  })
  const [showPassword, setShowPassword] = useState(false)
  const [isLoading, setIsLoading] = useState(false)
  const [showTwoFactor, setShowTwoFactor] = useState(false)
  const [tempToken, setTempToken] = useState("")
  const [userEmail, setUserEmail] = useState("")
  const [errors, setErrors] = useState<{[key: string]: string}>({})
  const router = useRouter()
  const { apiCall } = useApi()
  const { login } = useAuth()
  const { toast } = useToast()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (isLoading) return
    
    setIsLoading(true)
    setErrors({})

    // Basic validation
    const newErrors: {[key: string]: string} = {}
    
    if (!formData.email.trim()) {
      newErrors.email = "Email is required"
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = "Please enter a valid email address"
    }
    
    if (!formData.password) {
      newErrors.password = "Password is required"
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      setIsLoading(false)
      toast({
        title: "Validation Error",
        description: "Please fix the errors in the form",
        variant: "destructive",
      })
      return
    }

    try {
      const response = await apiCall("/api/auth/login", {
        method: "POST",
        body: JSON.stringify(formData),
        requiresAuth: false
      })

      if (response && response.success) {
        if (response.requiresTwoFactor) {
          // 2FA required
          setTempToken(response.tempToken)
          setUserEmail(response.user.email)
          setShowTwoFactor(true)
          toast({
            title: "2FA Required 🔐",
            description: "Please enter your 2FA code to complete login.",
          })
        } else if (response.requiresVerification) {
          // Email/SMS verification required
          toast({
            title: "Verification Required 📧",
            description: "Please check your email and phone for verification codes.",
          })
          router.push(`/verify-otp?userId=${response.userId}&purpose=login`)
        } else {
          // Regular login success
          login(
            { 
              accessToken: response.tokens?.accessToken || response.accessToken, 
              refreshToken: response.tokens?.refreshToken || response.refreshToken
            }, 
            response.user
          )
          toast({
            title: "Welcome back! 🎉",
            description: `Successfully logged in as ${response.user.firstName || response.user.username}`,
          })
          router.push("/dashboard")
        }
      }
    } catch (error) {
      console.error("Login failed:", error)
      // Error is handled by useApi hook and shown via toast
    } finally {
      setIsLoading(false)
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: type === 'checkbox' ? checked : value
    }))
    
    // Clear errors when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ""
      }))
    }
  }

  const handleTwoFactorSuccess = (token: string, user: any) => {
    login({ accessToken: token, refreshToken: token }, user)
    toast({
      title: "Welcome back! 🎉",
      description: `Successfully logged in with 2FA as ${user.firstName || user.username}`,
    })
    router.push("/dashboard")
  }

  const handleTwoFactorBack = () => {
    setShowTwoFactor(false)
    setTempToken("")
    setUserEmail("")
  }

  // Show 2FA verification if required
  if (showTwoFactor) {
    return (
      <TwoFactorVerify
        tempToken={tempToken}
        userEmail={userEmail}
        onSuccess={handleTwoFactorSuccess}
        onBack={handleTwoFactorBack}
      />
    )
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 p-2 sm:p-4">
      {/* Background decoration */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-60 sm:w-80 h-60 sm:h-80 bg-blue-400/20 rounded-full blur-3xl"></div>
        <div className="absolute -bottom-40 -left-40 w-60 sm:w-80 h-60 sm:h-80 bg-purple-400/20 rounded-full blur-3xl"></div>
        <div className="absolute top-1/2 left-1/4 w-48 sm:w-64 h-48 sm:h-64 bg-green-400/10 rounded-full blur-3xl"></div>
      </div>

      <Card className="w-full max-w-sm sm:max-w-md relative z-10 shadow-2xl border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-xl mx-2">
        <CardHeader className="space-y-1 pb-4 sm:pb-6 px-4 sm:px-6">
          <div className="text-center">
            <div className="mx-auto mb-3 sm:mb-4 w-12 sm:w-16 h-12 sm:h-16 bg-gradient-to-br from-blue-600 to-purple-600 rounded-full flex items-center justify-center shadow-lg">
              <Shield className="w-6 sm:w-8 h-6 sm:h-8 text-white" />
            </div>
            <h1 className="text-xl sm:text-2xl md:text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              Welcome Back
            </h1>
            <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-300 mt-2">
              Sign in to your CyberShield account
            </p>
          </div>
        </CardHeader>

        <CardContent className="px-4 sm:px-6">
          <form onSubmit={handleSubmit} className="space-y-3 sm:space-y-4">
            <div className="space-y-2">
              <Label htmlFor="email" className="text-sm font-medium text-gray-700 dark:text-gray-300">
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
                  required
                  className={`pl-10 h-11 bg-white/50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 focus:border-blue-500 transition-colors ${
                    errors.email ? 'border-red-500 focus:border-red-500' : ''
                  }`}
                  placeholder="Enter your email address"
                />
                {errors.email && (
                  <div className="flex items-center gap-1 text-xs text-red-500 mt-1">
                    <AlertCircle className="w-3 h-3" />
                    {errors.email}
                  </div>
                )}
              </div>
            </div>

            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium text-gray-700 dark:text-gray-300">
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
                  required
                  className={`pl-10 pr-10 h-11 bg-white/50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 focus:border-blue-500 transition-colors ${
                    errors.password ? 'border-red-500 focus:border-red-500' : ''
                  }`}
                  placeholder="Enter your password"
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600 transition-colors"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
                {errors.password && (
                  <div className="flex items-center gap-1 text-xs text-red-500 mt-1">
                    <AlertCircle className="w-3 h-3" />
                    {errors.password}
                  </div>
                )}
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="rememberMe"
                  name="rememberMe"
                  checked={formData.rememberMe}
                  onChange={handleChange}
                  className="h-4 w-4 rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500"
                />
                <label htmlFor="rememberMe" className="text-sm text-gray-600 dark:text-gray-400">
                  Remember me
                </label>
              </div>
              
              <Link 
                href="/forgot-password" 
                className="text-sm text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 font-medium transition-colors"
              >
                Forgot password?
              </Link>
            </div>

            <Button
              type="submit"
              disabled={isLoading}
              className="w-full h-11 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-medium transition-all duration-200 transform hover:scale-[1.02] group"
            >
              {isLoading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2"></div>
                  Signing in...
                </>
              ) : (
                <>
                  Sign In
                  <ArrowRight className="w-4 h-4 ml-2 transition-transform group-hover:translate-x-0.5" />
                </>
              )}
            </Button>
          </form>

          {/* Quick Login Demo (Development Only) */}
          {process.env.NODE_ENV === 'development' && (
            <div className="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <div className="text-xs text-blue-600 dark:text-blue-400 font-medium mb-2">
                🔧 Development Mode - Quick Login
              </div>
              <div className="flex gap-2">
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => setFormData(prev => ({
                    ...prev,
                    email: "admin@cybershield.com",
                    password: "SecureAdmin123"
                  }))}
                  className="text-xs"
                >
                  Admin Login
                </Button>
                <Button
                  type="button"
                  size="sm"
                  variant="outline"
                  onClick={() => setFormData(prev => ({
                    ...prev,
                    email: "user@cybershield.com",
                    password: "SecureUser123"
                  }))}
                  className="text-xs"
                >
                  User Login
                </Button>
              </div>
            </div>
          )}

          <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-600">
            <p className="text-center text-sm text-gray-600 dark:text-gray-400">
              Don't have an account?{" "}
              <Link 
                href="/register" 
                className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 font-medium transition-colors"
              >
                Sign up here
              </Link>
            </p>
          </div>

          {/* Security Features */}
          <div className="mt-4 p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg">
            <div className="text-xs text-gray-600 dark:text-gray-400 text-center">
              🔒 Your data is protected with enterprise-grade encryption
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
