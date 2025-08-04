"use client"

import type React from "react"

import { useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ThemeToggle } from "@/components/ThemeToggle"
import { useApi } from "@/hooks/useApi"
import { useAuth } from "@/contexts/AuthContext"
import { toast } from "@/hooks/use-toast"
import { Shield, Mail, Lock, ArrowRight, User, Info } from "lucide-react"
import ReCAPTCHA from "react-google-recaptcha"

export default function LoginPage() {
  const [formData, setFormData] = useState({
    email: "",
    password: "",
  })
  const [recaptchaToken, setRecaptchaToken] = useState<string | null>(null)
  const { apiCall, loading } = useApi()
  const { login } = useAuth()
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!recaptchaToken && process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY) {
      toast({
        title: "Error",
        description: "Please complete the reCAPTCHA",
        variant: "destructive",
      })
      return
    }

    try {
      const response = await apiCall("/api/auth/login", {
        method: "POST",
        body: { ...formData, recaptchaToken },
        requiresAuth: false,
      })

      if (response) {
        if (response.requiresOTP) {
          toast({
            title: "OTP Sent",
            description: "Please check your email and phone for verification codes.",
          })
          router.push(`/verify-otp?userId=${response.userId}&purpose=login`)
        } else if (response.accessToken && response.user) {
          // Direct login success (development mode)
          login(
            {
              accessToken: response.accessToken,
              refreshToken: response.refreshToken,
            },
            {
              id: response.user._id,
              username: response.user.firstName || response.user.email.split('@')[0],
              email: response.user.email,
              role: "user",
            }
          )
          
          toast({
            title: "Login Successful",
            description: "Welcome back !",
          })
          
          router.push("/dashboard")
        }
      }
    } catch (error) {
      // Error handled by useApi hook
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }))
  }

  const fillDemoCredentials = () => {
    setFormData({
      email: "user@unified.com",
      password: "user123",
    })
  }

  return (
    <div className="min-h-screen gradient-bg flex items-center justify-center p-4">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-cyber-grid opacity-5"></div>

      {/* Theme Toggle */}
      <div className="absolute top-4 right-4 z-10">
        <ThemeToggle />
      </div>

      <div className="w-full max-w-md relative z-10">
        {/* Header */}
        <div className="text-center mb-8 animate-fade-in">
          <div className="flex justify-center mb-4">
            <div className="p-3 rounded-full bg-primary/10 glow animate-pulse-glow">
              <Shield className="h-8 w-8 text-primary" />
            </div>
          </div>
          <h1 className="text-2xl font-bold mb-2">Welcome Back</h1>
          <p className="text-muted-foreground">Sign in to your Unified Toolkit for New Pen-Testers account</p>
        </div>

        {/* Demo Account Info */}
        <Card className="glass-card animate-slide-up mb-6 border-primary/20">
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-primary">
              <Info className="h-4 w-4" />
              Demo Account Available
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              <p className="text-sm text-muted-foreground">
                Try the platform with our demo account - no registration required!
              </p>
              <div className="bg-primary/5 border border-primary/20 rounded-lg p-3">
                <div className="grid grid-cols-2 gap-3 text-sm">
                  <div>
                    <p className="text-muted-foreground">Email:</p>
                    <p className="font-mono text-primary">user@unified.com</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Password:</p>
                    <p className="font-mono text-primary">user123</p>
                  </div>
                </div>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={fillDemoCredentials}
                className="w-full glass hover:glow-hover bg-transparent"
              >
                <User className="mr-2 h-4 w-4" />
                Use Demo Account
              </Button>
            </div>
          </CardContent>
        </Card>

        {/* Login Form */}
        <Card className="glass-card animate-slide-up">
          <CardHeader className="text-center pb-4">
            <CardTitle className="text-xl">Sign In</CardTitle>
            <CardDescription>Enter your credentials to access your account</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-4">
              <div className="space-y-2">
                <Label htmlFor="email" className="flex items-center gap-2">
                  <Mail className="h-4 w-4" />
                  Email
                </Label>
                <Input
                  id="email"
                  name="email"
                  type="email"
                  required
                  value={formData.email}
                  onChange={handleChange}
                  placeholder="Enter your email"
                  className="glass focus-ring"
                />
              </div>

              <div className="space-y-2">
                <Label htmlFor="password" className="flex items-center gap-2">
                  <Lock className="h-4 w-4" />
                  Password
                </Label>
                <Input
                  id="password"
                  name="password"
                  type="password"
                  required
                  value={formData.password}
                  onChange={handleChange}
                  placeholder="Enter your password"
                  className="glass focus-ring"
                />
              </div>

              <div className="flex justify-center py-2">
                {process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY ? (
                  <ReCAPTCHA
                    sitekey={process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY}
                    onChange={setRecaptchaToken}
                    theme="dark"
                    onError={() => {
                      console.error('reCAPTCHA error occurred')
                      setRecaptchaToken(null)
                    }}
                  />
                ) : (
                  <div className="text-sm text-muted-foreground bg-muted p-3 rounded">
                    reCAPTCHA not configured - continuing without verification
                  </div>
                )}
              </div>

              <Button type="submit" className="w-full glow-hover group" disabled={loading} size="lg">
                {loading ? (
                  <>
                    <div className="spinner w-4 h-4 mr-2"></div>
                    Signing In...
                  </>
                ) : (
                  <>
                    Sign In
                    <ArrowRight className="ml-2 h-4 w-4 group-hover:translate-x-1 transition-transform" />
                  </>
                )}
              </Button>
            </form>

            <div className="mt-6 space-y-4 text-center">
              <Link href="/forgot-password" className="text-sm text-primary hover:underline block transition-colors">
                Forgot your password?
              </Link>
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <span className="w-full border-t border-border/50" />
                </div>
                <div className="relative flex justify-center text-xs uppercase">
                  <span className="bg-background px-2 text-muted-foreground">Or</span>
                </div>
              </div>
              <p className="text-sm text-muted-foreground">
                Don't have an account?{" "}
                <Link href="/register" className="text-primary hover:underline font-medium">
                  Sign up
                </Link>
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Footer */}
        <div className="text-center mt-8 text-xs text-muted-foreground">
          <p>Secured with enterprise-grade authentication</p>
        </div>

        {/* Footer */}
        <footer className="mt-12 text-center">
          <div className="flex items-center justify-center space-x-3">
            <Shield className="h-4 w-4 text-primary" />
            <span className="text-xs text-muted-foreground">
              © 2025 Unified Toolkit for New Pen-Testers. Developed by Suman.
            </span>
          </div>
        </footer>
      </div>
    </div>
  )
}
