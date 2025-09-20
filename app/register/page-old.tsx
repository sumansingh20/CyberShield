"use client"

import type React from "react"

import { useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select"
import { Checkbox } from "@/components/ui/checkbox"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { ThemeToggle } from "@/components/ThemeToggle"
import { useApi } from "@/hooks/useApi"
import { toast } from "@/hooks/use-toast"
import { Shield, User, Mail, Phone, Building, Briefcase, Lock, Eye, EyeOff, CheckCircle } from "lucide-react"
import ReCAPTCHA from "react-google-recaptcha"

export default function RegisterPage() {
  const [formData, setFormData] = useState({
    username: "",
    firstName: "",
    lastName: "",
    email: "",
    phone: "",
    organization: "",
    jobTitle: "",
    experienceLevel: "beginner",
    password: "",
    confirmPassword: "",
    agreeToTerms: false,
  })
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [recaptchaToken, setRecaptchaToken] = useState<string | null>(null)
  const { apiCall, loading } = useApi()
  const router = useRouter()

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (formData.password !== formData.confirmPassword) {
      toast({
        title: "Error",
        description: "Passwords do not match",
        variant: "destructive",
      })
      return
    }

    if (formData.password.length < 8) {
      toast({
        title: "Error",
        description: "Password must be at least 8 characters long",
        variant: "destructive",
      })
      return
    }

    if (!formData.agreeToTerms) {
      toast({
        title: "Error",
        description: "Please agree to the terms and conditions",
        variant: "destructive",
      })
      return
    }

    if (!recaptchaToken && process.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY) {
      toast({
        title: "Error",
        description: "Please complete the reCAPTCHA",
        variant: "destructive",
      })
      return
    }

    try {
      const response = await apiCall("/api/auth/register", {
        method: "POST",
        body: { ...formData, recaptchaToken },
        requiresAuth: false,
      })

      if (response) {
        toast({
          title: "Registration Successful",
          description: "Please check your email and phone for OTP verification.",
        })
        router.push(`/verify-otp?userId=${response.userId}&purpose=registration`)
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

  const handleSelectChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    setFormData((prev) => ({
      ...prev,
      [e.target.name]: e.target.value,
    }))
  }

  return (
    <div className="min-h-screen gradient-bg flex items-center justify-center p-4">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-cyber-grid opacity-5"></div>

      <div className="w-full max-w-2xl relative z-10">
        {/* Header */}
        <div className="text-center mb-8 animate-fade-in">
          <div className="flex justify-center mb-4">
            <div className="p-3 rounded-full bg-primary/10 glow animate-pulse-glow">
              <Shield className="h-8 w-8 text-primary" />
            </div>
          </div>
          <h1 className="text-3xl font-bold mb-2">Join the Security Community</h1>
          <p className="text-muted-foreground">Create your account for the Unified Toolkit for New Pen-Testers</p>
        </div>

        {/* Registration Form */}
        <Card className="glass-card animate-slide-up">
          <CardHeader className="text-center pb-4">
            <CardTitle className="text-2xl">Create Account</CardTitle>
            <CardDescription>Fill in your details to get started with professional security tools</CardDescription>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Personal Information */}
              <div className="space-y-4">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <User className="h-5 w-5 text-primary" />
                  Personal Information
                </h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="firstName" className="flex items-center gap-2">
                      <User className="h-4 w-4" />
                      First Name
                    </Label>
                    <Input
                      id="firstName"
                      name="firstName"
                      type="text"
                      required
                      value={formData.firstName}
                      onChange={handleChange}
                      placeholder="Enter your first name"
                      className="glass focus-ring"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="lastName">Last Name</Label>
                    <Input
                      id="lastName"
                      name="lastName"
                      type="text"
                      required
                      value={formData.lastName}
                      onChange={handleChange}
                      placeholder="Enter your last name"
                      className="glass focus-ring"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="username" className="flex items-center gap-2">
                    <User className="h-4 w-4" />
                    Username
                  </Label>
                  <Input
                    id="username"
                    name="username"
                    type="text"
                    required
                    value={formData.username}
                    onChange={handleChange}
                    placeholder="Choose a unique username"
                    className="glass focus-ring"
                  />
                </div>
              </div>

              {/* Contact Information */}
              <div className="space-y-4">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Mail className="h-5 w-5 text-primary" />
                  Contact Information
                </h3>
                
                <div className="space-y-2">
                  <Label htmlFor="email" className="flex items-center gap-2">
                    <Mail className="h-4 w-4" />
                    Email Address
                  </Label>
                  <Input
                    id="email"
                    name="email"
                    type="email"
                    required
                    value={formData.email}
                    onChange={handleChange}
                    placeholder="Enter your email address"
                    className="glass focus-ring"
                  />
                </div>

                <div className="space-y-2">
                  <Label htmlFor="phone" className="flex items-center gap-2">
                    <Phone className="h-4 w-4" />
                    Phone Number
                  </Label>
                  <Input
                    id="phone"
                    name="phone"
                    type="tel"
                    required
                    value={formData.phone}
                    onChange={handleChange}
                    placeholder="Enter your phone number"
                    className="glass focus-ring"
                  />
                </div>
              </div>

              {/* Professional Information */}
              <div className="space-y-4">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Building className="h-5 w-5 text-primary" />
                  Professional Details
                </h3>
                
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <Label htmlFor="organization" className="flex items-center gap-2">
                      <Building className="h-4 w-4" />
                      Organization
                    </Label>
                    <Input
                      id="organization"
                      name="organization"
                      type="text"
                      value={formData.organization}
                      onChange={handleChange}
                      placeholder="Your company/organization"
                      className="glass focus-ring"
                    />
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="jobTitle" className="flex items-center gap-2">
                      <Briefcase className="h-4 w-4" />
                      Job Title
                    </Label>
                    <Input
                      id="jobTitle"
                      name="jobTitle"
                      type="text"
                      value={formData.jobTitle}
                      onChange={handleChange}
                      placeholder="Your role/position"
                      className="glass focus-ring"
                    />
                  </div>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="experienceLevel">Experience Level</Label>
                  <select
                    id="experienceLevel"
                    name="experienceLevel"
                    value={formData.experienceLevel}
                    onChange={handleSelectChange}
                    title="Select your experience level"
                    className="w-full px-3 py-2 border border-border rounded-md bg-background glass focus-ring"
                  >
                    <option value="beginner">Beginner - New to cybersecurity</option>
                    <option value="intermediate">Intermediate - Some experience</option>
                    <option value="advanced">Advanced - Professional experience</option>
                    <option value="expert">Expert - Senior professional</option>
                  </select>
                </div>
              </div>

              {/* Security */}
              <div className="space-y-4">
                <h3 className="text-lg font-semibold flex items-center gap-2">
                  <Lock className="h-5 w-5 text-primary" />
                  Account Security
                </h3>
                
                <div className="space-y-2">
                  <Label htmlFor="password" className="flex items-center gap-2">
                    <Lock className="h-4 w-4" />
                    Password
                  </Label>
                  <div className="relative">
                    <Input
                      id="password"
                      name="password"
                      type={showPassword ? "text" : "password"}
                      required
                      value={formData.password}
                      onChange={handleChange}
                      placeholder="Create a strong password"
                      minLength={8}
                      className="glass focus-ring pr-10"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                  <p className="text-xs text-muted-foreground">Minimum 8 characters with letters, numbers, and symbols</p>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="confirmPassword">Confirm Password</Label>
                  <div className="relative">
                    <Input
                      id="confirmPassword"
                      name="confirmPassword"
                      type={showConfirmPassword ? "text" : "password"}
                      required
                      value={formData.confirmPassword}
                      onChange={handleChange}
                      placeholder="Confirm your password"
                      className="glass focus-ring pr-10"
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
                    >
                      {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                    </button>
                  </div>
                </div>
              </div>

              {/* Terms and Conditions */}
              <div className="space-y-4">
                <div className="flex items-center space-x-2">
                  <input
                    id="agreeToTerms"
                    name="agreeToTerms"
                    type="checkbox"
                    checked={formData.agreeToTerms}
                    onChange={(e) => setFormData(prev => ({ ...prev, agreeToTerms: e.target.checked }))}
                    title="Agree to Terms and Privacy Policy"
                    className="h-4 w-4 text-primary focus:ring-primary border-border rounded"
                  />
                  <Label htmlFor="agreeToTerms" className="text-sm">
                    I agree to the{" "}
                    <Link href="/terms" className="text-primary hover:underline">
                      Terms of Service
                    </Link>{" "}
                    and{" "}
                    <Link href="/privacy" className="text-primary hover:underline">
                      Privacy Policy
                    </Link>
                  </Label>
                </div>
              </div>

              {/* reCAPTCHA */}
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

              {/* Submit Button */}
              <Button 
                type="submit" 
                className="w-full glow-hover group" 
                disabled={loading} 
                size="lg"
              >
                {loading ? (
                  <>
                    <div className="loading-spinner w-4 h-4 mr-2"></div>
                    Creating Account...
                  </>
                ) : (
                  <>
                    <CheckCircle className="mr-2 h-4 w-4 group-hover:scale-110 transition-transform" />
                    Create Account
                  </>
                )}
              </Button>
            </form>

            <div className="mt-6 text-center">
              <p className="text-sm text-muted-foreground">
                Already have an account?{" "}
                <Link href="/login" className="text-primary hover:underline font-medium">
                  Sign in
                </Link>
              </p>
            </div>
          </CardContent>
        </Card>

        {/* Footer */}
        <footer className="mt-8 text-center">
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
