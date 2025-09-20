"use client"

import { useState } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardHeader } from "@/components/ui/card"
import { useApi } from "@/hooks/useApi"
import { toast } from "@/hooks/use-toast"
import { Shield, Mail, Lock, User, Eye, EyeOff, Phone } from "lucide-react"

export default function RegisterPage() {
  const [formData, setFormData] = useState({
    firstName: "",
    lastName: "",
    username: "",
    email: "",
    phone: "",
    password: "",
    confirmPassword: "",
    agreeToTerms: false,
  })
  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const { apiCall, loading } = useApi()
  const router = useRouter()

  const [errors, setErrors] = useState<{[key: string]: string}>({})

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setErrors({})

    // Basic validation
    const newErrors: {[key: string]: string} = {}
    
    if (!formData.firstName) {
      newErrors.firstName = "First name is required"
    }
    if (!formData.lastName) {
      newErrors.lastName = "Last name is required"
    }
    if (!formData.username) {
      newErrors.username = "Username is required"
    }
    if (!formData.email) {
      newErrors.email = "Email is required"
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = "Please enter a valid email address"
    }
    if (!formData.password) {
      newErrors.password = "Password is required"
    }
    if (!formData.agreeToTerms) {
      newErrors.agreeToTerms = "You must agree to the Terms of Service and Privacy Policy"
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      const errorFields = document.querySelectorAll('.error-input')
      errorFields.forEach(field => {
        field.classList.add('error-shake')
        setTimeout(() => field.classList.remove('error-shake'), 500)
      })
      toast({
        title: "Missing Information",
        description: "Please fill in all required fields correctly",
        variant: "destructive",
      })
      return
    }

    if (formData.password.length < 6) {
      newErrors.password = "Password must be at least 6 characters long"
    }

    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match"
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      const errorFields = document.querySelectorAll('.error-input')
      errorFields.forEach(field => {
        field.classList.add('error-shake')
        setTimeout(() => field.classList.remove('error-shake'), 500)
      })
      return
    }

    try {
      const response = await apiCall("/api/auth/register", {
        method: "POST",
        body: {
          firstName: formData.firstName,
          lastName: formData.lastName,
          username: formData.username,
          email: formData.email,
          phone: formData.phone || undefined,
          password: formData.password,
          agreeToTerms: formData.agreeToTerms,
        },
        requiresAuth: false,
      })

      if (response?.userId) {
        if (response.isExistingUser) {
          toast({
            title: "Welcome Back!",
            description: "Account found. Proceeding with login verification.",
          })
          router.push(`/verify-otp?userId=${response.userId}&purpose=login`)
        } else {
          toast({
            title: "Registration Successful!",
            description: "Please check your email for the verification code.",
          })
          router.push(`/verify-otp?userId=${response.userId}&purpose=register`)
        }
      }
    } catch (error) {
      console.error("Registration error:", error);
      const errorMessage = error instanceof Error ? error.message : "An error occurred during registration. Please try again."
      
      if (errorMessage.includes("This email is already registered")) {
        toast({
          title: "Account Exists",
          description: "This email is already registered. You can login directly or reset your password if needed.",
          action: (
            <div className="flex gap-2 mt-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => router.push("/login")}
              >
                Login
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => router.push("/forgot-password")}
              >
                Reset Password
              </Button>
            </div>
          ),
        });
      } else if (errorMessage.includes("username is already taken")) {
        toast({
          title: "Username Taken",
          description: "This username is already in use. Please choose a different username.",
          variant: "destructive",
        });
      } else {
        toast({
          title: "Registration Error",
          description: errorMessage,
          variant: "destructive",
        });
      }
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
            Create Account
          </h1>
          <p className="text-gray-600 dark:text-gray-400">
            Join CyberSec Pro and start securing your digital world
          </p>
        </CardHeader>

        <CardContent className="space-y-4">
          <form onSubmit={handleSubmit} className="space-y-4">
            {/* First Name Field */}
            <div className="space-y-2">
              <Label htmlFor="firstName" className="text-sm font-medium">
                First Name *
              </Label>
              <div className="relative">
                <User className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="firstName"
                  name="firstName"
                  type="text"
                  value={formData.firstName}
                  onChange={handleChange}
                  className={`pl-10 ${errors.firstName ? 'error-input' : ''}`}
                  placeholder="Enter your first name"
                  required
                />
                {errors.firstName && (
                  <div className="error-text">{errors.firstName}</div>
                )}
              </div>
            </div>

            {/* Last Name Field */}
            <div className="space-y-2">
              <Label htmlFor="lastName" className="text-sm font-medium">
                Last Name *
              </Label>
              <div className="relative">
                <User className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="lastName"
                  name="lastName"
                  type="text"
                  value={formData.lastName}
                  onChange={handleChange}
                  className={`pl-10 ${errors.lastName ? 'error-input' : ''}`}
                  placeholder="Enter your last name"
                  required
                />
                {errors.lastName && (
                  <div className="error-text">{errors.lastName}</div>
                )}
              </div>
            </div>

            {/* Username Field */}
            <div className="space-y-2">
              <Label htmlFor="username" className="text-sm font-medium">
                Username *
              </Label>
              <div className="relative">
                <User className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="username"
                  name="username"
                  type="text"
                  value={formData.username}
                  onChange={handleChange}
                  className={`pl-10 ${errors.username ? 'error-input' : ''}`}
                  placeholder="Choose a username"
                  required
                />
                {errors.username && (
                  <div className="error-text">{errors.username}</div>
                )}
              </div>
            </div>

            {/* Email Field */}
            <div className="space-y-2">
              <Label htmlFor="email" className="text-sm font-medium">
                Email Address *
              </Label>
              <div className="relative">
                <Mail className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="email"
                  name="email"
                  type="email"
                  value={formData.email}
                  onChange={handleChange}
                  className={`pl-10 ${errors.email ? 'error-input' : ''}`}
                  placeholder="Enter your email"
                  required
                />
                {errors.email && (
                  <div className="error-text">{errors.email}</div>
                )}
              </div>
            </div>

            {/* Phone Field */}
            <div className="space-y-2">
              <Label htmlFor="phone" className="text-sm font-medium">
                Phone Number (Optional)
              </Label>
              <div className="relative">
                <Phone className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="phone"
                  name="phone"
                  type="tel"
                  value={formData.phone}
                  onChange={handleChange}
                  className="pl-10"
                  placeholder="Enter your phone number"
                />
              </div>
            </div>

            {/* Password Field */}
            <div className="space-y-2">
              <Label htmlFor="password" className="text-sm font-medium">
                Password *
              </Label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="password"
                  name="password"
                  type={showPassword ? "text" : "password"}
                  value={formData.password}
                  onChange={handleChange}
                  className={`pl-10 pr-10 ${errors.password ? 'error-input' : ''}`}
                  placeholder="Create a password"
                  required
                />
                {errors.password && (
                  <div className="error-text">{errors.password}</div>
                )}
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Confirm Password Field */}
            <div className="space-y-2">
              <Label htmlFor="confirmPassword" className="text-sm font-medium">
                Confirm Password *
              </Label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="confirmPassword"
                  name="confirmPassword"
                  type={showConfirmPassword ? "text" : "password"}
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  className={`pl-10 pr-10 ${errors.confirmPassword ? 'error-input' : ''}`}
                  placeholder="Confirm your password"
                  required
                />
                {errors.confirmPassword && (
                  <div className="error-text">{errors.confirmPassword}</div>
                )}
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600"
                >
                  {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            {/* Password Requirements */}
            <div className="text-xs text-gray-500 space-y-1">
              <div>Password must be at least 6 characters long</div>
            </div>

            {/* Terms and Conditions */}
            <div className="space-y-2">
              <div className="flex items-center space-x-2">
                <input
                  type="checkbox"
                  id="agreeToTerms"
                  name="agreeToTerms"
                  checked={formData.agreeToTerms}
                  onChange={(e) => setFormData(prev => ({ ...prev, agreeToTerms: e.target.checked }))}
                  className={`h-4 w-4 rounded border-gray-300 text-primary focus:ring-primary ${
                    errors.agreeToTerms ? 'border-red-500 ring-1 ring-red-500' : ''
                  }`}
                  required
                />
                <label htmlFor="agreeToTerms" className="text-sm text-gray-600 dark:text-gray-400">
                  I agree to the Terms of Service and Privacy Policy
                </label>
              </div>
              {errors.agreeToTerms && (
                <div className="text-sm text-red-500 mt-1">{errors.agreeToTerms}</div>
              )}
            </div>

            {/* Submit Button */}
            <Button 
              type="submit" 
              className="w-full bg-blue-600 hover:bg-blue-700" 
              disabled={loading}
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                  Creating account...
                </>
              ) : (
                "Create Account"
              )}
            </Button>
          </form>

          {/* Links */}
          <div className="text-center text-sm text-gray-600 dark:text-gray-400 pt-2">
            Already have an account?{" "}
            <Link 
              href="/login" 
              className="text-blue-600 hover:text-blue-800 dark:text-blue-400 font-medium"
            >
              Sign in
            </Link>
          </div>

          {/* Terms */}
          <div className="text-xs text-gray-500 text-center">
            By creating an account, you agree to our{" "}
            <span className="text-blue-600">Terms of Service</span> and{" "}
            <span className="text-blue-600">Privacy Policy</span>
          </div>

          {/* Development Mode Indicator */}
          {process.env.NODE_ENV === 'development' && (
            <div className="text-center mt-4">
              <div className="text-xs text-green-600 bg-green-50 dark:bg-green-900/20 border border-green-200 dark:border-green-800 p-2 rounded">
                🔧 Development Mode Active
              </div>
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}