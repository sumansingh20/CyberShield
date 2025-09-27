"use client"

import { useState, useRef } from "react"
import { useRouter } from "next/navigation"
import Link from "next/link"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Card, CardContent, CardHeader } from "@/src/ui/components/ui/card"
import { useApi } from "@/src/ui/hooks/useApi"
import { toast } from "@/src/ui/hooks/use-toast"
import { Shield, Mail, Lock, User, Eye, EyeOff, Phone, CheckCircle, AlertCircle } from "lucide-react"
import ReCaptcha, { ReCaptchaRef } from "@/components/ReCaptcha"

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
  const [recaptchaToken, setRecaptchaToken] = useState<string | null>(null)
  const recaptchaRef = useRef<ReCaptchaRef>(null)
  const { apiCall, loading } = useApi()
  const router = useRouter()
  const [errors, setErrors] = useState<{[key: string]: string}>({})
  const [passwordStrength, setPasswordStrength] = useState({
    hasMinLength: false,
    hasUppercase: false,
    hasLowercase: false,
    hasNumber: false,
    hasSpecialChar: false
  })

  const validatePassword = (password: string) => {
    setPasswordStrength({
      hasMinLength: password.length >= 8,
      hasUppercase: /[A-Z]/.test(password),
      hasLowercase: /[a-z]/.test(password),
      hasNumber: /\d/.test(password),
      hasSpecialChar: /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?]/.test(password)
    })
  }

  const getPasswordStrengthScore = () => {
    return Object.values(passwordStrength).filter(Boolean).length
  }

  const getPasswordStrengthColor = (score: number) => {
    if (score <= 2) return "bg-red-500"
    if (score <= 3) return "bg-yellow-500"
    if (score <= 4) return "bg-orange-500"
    return "bg-green-500"
  }

  const getPasswordStrengthText = (score: number) => {
    if (score <= 2) return "Weak"
    if (score <= 3) return "Fair"
    if (score <= 4) return "Good"
    return "Strong"
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (loading) return
    
    setErrors({})

    // Enhanced validation
    const newErrors: {[key: string]: string} = {}
    
    if (!formData.firstName.trim()) {
      newErrors.firstName = "First name is required"
    } else if (formData.firstName.trim().length > 50) {
      newErrors.firstName = "First name cannot exceed 50 characters"
    }
    
    if (!formData.lastName.trim()) {
      newErrors.lastName = "Last name is required"
    } else if (formData.lastName.trim().length > 50) {
      newErrors.lastName = "Last name cannot exceed 50 characters"
    }
    
    if (!formData.username.trim()) {
      newErrors.username = "Username is required"
    } else if (formData.username.length < 3) {
      newErrors.username = "Username must be at least 3 characters long"
    } else if (formData.username.length > 30) {
      newErrors.username = "Username cannot exceed 30 characters"
    } else if (!/^[a-zA-Z0-9_-]+$/.test(formData.username)) {
      newErrors.username = "Username can only contain letters, numbers, underscores and hyphens"
    }
    
    if (!formData.email.trim()) {
      newErrors.email = "Email is required"
    } else if (!/\S+@\S+\.\S+/.test(formData.email)) {
      newErrors.email = "Please enter a valid email address"
    }
    
    if (!formData.password) {
      newErrors.password = "Password is required"
    } else if (formData.password.length < 8) {
      newErrors.password = "Password must be at least 8 characters long"
    } else if (!/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)/.test(formData.password)) {
      newErrors.password = "Password must contain at least one uppercase letter, one lowercase letter, and one number"
    }
    
    if (formData.password !== formData.confirmPassword) {
      newErrors.confirmPassword = "Passwords do not match"
    }
    
    if (!formData.agreeToTerms) {
      newErrors.agreeToTerms = "You must agree to the Terms of Service and Privacy Policy"
    }

    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      toast({
        title: "Validation Error",
        description: "Please fix the errors in the form",
        variant: "destructive",
      })
      return
    }

    try {
      const response = await apiCall("/api/auth/register", {
        method: "POST",
        body: {
          firstName: formData.firstName.trim(),
          lastName: formData.lastName.trim(),
          username: formData.username.trim(),
          email: formData.email.toLowerCase().trim(),
          phone: formData.phone.trim() || undefined,
          password: formData.password,
          agreeToTerms: formData.agreeToTerms,
          recaptchaToken: recaptchaToken,
        },
        requiresAuth: false,
      })

      if (response?.success) {
        toast({
          title: "Registration Successful! 🎉",
          description: response.requiresVerification 
            ? "Please check your email to verify your account."
            : "You can now log in to your account.",
        })
        
        if (response.requiresVerification) {
          router.push(`/verify-otp?userId=${response.user.id}&purpose=register`)
        } else {
          router.push("/login")
        }
      }
    } catch (error) {
      console.error("Registration error:", error)
      // Error is already handled by useApi hook
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    setFormData(prev => ({
      ...prev,
      [name]: value
    }))
    
    // Update password strength in real-time
    if (name === 'password') {
      validatePassword(value)
    }
    
    // Clear errors when user starts typing
    if (errors[name]) {
      setErrors(prev => ({
        ...prev,
        [name]: ""
      }))
    }
  }

  const strengthScore = getPasswordStrengthScore()

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-blue-50 via-white to-purple-50 dark:from-gray-900 dark:via-gray-800 dark:to-gray-900 p-2 sm:p-4">
      {/* Background decoration */}
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute -top-40 -right-40 w-60 sm:w-80 h-60 sm:h-80 bg-blue-400/20 rounded-full blur-3xl"></div>
        <div className="absolute -bottom-40 -left-40 w-60 sm:w-80 h-60 sm:h-80 bg-purple-400/20 rounded-full blur-3xl"></div>
      </div>

      <Card className="w-full max-w-sm sm:max-w-md md:max-w-lg relative z-10 shadow-2xl border-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-xl mx-2">
        <CardHeader className="space-y-1 pb-4 sm:pb-6 px-4 sm:px-6">
          <div className="text-center">
            <div className="mx-auto mb-3 sm:mb-4 w-12 sm:w-16 h-12 sm:h-16 bg-gradient-to-br from-blue-600 to-purple-600 rounded-full flex items-center justify-center shadow-lg">
              <Shield className="w-6 sm:w-8 h-6 sm:h-8 text-white" />
            </div>
            <h1 className="text-xl sm:text-2xl md:text-3xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
              Join CyberShield
            </h1>
            <p className="text-xs sm:text-sm text-gray-600 dark:text-gray-300 mt-2">
              Create your professional cybersecurity account
            </p>
          </div>
        </CardHeader>

        <CardContent className="px-4 sm:px-6">
          <form onSubmit={handleSubmit} className="space-y-3 sm:space-y-4">
            {/* Name Fields Row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 sm:gap-4">
              <div className="space-y-2">
                <Label htmlFor="firstName" className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  First Name
                </Label>
                <div className="relative">
                  <User className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                  <Input
                    id="firstName"
                    name="firstName"
                    type="text"
                    value={formData.firstName}
                    onChange={handleChange}
                    className={`pl-10 bg-white/50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 focus:border-blue-500 transition-colors ${
                      errors.firstName ? 'border-red-500 focus:border-red-500' : ''
                    }`}
                    placeholder="First name"
                    required
                  />
                  {errors.firstName && (
                    <div className="text-xs text-red-500 mt-1">{errors.firstName}</div>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="lastName" className="text-sm font-medium text-gray-700 dark:text-gray-300">
                  Last Name
                </Label>
                <div className="relative">
                  <User className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                  <Input
                    id="lastName"
                    name="lastName"
                    type="text"
                    value={formData.lastName}
                    onChange={handleChange}
                    className={`pl-10 bg-white/50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 focus:border-blue-500 transition-colors ${
                      errors.lastName ? 'border-red-500 focus:border-red-500' : ''
                    }`}
                    placeholder="Last name"
                    required
                  />
                  {errors.lastName && (
                    <div className="text-xs text-red-500 mt-1">{errors.lastName}</div>
                  )}
                </div>
              </div>
            </div>

            {/* Username Field */}
            <div className="space-y-2">
              <Label htmlFor="username" className="text-sm font-medium text-gray-700 dark:text-gray-300">
                Username
              </Label>
              <div className="relative">
                <User className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="username"
                  name="username"
                  type="text"
                  value={formData.username}
                  onChange={handleChange}
                  className={`pl-10 bg-white/50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 focus:border-blue-500 transition-colors ${
                    errors.username ? 'border-red-500 focus:border-red-500' : ''
                  }`}
                  placeholder="Choose a unique username"
                  required
                />
                {errors.username && (
                  <div className="text-xs text-red-500 mt-1">{errors.username}</div>
                )}
              </div>
              <div className="text-xs text-gray-500 dark:text-gray-400">
                3-30 characters, letters, numbers, underscores, and hyphens only
              </div>
            </div>

            {/* Email Field */}
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
                  className={`pl-10 bg-white/50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 focus:border-blue-500 transition-colors ${
                    errors.email ? 'border-red-500 focus:border-red-500' : ''
                  }`}
                  placeholder="Enter your email address"
                  required
                />
                {errors.email && (
                  <div className="text-xs text-red-500 mt-1">{errors.email}</div>
                )}
              </div>
            </div>

            {/* Phone Field */}
            <div className="space-y-2">
              <Label htmlFor="phone" className="text-sm font-medium text-gray-700 dark:text-gray-300">
                Phone Number <span className="text-xs text-gray-400">(Optional)</span>
              </Label>
              <div className="relative">
                <Phone className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="phone"
                  name="phone"
                  type="tel"
                  value={formData.phone}
                  onChange={handleChange}
                  className="pl-10 bg-white/50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 focus:border-blue-500 transition-colors"
                  placeholder="Enter your phone number"
                />
              </div>
            </div>

            {/* Password Field */}
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
                  className={`pl-10 pr-10 bg-white/50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 focus:border-blue-500 transition-colors ${
                    errors.password ? 'border-red-500 focus:border-red-500' : ''
                  }`}
                  placeholder="Create a strong password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600 transition-colors"
                >
                  {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              
              {/* Password Strength Indicator */}
              {formData.password && (
                <div className="space-y-2">
                  <div className="flex items-center gap-2">
                    <div className="flex-1 h-2 bg-gray-200 dark:bg-gray-700 rounded-full overflow-hidden">
                      <div 
                        className={`h-full transition-all duration-300 ${getPasswordStrengthColor(strengthScore)} ${
                          strengthScore === 1 ? 'w-1/5' :
                          strengthScore === 2 ? 'w-2/5' :
                          strengthScore === 3 ? 'w-3/5' :
                          strengthScore === 4 ? 'w-4/5' :
                          strengthScore === 5 ? 'w-full' : 'w-0'
                        }`}
                      ></div>
                    </div>
                    <span className="text-xs font-medium text-gray-600 dark:text-gray-400">
                      {getPasswordStrengthText(strengthScore)}
                    </span>
                  </div>
                  
                  <div className="grid grid-cols-2 gap-2 text-xs">
                    <div className={`flex items-center gap-1 ${passwordStrength.hasMinLength ? 'text-green-600' : 'text-gray-400'}`}>
                      {passwordStrength.hasMinLength ? <CheckCircle className="w-3 h-3" /> : <AlertCircle className="w-3 h-3" />}
                      8+ characters
                    </div>
                    <div className={`flex items-center gap-1 ${passwordStrength.hasUppercase ? 'text-green-600' : 'text-gray-400'}`}>
                      {passwordStrength.hasUppercase ? <CheckCircle className="w-3 h-3" /> : <AlertCircle className="w-3 h-3" />}
                      Uppercase letter
                    </div>
                    <div className={`flex items-center gap-1 ${passwordStrength.hasLowercase ? 'text-green-600' : 'text-gray-400'}`}>
                      {passwordStrength.hasLowercase ? <CheckCircle className="w-3 h-3" /> : <AlertCircle className="w-3 h-3" />}
                      Lowercase letter
                    </div>
                    <div className={`flex items-center gap-1 ${passwordStrength.hasNumber ? 'text-green-600' : 'text-gray-400'}`}>
                      {passwordStrength.hasNumber ? <CheckCircle className="w-3 h-3" /> : <AlertCircle className="w-3 h-3" />}
                      Number
                    </div>
                  </div>
                </div>
              )}
              
              {errors.password && (
                <div className="text-xs text-red-500">{errors.password}</div>
              )}
            </div>

            {/* Confirm Password Field */}
            <div className="space-y-2">
              <Label htmlFor="confirmPassword" className="text-sm font-medium text-gray-700 dark:text-gray-300">
                Confirm Password
              </Label>
              <div className="relative">
                <Lock className="absolute left-3 top-3 h-4 w-4 text-gray-400" />
                <Input
                  id="confirmPassword"
                  name="confirmPassword"
                  type={showConfirmPassword ? "text" : "password"}
                  value={formData.confirmPassword}
                  onChange={handleChange}
                  className={`pl-10 pr-10 bg-white/50 dark:bg-gray-700/50 border-gray-200 dark:border-gray-600 focus:border-blue-500 transition-colors ${
                    errors.confirmPassword ? 'border-red-500 focus:border-red-500' : ''
                  }`}
                  placeholder="Confirm your password"
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                  className="absolute right-3 top-3 text-gray-400 hover:text-gray-600 transition-colors"
                >
                  {showConfirmPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
              {errors.confirmPassword && (
                <div className="text-xs text-red-500">{errors.confirmPassword}</div>
              )}
            </div>

            {/* Terms and Conditions */}
            <div className="space-y-2">
              <div className="flex items-start space-x-3">
                <input
                  type="checkbox"
                  id="agreeToTerms"
                  name="agreeToTerms"
                  checked={formData.agreeToTerms}
                  onChange={(e) => setFormData(prev => ({ ...prev, agreeToTerms: e.target.checked }))}
                  className={`mt-1 h-4 w-4 rounded border-gray-300 dark:border-gray-600 text-blue-600 focus:ring-blue-500 ${
                    errors.agreeToTerms ? 'border-red-500' : ''
                  }`}
                  required
                />
                <label htmlFor="agreeToTerms" className="text-sm text-gray-600 dark:text-gray-400">
                  I agree to the{" "}
                  <Link href="/terms" className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 font-medium">
                    Terms of Service
                  </Link>{" "}
                  and{" "}
                  <Link href="/privacy" className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 font-medium">
                    Privacy Policy
                  </Link>
                </label>
              </div>
              {errors.agreeToTerms && (
                <div className="text-xs text-red-500 ml-7">{errors.agreeToTerms}</div>
              )}
            </div>

            {/* reCAPTCHA */}
            <div className="flex justify-center">
              <ReCaptcha
                ref={recaptchaRef}
                onVerify={setRecaptchaToken}
              />
            </div>

            <Button
              type="submit"
              disabled={loading}
              className="w-full h-11 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-medium transition-all duration-200 transform hover:scale-[1.02]"
            >
              {loading ? (
                <>
                  <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin mr-2"></div>
                  Creating Account...
                </>
              ) : (
                "Create Account"
              )}
            </Button>
          </form>

          <div className="mt-6 pt-6 border-t border-gray-200 dark:border-gray-600">
            <p className="text-center text-sm text-gray-600 dark:text-gray-400">
              Already have an account?{" "}
              <Link 
                href="/login" 
                className="text-blue-600 hover:text-blue-700 dark:text-blue-400 dark:hover:text-blue-300 font-medium transition-colors"
              >
                Sign in here
              </Link>
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  )
}
