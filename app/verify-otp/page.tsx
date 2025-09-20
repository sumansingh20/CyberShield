"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { Button } from "@/components/ui/button"
import { Input } from "@/components/ui/input"
import { Label } from "@/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { useApi } from "@/hooks/useApi"
import { useAuth } from "@/contexts/AuthContext"
import { toast } from "@/hooks/use-toast"
import { Shield, Mail, Phone, Clock, ArrowLeft, CheckCircle } from "lucide-react"
import Link from "next/link"

export default function VerifyOTPPage() {
  const [formData, setFormData] = useState({
    emailOTP: "",
    phoneOTP: "",
  })
  const [timeLeft, setTimeLeft] = useState(600) // 10 minutes
  const { apiCall, loading } = useApi()
  const { login } = useAuth()
  const router = useRouter()
  const searchParams = useSearchParams()

  const userId = searchParams.get("userId")
  const purpose = searchParams.get("purpose") || "login"

  useEffect(() => {
    if (!userId) {
      router.push("/login")
    }
  }, [userId, router])

  // Countdown timer
  useEffect(() => {
    if (timeLeft > 0) {
      const timer = setTimeout(() => setTimeLeft(timeLeft - 1), 1000)
      return () => clearTimeout(timer)
    }
  }, [timeLeft])

  const formatTime = (seconds: number) => {
    const minutes = Math.floor(seconds / 60)
    const remainingSeconds = seconds % 60
    return `${minutes}:${remainingSeconds.toString().padStart(2, '0')}`
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (!formData.emailOTP || !formData.phoneOTP) {
      toast({
        title: "Missing OTP",
        description: "Please enter both email and phone verification codes.",
        variant: "destructive",
      })
      return
    }

    if (formData.emailOTP.length !== 6 || formData.phoneOTP.length !== 6) {
      toast({
        title: "Invalid OTP Format",
        description: "Verification codes must be 6 digits.",
        variant: "destructive",
      })
      return
    }

    try {
      const response = await apiCall("/api/auth/verify-otp", {
        method: "POST",
        body: {
          userId,
          purpose,
          ...formData,
        },
        requiresAuth: false,
      })

      if (response) {
        toast({
          title: "✅ Verification Successful",
          description: "Your identity has been verified successfully!",
        })

        if (purpose === "login") {
          login(
            {
              accessToken: response.accessToken,
              refreshToken: response.refreshToken,
            },
            response.user,
          )
          router.push("/dashboard")
        } else if (purpose === "registration") {
          toast({
            title: "Account Verified",
            description: "Your account has been verified. Please log in.",
          })
          router.push("/login")
        }
      }
    } catch (error) {
      if (error instanceof Error) {
        const errorMessage = error.message;
        const attemptsMatch = errorMessage.match(/(\d+) attempts? remaining/);
        const attempts = attemptsMatch ? parseInt(attemptsMatch[1], 10) : null;

        if (attempts !== null) {
          toast({
            title: "Invalid Code",
            description: errorMessage,
            variant: "destructive",
          });

          // Visual feedback for wrong input
          const inputs = document.querySelectorAll('input');
          inputs.forEach(input => {
            input.classList.add('border-red-500', 'animate-shake');
            setTimeout(() => {
              input.classList.remove('border-red-500', 'animate-shake');
            }, 500);
          });

          // Clear the inputs
          setFormData({
            emailOTP: "",
            phoneOTP: "",
          });
        } else {
          // Handle other errors (expired, max attempts exceeded, etc.)
          toast({
            title: "Verification Failed",
            description: errorMessage,
            variant: "destructive",
          });
          
          if (errorMessage.includes("Maximum attempts exceeded") || errorMessage.includes("expired")) {
            setTimeout(() => {
              router.push("/login");
            }, 3000);
          }
        }
      }
    }
  }

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target
    // Only allow numbers and limit to 6 digits
    const numericValue = value.replace(/\D/g, '').slice(0, 6)
    setFormData((prev) => ({
      ...prev,
      [name]: numericValue,
    }))
  }

  const handleResendOTP = async () => {
    try {
      toast({
        title: "Resending OTP",
        description: "Please wait while we send new verification codes...",
      })
      
      const response = await apiCall("/api/auth/resend-otp", {
        method: "POST",
        body: {
          userId,
          purpose,
        },
        requiresAuth: false,
      })

      if (response && response.success) {
        setTimeLeft(600) // Reset timer
        
        toast({
          title: "✅ OTP Resent",
          description: "New verification codes have been sent to your email and phone.",
        })
      }
    } catch (error) {
      toast({
        title: "Error",
        description: "Failed to resend OTP. Please try again.",
        variant: "destructive",
      })
    }
  }

  const getPurposeTitle = () => {
    switch (purpose) {
      case "login":
        return "Two-Factor Authentication"
      case "registration":
        return "Account Verification"
      case "forgot-password":
        return "Password Reset Verification"
      default:
        return "OTP Verification"
    }
  }

  const getPurposeDescription = () => {
    switch (purpose) {
      case "login":
        return "Complete your secure login with two-factor authentication"
      case "registration":
        return "Verify your account to complete registration"
      case "forgot-password":
        return "Verify your identity to reset your password"
      default:
        return "Enter the verification codes sent to your email and phone"
    }
  }

  if (!userId) {
    return null
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-indigo-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-6">
        {/* Back Button */}
        <div className="flex items-center space-x-2">
          <Link
            href="/login"
            className="flex items-center text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-gray-100 transition-colors"
          >
            <ArrowLeft className="h-4 w-4 mr-1" />
            Back to login
          </Link>
        </div>

        {/* Main Card */}
        <Card className="border-0 shadow-2xl bg-white/80 dark:bg-slate-800/80 backdrop-blur-sm">
          <CardHeader className="text-center pb-2">
            <div className="flex justify-center mb-4">
              <div className="p-4 rounded-full bg-gradient-to-r from-blue-600 to-indigo-600 text-white shadow-lg">
                <Shield className="h-8 w-8" />
              </div>
            </div>
            <CardTitle className="text-2xl font-bold text-gray-900 dark:text-white">
              {getPurposeTitle()}
            </CardTitle>
            <CardDescription className="text-gray-600 dark:text-gray-400 mt-2">
              {getPurposeDescription()}
            </CardDescription>
          </CardHeader>
          
          <CardContent className="p-6 pt-0">
            {/* Timer */}
            <div className="flex items-center justify-center mb-6 p-3 bg-orange-50 dark:bg-orange-900/20 rounded-lg border border-orange-200 dark:border-orange-800">
              <Clock className="h-4 w-4 text-orange-600 dark:text-orange-400 mr-2" />
              <span className="text-sm font-medium text-orange-700 dark:text-orange-300">
                Code expires in: {formatTime(timeLeft)}
              </span>
            </div>

            <form onSubmit={handleSubmit} className="space-y-6">
              {/* Email OTP */}
              <div className="space-y-2">
                <Label htmlFor="emailOTP" className="text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center">
                  <Mail className="h-4 w-4 mr-2 text-blue-600" />
                  Email Verification Code
                </Label>
                <Input
                  id="emailOTP"
                  name="emailOTP"
                  type="text"
                  required
                  value={formData.emailOTP}
                  onChange={handleChange}
                  placeholder="000000"
                  maxLength={6}
                  className="h-12 text-center text-lg font-mono tracking-widest border-gray-300 dark:border-gray-600 focus:border-blue-500 focus:ring-blue-500"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Check your email inbox for the 6-digit code
                </p>
              </div>

              {/* Phone OTP */}
              <div className="space-y-2">
                <Label htmlFor="phoneOTP" className="text-sm font-medium text-gray-700 dark:text-gray-300 flex items-center">
                  <Phone className="h-4 w-4 mr-2 text-green-600" />
                  SMS Verification Code
                </Label>
                <Input
                  id="phoneOTP"
                  name="phoneOTP"
                  type="text"
                  required
                  value={formData.phoneOTP}
                  onChange={handleChange}
                  placeholder="000000"
                  maxLength={6}
                  className="h-12 text-center text-lg font-mono tracking-widest border-gray-300 dark:border-gray-600 focus:border-blue-500 focus:ring-blue-500"
                />
                <p className="text-xs text-gray-500 dark:text-gray-400">
                  Check your phone for the SMS with 6-digit code
                </p>
              </div>

              {/* Submit Button */}
              <Button 
                type="submit" 
                className="w-full h-12 bg-gradient-to-r from-green-600 to-emerald-600 hover:from-green-700 hover:to-emerald-700 text-white font-semibold rounded-lg shadow-lg hover:shadow-xl transition-all duration-200" 
                disabled={loading || !formData.emailOTP || !formData.phoneOTP}
              >
                {loading ? (
                  <>
                    <div className="w-5 h-5 border-2 border-white border-t-transparent rounded-full animate-spin mr-2"></div>
                    Verifying...
                  </>
                ) : (
                  <>
                    <CheckCircle className="mr-2 h-5 w-5" />
                    Verify Identity
                  </>
                )}
              </Button>
            </form>

            {/* Resend OTP */}
            <div className="mt-6 text-center">
              <p className="text-sm text-gray-600 dark:text-gray-400 mb-3">
                Didn't receive the codes?
              </p>
              <Button
                type="button"
                variant="outline"
                onClick={handleResendOTP}
                disabled={timeLeft > 540} // Allow resend after 1 minute
                className="text-sm"
              >
                {timeLeft > 540 ? `Resend in ${formatTime(600 - timeLeft)}` : "Resend Verification Codes"}
              </Button>
            </div>

            {/* Security Notice */}
            <div className="mt-6 p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg border border-blue-200 dark:border-blue-800">
              <div className="flex items-start space-x-3">
                <Shield className="h-5 w-5 text-blue-600 dark:text-blue-400 mt-0.5 flex-shrink-0" />
                <div>
                  <h4 className="text-sm font-medium text-blue-800 dark:text-blue-200">
                    Security Notice
                  </h4>
                  <p className="text-xs text-blue-700 dark:text-blue-300 mt-1">
                    This two-factor authentication helps protect your account from unauthorized access. 
                    Never share these codes with anyone.
                  </p>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Help Link */}
        <div className="text-center">
          <p className="text-xs text-gray-500 dark:text-gray-400">
            Having trouble? {" "}
            <Link href="/contact" className="text-blue-600 hover:text-blue-500">
              Contact support
            </Link>
          </p>
        </div>
      </div>
    </div>
  )
}
