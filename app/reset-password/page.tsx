"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { useRouter, useSearchParams } from "next/navigation"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { useApi } from "@/src/ui/hooks/useApi"
import { toast } from "@/src/ui/hooks/use-toast"

export default function ResetPasswordPage() {
  const [formData, setFormData] = useState({
    emailOTP: "",
    phoneOTP: "",
    newPassword: "",
    confirmPassword: "",
  })
  const { apiCall, loading } = useApi()
  const router = useRouter()
  const searchParams = useSearchParams()

  const userId = searchParams.get("userId")

  useEffect(() => {
    if (!userId) {
      router.push("/forgot-password")
    }
  }, [userId, router])

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()

    if (formData.newPassword !== formData.confirmPassword) {
      toast({
        title: "Error",
        description: "Passwords do not match",
        variant: "destructive",
      })
      return
    }

    try {
      const response = await apiCall("/api/auth/reset-password", {
        method: "POST",
        body: {
          userId,
          emailOTP: formData.emailOTP,
          phoneOTP: formData.phoneOTP,
          newPassword: formData.newPassword,
        },
        requiresAuth: false,
      })

      if (response) {
        toast({
          title: "Success",
          description: "Password reset successfully!",
        })
        router.push("/login")
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

  return (
    <div className="min-h-screen flex items-center justify-center bg-gradient-to-br from-slate-900 to-slate-800 p-4">
      <Card className="w-full max-w-md">
        <CardHeader className="text-center">
          <CardTitle className="text-2xl font-bold">Reset Password</CardTitle>
          <CardDescription>Enter the OTP codes and your new password</CardDescription>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleSubmit} className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="emailOTP">Email OTP</Label>
              <Input
                id="emailOTP"
                name="emailOTP"
                type="text"
                required
                value={formData.emailOTP}
                onChange={handleChange}
                placeholder="Enter OTP from email"
                maxLength={6}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="phoneOTP">Phone OTP</Label>
              <Input
                id="phoneOTP"
                name="phoneOTP"
                type="text"
                required
                value={formData.phoneOTP}
                onChange={handleChange}
                placeholder="Enter OTP from SMS"
                maxLength={6}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="newPassword">New Password</Label>
              <Input
                id="newPassword"
                name="newPassword"
                type="password"
                required
                value={formData.newPassword}
                onChange={handleChange}
                placeholder="Enter new password"
                minLength={8}
              />
            </div>

            <div className="space-y-2">
              <Label htmlFor="confirmPassword">Confirm Password</Label>
              <Input
                id="confirmPassword"
                name="confirmPassword"
                type="password"
                required
                value={formData.confirmPassword}
                onChange={handleChange}
                placeholder="Confirm new password"
              />
            </div>

            <Button type="submit" className="w-full" disabled={loading}>
              {loading ? "Resetting Password..." : "Reset Password"}
            </Button>
          </form>
        </CardContent>
      </Card>
    </div>
  )
}
