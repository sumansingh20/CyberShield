"use client"

import type React from "react"
import { useState, useEffect } from "react"
import { useAuth } from "@/src/auth/utils/AuthContext"
import { ThemeToggle } from "@/components/ThemeToggle"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Badge } from "@/src/ui/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Switch } from "@/src/ui/components/ui/switch"
import { Separator } from "@/src/ui/components/ui/separator"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { 
  ArrowLeft, 
  Settings, 
  Shield, 
  Bell, 
  Lock, 
  Save,
  Download,
  AlertTriangle,
  Key,
  Eye,
  EyeOff,
  Smartphone,
  Mail,
  Globe,
  User,
  Activity,
  Trash2
} from "lucide-react"
import Link from "next/link"
import { useApi } from "@/src/ui/hooks/useApi"
import { toast } from "@/src/ui/hooks/use-toast"

export default function SettingsPage() {
  const { user, logout } = useAuth()
  const { apiCall, loading } = useApi()
  
  const [securitySettings, setSecuritySettings] = useState({
    twoFactorEnabled: false,
    emailNotifications: true,
    smsNotifications: false,
    loginAlerts: true,
    sessionTimeout: "30"
  })

  const [passwordData, setPasswordData] = useState({
    currentPassword: "",
    newPassword: "",
    confirmPassword: ""
  })

  const [privacySettings, setPrivacySettings] = useState({
    profileVisibility: "private",
    activityTracking: true,
    dataCollection: true,
    marketingEmails: false
  })

  const [showCurrentPassword, setShowCurrentPassword] = useState(false)
  const [showNewPassword, setShowNewPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)

  useEffect(() => {
    if (user) {
      setSecuritySettings({
        twoFactorEnabled: user.twoFactorEnabled || false,
        emailNotifications: user.emailNotifications !== false,
        smsNotifications: user.smsNotifications || false,
        loginAlerts: user.loginAlerts !== false,
        sessionTimeout: user.sessionTimeout || "30"
      })
    }
  }, [user])

  const handleSecurityUpdate = async () => {
    try {
      const response = await apiCall("/api/auth/security-settings", {
        method: "PUT",
        body: securitySettings
      })

      if (response) {
        toast({
          title: "Security Settings Updated",
          description: "Your security preferences have been saved."
        })
      }
    } catch (error) {
      // Error handled by useApi hook
    }
  }

  const handlePasswordChange = async (e: React.FormEvent) => {
    e.preventDefault()
    
    if (passwordData.newPassword !== passwordData.confirmPassword) {
      toast({
        title: "Password Mismatch",
        description: "New password and confirmation don't match.",
        variant: "destructive"
      })
      return
    }

    if (passwordData.newPassword.length < 8) {
      toast({
        title: "Password Too Short",
        description: "Password must be at least 8 characters long.",
        variant: "destructive"
      })
      return
    }

    try {
      const response = await apiCall("/api/auth/change-password", {
        method: "POST",
        body: {
          currentPassword: passwordData.currentPassword,
          newPassword: passwordData.newPassword
        }
      })

      if (response) {
        toast({
          title: "Password Changed",
          description: "Your password has been updated successfully."
        })
        setPasswordData({
          currentPassword: "",
          newPassword: "",
          confirmPassword: ""
        })
      }
    } catch (error) {
      // Error handled by useApi hook
    }
  }

  const handleAccountDelete = async () => {
    if (window.confirm("Are you sure you want to delete your account? This action cannot be undone.")) {
      try {
        const response = await apiCall("/api/auth/delete-account", {
          method: "DELETE"
        })

        if (response) {
          toast({
            title: "Account Deleted",
            description: "Your account has been permanently deleted."
          })
          logout()
        }
      } catch (error) {
        // Error handled by useApi hook
      }
    }
  }

  const handleSecurityChange = (field: string, value: boolean | string) => {
    setSecuritySettings(prev => ({
      ...prev,
      [field]: value
    }))
  }

  const handlePrivacyChange = (field: string, value: boolean | string) => {
    setPrivacySettings(prev => ({
      ...prev,
      [field]: value
    }))
  }

  const handlePasswordInputChange = (field: string, value: string) => {
    setPasswordData(prev => ({
      ...prev,
      [field]: value
    }))
  }

  const handleExportData = async () => {
    try {
      toast({
        title: "Export Started",
        description: "Your data export has been initiated. You'll receive an email when it's ready.",
      })
    } catch (error) {
      toast({
        title: "Export Failed",
        description: "Failed to start data export. Please try again.",
        variant: "destructive"
      })
    }
  }

  return (
    <div className="min-h-screen gradient-bg">
      {/* Background Effects */}
      <div className="absolute inset-0 bg-cyber-grid opacity-5"></div>
      
      {/* Theme Toggle */}
      <div className="absolute top-4 right-4 z-10">
        <ThemeToggle />
      </div>

      <div className="relative z-10 container mx-auto px-4 py-8">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/dashboard">
            <Button variant="outline" size="sm" className="glass hover:glow-hover bg-transparent">
              <ArrowLeft className="h-4 w-4 mr-2" />
              Dashboard
            </Button>
          </Link>
          <Link href="/profile">
            <Button variant="outline" size="sm" className="glass hover:glow-hover bg-transparent">
              <User className="h-4 w-4 mr-2" />
              Profile
            </Button>
          </Link>
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10 glow">
              <Settings className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold">CyberShield Settings</h1>
              <p className="text-xs text-muted-foreground">Manage your account preferences and security settings</p>
            </div>
          </div>
        </div>

        {/* Settings Content */}
        <div className="max-w-4xl mx-auto">
          <Tabs defaultValue="security" className="space-y-6">
            <TabsList className="grid w-full grid-cols-4 glass">
              <TabsTrigger value="security" className="flex items-center gap-2">
                <Shield className="h-4 w-4" />
                Security
              </TabsTrigger>
              <TabsTrigger value="notifications" className="flex items-center gap-2">
                <Bell className="h-4 w-4" />
                Notifications
              </TabsTrigger>
              <TabsTrigger value="privacy" className="flex items-center gap-2">
                <Eye className="h-4 w-4" />
                Privacy
              </TabsTrigger>
              <TabsTrigger value="account" className="flex items-center gap-2">
                <User className="h-4 w-4" />
                Account
              </TabsTrigger>
            </TabsList>

            {/* Security Tab */}
            <TabsContent value="security" className="space-y-6">
              <Card className="glass-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    Password & Authentication
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  {/* Change Password */}
                  <form onSubmit={handlePasswordChange} className="space-y-4">
                    <h4 className="font-medium">Change Password</h4>
                    
                    <div className="space-y-2">
                      <Label htmlFor="currentPassword">Current Password</Label>
                      <div className="relative">
                        <Input
                          id="currentPassword"
                          type={showCurrentPassword ? "text" : "password"}
                          value={passwordData.currentPassword}
                          onChange={(e) => handlePasswordInputChange("currentPassword", e.target.value)}
                          placeholder="Enter your current password"
                          className="glass focus-ring pr-10"
                          required
                        />
                        <button
                          type="button"
                          onClick={() => setShowCurrentPassword(!showCurrentPassword)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
                        >
                          {showCurrentPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="newPassword">New Password</Label>
                      <div className="relative">
                        <Input
                          id="newPassword"
                          type={showNewPassword ? "text" : "password"}
                          value={passwordData.newPassword}
                          onChange={(e) => handlePasswordInputChange("newPassword", e.target.value)}
                          placeholder="Enter your new password"
                          className="glass focus-ring pr-10"
                          required
                        />
                        <button
                          type="button"
                          onClick={() => setShowNewPassword(!showNewPassword)}
                          className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
                        >
                          {showNewPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                        </button>
                      </div>
                      <p className="text-xs text-muted-foreground">
                        Password must be at least 8 characters long
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="confirmPassword">Confirm New Password</Label>
                      <div className="relative">
                        <Input
                          id="confirmPassword"
                          type={showConfirmPassword ? "text" : "password"}
                          value={passwordData.confirmPassword}
                          onChange={(e) => handlePasswordInputChange("confirmPassword", e.target.value)}
                          placeholder="Confirm your new password"
                          className="glass focus-ring pr-10"
                          required
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

                    <Button type="submit" className="glow-hover" disabled={loading}>
                      {loading ? (
                        <>
                          <div className="spinner w-4 h-4 mr-2"></div>
                          Changing...
                        </>
                      ) : (
                        <>
                          <Lock className="mr-2 h-4 w-4" />
                          Change Password
                        </>
                      )}
                    </Button>
                  </form>

                  <Separator />

                  {/* Two-Factor Authentication */}
                  <div className="flex items-center justify-between p-4 rounded-lg border border-border/50 bg-background/30">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-green-500/10">
                        <Key className="h-4 w-4 text-green-500" />
                      </div>
                      <div>
                        <h4 className="font-medium">Two-Factor Authentication</h4>
                        <p className="text-sm text-muted-foreground">Add an extra layer of security to your account</p>
                      </div>
                    </div>
                    <Switch
                      checked={securitySettings.twoFactorEnabled}
                      onCheckedChange={(checked) => handleSecurityChange("twoFactorEnabled", checked)}
                    />
                  </div>

                  {/* Session Management */}
                  <div>
                    <h4 className="font-medium mb-4">Session Management</h4>
                    <div className="space-y-2">
                      <Label htmlFor="sessionTimeout">Session Timeout</Label>
                      <Select 
                        value={securitySettings.sessionTimeout} 
                        onValueChange={(value) => handleSecurityChange("sessionTimeout", value)}
                      >
                        <SelectTrigger className="glass w-full">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="15">15 minutes</SelectItem>
                          <SelectItem value="30">30 minutes</SelectItem>
                          <SelectItem value="60">1 hour</SelectItem>
                          <SelectItem value="120">2 hours</SelectItem>
                          <SelectItem value="480">8 hours</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>

                  <Button onClick={handleSecurityUpdate} className="glow-hover" disabled={loading}>
                    {loading ? (
                      <>
                        <div className="spinner w-4 h-4 mr-2"></div>
                        Updating...
                      </>
                    ) : (
                      <>
                        <Save className="mr-2 h-4 w-4" />
                        Save Security Settings
                      </>
                    )}
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Notifications Tab */}
            <TabsContent value="notifications" className="space-y-6">
              <Card className="glass-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Bell className="h-5 w-5" />
                    Notification Preferences
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-4">
                    <div className="flex items-center justify-between p-4 rounded-lg border border-border/50 bg-background/30">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-blue-500/10">
                          <Mail className="h-4 w-4 text-blue-500" />
                        </div>
                        <div>
                          <h4 className="font-medium">Email Notifications</h4>
                          <p className="text-sm text-muted-foreground">Receive security alerts and updates via email</p>
                        </div>
                      </div>
                      <Switch
                        checked={securitySettings.emailNotifications}
                        onCheckedChange={(checked) => handleSecurityChange("emailNotifications", checked)}
                      />
                    </div>

                    <div className="flex items-center justify-between p-4 rounded-lg border border-border/50 bg-background/30">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-green-500/10">
                          <Smartphone className="h-4 w-4 text-green-500" />
                        </div>
                        <div>
                          <h4 className="font-medium">SMS Notifications</h4>
                          <p className="text-sm text-muted-foreground">Receive security alerts via SMS</p>
                        </div>
                      </div>
                      <Switch
                        checked={securitySettings.smsNotifications}
                        onCheckedChange={(checked) => handleSecurityChange("smsNotifications", checked)}
                      />
                    </div>

                    <div className="flex items-center justify-between p-4 rounded-lg border border-border/50 bg-background/30">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-yellow-500/10">
                          <Shield className="h-4 w-4 text-yellow-500" />
                        </div>
                        <div>
                          <h4 className="font-medium">Login Alerts</h4>
                          <p className="text-sm text-muted-foreground">Get notified of new login attempts</p>
                        </div>
                      </div>
                      <Switch
                        checked={securitySettings.loginAlerts}
                        onCheckedChange={(checked) => handleSecurityChange("loginAlerts", checked)}
                      />
                    </div>

                    <div className="flex items-center justify-between p-4 rounded-lg border border-border/50 bg-background/30">
                      <div className="flex items-center gap-3">
                        <div className="p-2 rounded-lg bg-purple-500/10">
                          <Globe className="h-4 w-4 text-purple-500" />
                        </div>
                        <div>
                          <h4 className="font-medium">Marketing Emails</h4>
                          <p className="text-sm text-muted-foreground">Receive product updates and newsletters</p>
                        </div>
                      </div>
                      <Switch
                        checked={privacySettings.marketingEmails}
                        onCheckedChange={(checked) => handlePrivacyChange("marketingEmails", checked)}
                      />
                    </div>
                  </div>

                  <Button onClick={handleSecurityUpdate} className="glow-hover" disabled={loading}>
                    <Save className="mr-2 h-4 w-4" />
                    Save Notification Settings
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Privacy Tab */}
            <TabsContent value="privacy" className="space-y-6">
              <Card className="glass-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Eye className="h-5 w-5" />
                    Privacy Settings
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="profileVisibility">Profile Visibility</Label>
                      <Select 
                        value={privacySettings.profileVisibility}
                        onValueChange={(value) => handlePrivacyChange("profileVisibility", value)}
                      >
                        <SelectTrigger className="glass w-full mt-2">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="public">Public - Anyone can see your profile</SelectItem>
                          <SelectItem value="private">Private - Only you can see your profile</SelectItem>
                          <SelectItem value="limited">Limited - Only verified users can see</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>

                    <div className="flex items-center justify-between p-4 rounded-lg border border-border/50 bg-background/30">
                      <div>
                        <h4 className="font-medium">Activity Tracking</h4>
                        <p className="text-sm text-muted-foreground">Allow tracking of your tool usage and activity</p>
                      </div>
                      <Switch
                        checked={privacySettings.activityTracking}
                        onCheckedChange={(checked) => handlePrivacyChange("activityTracking", checked)}
                      />
                    </div>

                    <div className="flex items-center justify-between p-4 rounded-lg border border-border/50 bg-background/30">
                      <div>
                        <h4 className="font-medium">Data Collection</h4>
                        <p className="text-sm text-muted-foreground">Allow collection of usage data for improvement</p>
                      </div>
                      <Switch
                        checked={privacySettings.dataCollection}
                        onCheckedChange={(checked) => handlePrivacyChange("dataCollection", checked)}
                      />
                    </div>
                  </div>

                  <Button className="glow-hover">
                    <Save className="mr-2 h-4 w-4" />
                    Save Privacy Settings
                  </Button>
                </CardContent>
              </Card>
            </TabsContent>

            {/* Account Tab */}
            <TabsContent value="account" className="space-y-6">
              <Card className="glass-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Download className="h-5 w-5" />
                    Data Export
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <p className="text-sm text-muted-foreground">
                    Download a copy of your account data and activity history.
                  </p>
                  <Button onClick={handleExportData} variant="outline" className="glass hover:glow-hover bg-transparent">
                    <Download className="mr-2 h-4 w-4" />
                    Export My Data
                  </Button>
                </CardContent>
              </Card>

              <Card className="glass-card border-red-500/20">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-red-500">
                    <AlertTriangle className="h-5 w-5" />
                    Danger Zone
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-4">
                    <div>
                      <h4 className="font-medium text-red-500">Delete Account</h4>
                      <p className="text-sm text-muted-foreground">
                        Once you delete your account, there is no going back. Please be certain.
                      </p>
                    </div>
                    <Button 
                      variant="destructive" 
                      onClick={handleAccountDelete}
                      className="bg-red-600 hover:bg-red-700"
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
                      Delete Account
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </TabsContent>
          </Tabs>
        </div>

        {/* Footer */}
        <footer className="relative z-10 container mx-auto px-4 py-6 mt-12 border-t border-border/20">
          <div className="text-center">
            <div className="flex items-center justify-center space-x-3 mb-2">
              <Shield className="h-4 w-4 text-primary" />
              <span className="text-sm text-muted-foreground">
                © 2025 CyberShield. Developed by Suman.
              </span>
            </div>
          </div>
        </footer>
      </div>
    </div>
  )
}
