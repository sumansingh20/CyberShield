"use client"

import type React from "react"

import { useState, useEffect } from "react"
import { useAuth } from "@/src/auth/utils/AuthContext"
import { ThemeToggle } from "@/src/ui/components/ThemeToggle"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Card, CardContent, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Badge } from "@/src/ui/components/ui/badge"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Switch } from "@/src/ui/components/ui/switch"
import { Separator } from "@/src/ui/components/ui/separator"
import { Avatar, AvatarFallback, AvatarImage } from "@/src/ui/components/ui/avatar"
import { 
  ArrowLeft, 
  User, 
  Mail, 
  Phone, 
  Shield, 
  Bell, 
  Eye, 
  Lock, 
  Save,
  Camera,
  Activity,
  Calendar,
  MapPin,
  Globe,
  Smartphone,
  Key,
  Download,
  Trash2,
  AlertTriangle,
  Settings
} from "lucide-react"
import Link from "next/link"
import { useApi } from "@/src/ui/hooks/useApi"
import { toast } from "@/src/ui/hooks/use-toast"

export default function ProfilePage() {
  const { user, logout } = useAuth()
  const { apiCall, loading } = useApi()
  
  const [profileData, setProfileData] = useState({
    firstName: "",
    lastName: "",
    email: "",
    phone: "",
    organization: "",
    location: "",
    website: "",
    bio: ""
  })

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

  const [activeTab, setActiveTab] = useState("profile")

  // Fetch complete profile data on mount
  useEffect(() => {
    const fetchProfileData = async () => {
      try {
        const response = await apiCall("/api/auth/profile", {
          method: "GET"
        })

        if (response && response.user) {
          const userData = response.user
          setProfileData({
            firstName: userData.firstName || "",
            lastName: userData.lastName || "",
            email: userData.email || "",
            phone: userData.phone || "",
            organization: userData.organization || "",
            location: userData.location || "",
            website: userData.website || "",
            bio: userData.bio || ""
          })
          
          setSecuritySettings({
            twoFactorEnabled: userData.twoFactorEnabled || false,
            emailNotifications: userData.emailNotifications !== false,
            smsNotifications: userData.smsNotifications || false,
            loginAlerts: userData.loginAlerts !== false,
            sessionTimeout: userData.sessionTimeout || "30"
          })
        }
      } catch (error) {
        console.error("Failed to fetch profile data:", error)
      }
    }

    if (user) {
      fetchProfileData()
    }
  }, [user, apiCall])

  const handleProfileUpdate = async (e: React.FormEvent) => {
    e.preventDefault()
    
    try {
      const response = await apiCall("/api/auth/profile", {
        method: "PUT",
        body: profileData
      })

      if (response) {
        toast({
          title: "Profile Updated",
          description: "Your profile has been updated successfully."
        })
      }
    } catch (error) {
      // Error handled by useApi hook
    }
  }

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

  const handleInputChange = (field: string, value: string) => {
    setProfileData(prev => ({
      ...prev,
      [field]: value
    }))
  }

  const handleSecurityChange = (field: string, value: boolean | string) => {
    setSecuritySettings(prev => ({
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

  const getUserInitials = () => {
    if (profileData.firstName && profileData.lastName) {
      return `${profileData.firstName[0]}${profileData.lastName[0]}`.toUpperCase()
    }
    return profileData.email ? profileData.email[0].toUpperCase() : "U"
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
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-primary/10 glow">
              <User className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-xl font-bold">CyberShield</h1>
              <p className="text-xs text-muted-foreground">Manage your account settings and preferences</p>
            </div>
          </div>
        </div>

        <div className="grid lg:grid-cols-4 gap-8">
          {/* Sidebar Navigation */}
          <div className="lg:col-span-1">
            <Card className="glass-card">
              <CardHeader className="text-center pb-4">
                <div className="flex justify-center mb-4">
                  <div className="relative">
                    <Avatar className="h-20 w-20">
                      <AvatarImage src={user?.avatar} />
                      <AvatarFallback className="text-lg font-semibold bg-primary/10">
                        {getUserInitials()}
                      </AvatarFallback>
                    </Avatar>
                    <Button 
                      size="sm" 
                      variant="outline" 
                      className="absolute -bottom-2 -right-2 rounded-full w-8 h-8 p-0 glass"
                    >
                      <Camera className="h-3 w-3" />
                    </Button>
                  </div>
                </div>
                <CardTitle className="text-lg">
                  {profileData.firstName && profileData.lastName 
                    ? `${profileData.firstName} ${profileData.lastName}`
                    : profileData.email
                  }
                </CardTitle>
                <p className="text-sm text-muted-foreground">{profileData.email}</p>
                <Badge variant="secondary" className="glass mt-2">
                  <Shield className="h-3 w-3 mr-1" />
                  User
                </Badge>
              </CardHeader>
              <CardContent className="space-y-2">
                <Button
                  variant={activeTab === "profile" ? "default" : "ghost"}
                  className="w-full justify-start"
                  onClick={() => setActiveTab("profile")}
                >
                  <User className="mr-2 h-4 w-4" />
                  Profile Info
                </Button>
                <Button
                  variant={activeTab === "security" ? "default" : "ghost"}
                  className="w-full justify-start"
                  onClick={() => setActiveTab("security")}
                >
                  <Shield className="mr-2 h-4 w-4" />
                  Security
                </Button>
                <Button
                  variant={activeTab === "password" ? "default" : "ghost"}
                  className="w-full justify-start"
                  onClick={() => setActiveTab("password")}
                >
                  <Lock className="mr-2 h-4 w-4" />
                  Password
                </Button>
                <Button
                  variant={activeTab === "activity" ? "default" : "ghost"}
                  className="w-full justify-start"
                  onClick={() => setActiveTab("activity")}
                >
                  <Activity className="mr-2 h-4 w-4" />
                  Activity
                </Button>
                <Separator />
                <Link href="/settings">
                  <Button
                    variant="ghost"
                    className="w-full justify-start"
                  >
                    <Settings className="mr-2 h-4 w-4" />
                    Settings
                  </Button>
                </Link>
              </CardContent>
            </Card>
          </div>

          {/* Main Content */}
          <div className="lg:col-span-3">
            {activeTab === "profile" && (
              <Card className="glass-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <User className="h-5 w-5" />
                    Profile Information
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handleProfileUpdate} className="space-y-6">
                    <div className="grid md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="firstName">First Name</Label>
                        <Input
                          id="firstName"
                          value={profileData.firstName}
                          onChange={(e) => handleInputChange("firstName", e.target.value)}
                          placeholder="Enter your first name"
                          className="glass focus-ring"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="lastName">Last Name</Label>
                        <Input
                          id="lastName"
                          value={profileData.lastName}
                          onChange={(e) => handleInputChange("lastName", e.target.value)}
                          placeholder="Enter your last name"
                          className="glass focus-ring"
                        />
                      </div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="email" className="flex items-center gap-2">
                          <Mail className="h-4 w-4" />
                          Email Address
                        </Label>
                        <Input
                          id="email"
                          type="email"
                          value={profileData.email}
                          onChange={(e) => handleInputChange("email", e.target.value)}
                          className="glass focus-ring"
                          disabled
                        />
                        <p className="text-xs text-muted-foreground">Email cannot be changed</p>
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="phone" className="flex items-center gap-2">
                          <Phone className="h-4 w-4" />
                          Phone Number
                        </Label>
                        <Input
                          id="phone"
                          value={profileData.phone}
                          onChange={(e) => handleInputChange("phone", e.target.value)}
                          placeholder="+1 (555) 123-4567"
                          className="glass focus-ring"
                        />
                      </div>
                    </div>

                    <div className="grid md:grid-cols-2 gap-4">
                      <div className="space-y-2">
                        <Label htmlFor="organization">Organization</Label>
                        <Input
                          id="organization"
                          value={profileData.organization}
                          onChange={(e) => handleInputChange("organization", e.target.value)}
                          placeholder="Your company or organization"
                          className="glass focus-ring"
                        />
                      </div>
                      <div className="space-y-2">
                        <Label htmlFor="location" className="flex items-center gap-2">
                          <MapPin className="h-4 w-4" />
                          Location
                        </Label>
                        <Input
                          id="location"
                          value={profileData.location}
                          onChange={(e) => handleInputChange("location", e.target.value)}
                          placeholder="City, Country"
                          className="glass focus-ring"
                        />
                      </div>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="website" className="flex items-center gap-2">
                        <Globe className="h-4 w-4" />
                        Website
                      </Label>
                      <Input
                        id="website"
                        value={profileData.website}
                        onChange={(e) => handleInputChange("website", e.target.value)}
                        placeholder="https://your-website.com"
                        className="glass focus-ring"
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="bio">Bio</Label>
                      <textarea
                        id="bio"
                        value={profileData.bio}
                        onChange={(e) => handleInputChange("bio", e.target.value)}
                        placeholder="Tell us about yourself..."
                        className="w-full min-h-[100px] px-3 py-2 text-sm rounded-md border border-input bg-background/50 backdrop-blur-sm focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2"
                        rows={4}
                      />
                    </div>

                    <Button type="submit" className="glow-hover" disabled={loading}>
                      {loading ? (
                        <>
                          <div className="spinner w-4 h-4 mr-2"></div>
                          Updating...
                        </>
                      ) : (
                        <>
                          <Save className="mr-2 h-4 w-4" />
                          Save Changes
                        </>
                      )}
                    </Button>
                  </form>
                </CardContent>
              </Card>
            )}

            {activeTab === "security" && (
              <Card className="glass-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Shield className="h-5 w-5" />
                    Security Settings
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-6">
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

                  <Separator />

                  {/* Notification Preferences */}
                  <div>
                    <h4 className="font-medium mb-4 flex items-center gap-2">
                      <Bell className="h-4 w-4" />
                      Notification Preferences
                    </h4>
                    <div className="space-y-4">
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-sm">Email Notifications</p>
                          <p className="text-xs text-muted-foreground">Receive security alerts via email</p>
                        </div>
                        <Switch
                          checked={securitySettings.emailNotifications}
                          onCheckedChange={(checked) => handleSecurityChange("emailNotifications", checked)}
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-sm">SMS Notifications</p>
                          <p className="text-xs text-muted-foreground">Receive security alerts via SMS</p>
                        </div>
                        <Switch
                          checked={securitySettings.smsNotifications}
                          onCheckedChange={(checked) => handleSecurityChange("smsNotifications", checked)}
                        />
                      </div>
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-sm">Login Alerts</p>
                          <p className="text-xs text-muted-foreground">Get notified of new login attempts</p>
                        </div>
                        <Switch
                          checked={securitySettings.loginAlerts}
                          onCheckedChange={(checked) => handleSecurityChange("loginAlerts", checked)}
                        />
                      </div>
                    </div>
                  </div>

                  <Separator />

                  {/* Session Management */}
                  <div>
                    <h4 className="font-medium mb-4">Session Management</h4>
                    <div className="space-y-2">
                      <Label htmlFor="sessionTimeout">Session Timeout (minutes)</Label>
                      <Select 
                        value={securitySettings.sessionTimeout} 
                        onValueChange={(value) => handleSecurityChange("sessionTimeout", value)}
                      >
                        <SelectTrigger className="glass">
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
            )}

            {activeTab === "password" && (
              <Card className="glass-card">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    Change Password
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <form onSubmit={handlePasswordChange} className="space-y-4">
                    <div className="space-y-2">
                      <Label htmlFor="currentPassword">Current Password</Label>
                      <Input
                        id="currentPassword"
                        type="password"
                        value={passwordData.currentPassword}
                        onChange={(e) => handlePasswordInputChange("currentPassword", e.target.value)}
                        placeholder="Enter your current password"
                        className="glass focus-ring"
                        required
                      />
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="newPassword">New Password</Label>
                      <Input
                        id="newPassword"
                        type="password"
                        value={passwordData.newPassword}
                        onChange={(e) => handlePasswordInputChange("newPassword", e.target.value)}
                        placeholder="Enter your new password"
                        className="glass focus-ring"
                        required
                      />
                      <p className="text-xs text-muted-foreground">
                        Password must be at least 8 characters long
                      </p>
                    </div>

                    <div className="space-y-2">
                      <Label htmlFor="confirmPassword">Confirm New Password</Label>
                      <Input
                        id="confirmPassword"
                        type="password"
                        value={passwordData.confirmPassword}
                        onChange={(e) => handlePasswordInputChange("confirmPassword", e.target.value)}
                        placeholder="Confirm your new password"
                        className="glass focus-ring"
                        required
                      />
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
                </CardContent>
              </Card>
            )}

            {activeTab === "activity" && (
              <div className="space-y-6">
                <Card className="glass-card">
                  <CardHeader>
                    <CardTitle className="flex items-center gap-2">
                      <Activity className="h-5 w-5" />
                      Recent Activity
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-4">
                      <div className="flex items-center gap-3 p-3 rounded-lg bg-background/30">
                        <div className="p-2 rounded-lg bg-green-500/10">
                          <Shield className="h-4 w-4 text-green-500" />
                        </div>
                        <div className="flex-1">
                          <p className="font-medium text-sm">Successful Login</p>
                          <p className="text-xs text-muted-foreground">Today at 10:30 AM</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 p-3 rounded-lg bg-background/30">
                        <div className="p-2 rounded-lg bg-blue-500/10">
                          <User className="h-4 w-4 text-blue-500" />
                        </div>
                        <div className="flex-1">
                          <p className="font-medium text-sm">Profile Updated</p>
                          <p className="text-xs text-muted-foreground">Yesterday at 3:45 PM</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-3 p-3 rounded-lg bg-background/30">
                        <div className="p-2 rounded-lg bg-purple-500/10">
                          <Globe className="h-4 w-4 text-purple-500" />
                        </div>
                        <div className="flex-1">
                          <p className="font-medium text-sm">Network Scan Completed</p>
                          <p className="text-xs text-muted-foreground">Yesterday at 2:15 PM</p>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>

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
                    <Button variant="outline" className="glass hover:glow-hover bg-transparent">
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
                    <p className="text-sm text-muted-foreground">
                      Once you delete your account, there is no going back. Please be certain.
                    </p>
                    <Button 
                      variant="destructive" 
                      onClick={handleAccountDelete}
                      className="bg-red-600 hover:bg-red-700"
                    >
                      <Trash2 className="mr-2 h-4 w-4" />
                      Delete Account
                    </Button>
                  </CardContent>
                </Card>
              </div>
            )}
          </div>
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
