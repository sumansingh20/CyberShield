'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Input } from '@/src/ui/components/ui/input'
import { Label } from '@/src/ui/components/ui/label'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Badge } from '@/src/ui/components/ui/badge'
import { 
  Smartphone, 
  Phone, 
  Mail, 
  Shield, 
  Key, 
  Download,
  Eye,
  EyeOff,
  CheckCircle,
  XCircle,
  Clock,
  Settings
} from 'lucide-react'

interface TwoFactorMethod {
  id: string
  name: string
  description: string
  icon: React.ReactNode
  enabled: boolean
  status: 'active' | 'inactive' | 'pending' | 'setup'
}

export default function EnhancedTwoFactorSetupPage() {
  const [loading, setLoading] = useState(false)
  const [phoneNumber, setPhoneNumber] = useState('')
  const [otpCode, setOtpCode] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [showBackupCodes, setShowBackupCodes] = useState(false)
  const [message, setMessage] = useState('')
  const [messageType, setMessageType] = useState<'success' | 'error' | 'info'>('info')

  const [methods, setMethods] = useState<TwoFactorMethod[]>([
    {
      id: 'totp',
      name: 'Authenticator App',
      description: 'Use Google Authenticator, Authy, or similar apps',
      icon: <Shield className="h-5 w-5" />,
      enabled: false,
      status: 'setup'
    },
    {
      id: 'sms',
      name: 'SMS Messages',
      description: 'Receive codes via text message',
      icon: <Smartphone className="h-5 w-5" />,
      enabled: false,
      status: 'setup'
    },
    {
      id: 'voice',
      name: 'Voice Call',
      description: 'Receive codes via phone call',
      icon: <Phone className="h-5 w-5" />,
      enabled: false,
      status: 'setup'
    },
    {
      id: 'email',
      name: 'Email',
      description: 'Receive codes via email',
      icon: <Mail className="h-5 w-5" />,
      enabled: false,
      status: 'setup'
    },
    {
      id: 'backup',
      name: 'Backup Codes',
      description: 'Single-use codes for account recovery',
      icon: <Key className="h-5 w-5" />,
      enabled: false,
      status: 'setup'
    }
  ])

  const showMessage = (msg: string, type: 'success' | 'error' | 'info') => {
    setMessage(msg)
    setMessageType(type)
    setTimeout(() => setMessage(''), 5000)
  }

  const handleSendSMS = async () => {
    if (!phoneNumber) {
      showMessage('Please enter a phone number', 'error')
      return
    }

    setLoading(true)
    try {
      const response = await fetch('/api/auth/otp/sms', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone: phoneNumber })
      })

      const result = await response.json()
      if (result.success) {
        showMessage('📱 SMS OTP sent successfully! Check your phone.', 'success')
        updateMethodStatus('sms', 'pending')
      } else {
        showMessage(result.message || 'Failed to send SMS', 'error')
      }
    } catch (error) {
      showMessage('Failed to send SMS OTP', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleSendVoice = async () => {
    if (!phoneNumber) {
      showMessage('Please enter a phone number', 'error')
      return
    }

    setLoading(true)
    try {
      const response = await fetch('/api/auth/otp/voice', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ phone: phoneNumber })
      })

      const result = await response.json()
      if (result.success) {
        showMessage('📞 Voice call initiated! Check your phone for the OTP.', 'success')
        updateMethodStatus('voice', 'pending')
      } else {
        showMessage(result.message || 'Failed to initiate voice call', 'error')
      }
    } catch (error) {
      showMessage('Failed to send voice OTP', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleSendEmail = async () => {
    setLoading(true)
    try {
      const response = await fetch('/api/auth/otp/email', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      })

      const result = await response.json()
      if (result.success) {
        showMessage('📧 Email OTP sent successfully! Check your inbox.', 'success')
        updateMethodStatus('email', 'pending')
      } else {
        showMessage(result.message || 'Failed to send email OTP', 'error')
      }
    } catch (error) {
      showMessage('Failed to send email OTP', 'error')
    } finally {
      setLoading(false)
    }
  }

  const handleGenerateBackupCodes = async () => {
    setLoading(true)
    try {
      const token = localStorage.getItem('accessToken')
      const response = await fetch('/api/auth/backup-codes', {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        }
      })

      const result = await response.json()
      if (result.success) {
        setBackupCodes(result.codes)
        setShowBackupCodes(true)
        showMessage('🔑 Backup codes generated successfully!', 'success')
        updateMethodStatus('backup', 'active')
      } else {
        showMessage(result.message || 'Failed to generate backup codes', 'error')
      }
    } catch (error) {
      showMessage('Failed to generate backup codes', 'error')
    } finally {
      setLoading(false)
    }
  }

  const updateMethodStatus = (methodId: string, status: TwoFactorMethod['status']) => {
    setMethods(prev => prev.map(method => 
      method.id === methodId ? { ...method, status, enabled: status === 'active' } : method
    ))
  }

  const getStatusBadge = (status: TwoFactorMethod['status']) => {
    switch (status) {
      case 'active':
        return <Badge className="bg-green-500 hover:bg-green-600"><CheckCircle className="h-3 w-3 mr-1" />Active</Badge>
      case 'inactive':
        return <Badge variant="secondary"><XCircle className="h-3 w-3 mr-1" />Inactive</Badge>
      case 'pending':
        return <Badge variant="outline"><Clock className="h-3 w-3 mr-1" />Pending</Badge>
      default:
        return <Badge variant="outline">Setup Required</Badge>
    }
  }

  const downloadBackupCodes = () => {
    const text = backupCodes.join('\n')
    const blob = new Blob([
      `CyberShield Backup Codes\n\nGenerated: ${new Date().toLocaleString()}\n\n${text}\n\nIMPORTANT:\n- Keep these codes safe!\n- Each code can only be used once\n- Use them if you lose access to your other 2FA methods\n\nCyberShield Security Team`
    ], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'cybershield-backup-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
    showMessage('💾 Backup codes downloaded successfully!', 'success')
  }

  return (
    <div className="container mx-auto px-4 py-8 min-h-screen bg-gradient-to-br from-blue-50 to-purple-50 dark:from-gray-900 dark:to-gray-800">
      <div className="max-w-6xl mx-auto">
        <div className="mb-8 text-center">
          <div className="flex items-center justify-center mb-4">
            <Settings className="h-12 w-12 text-blue-600 mr-3" />
            <Shield className="h-12 w-12 text-green-600" />
          </div>
          <h1 className="text-4xl font-bold bg-gradient-to-r from-blue-600 to-purple-600 bg-clip-text text-transparent">
            Enhanced Two-Factor Authentication
          </h1>
          <p className="text-lg text-muted-foreground mt-2">
            Secure your account with multiple authentication methods
          </p>
          <div className="flex items-center justify-center mt-4 space-x-2">
            <Badge variant="outline" className="text-blue-600">5 Methods Available</Badge>
            <Badge variant="outline" className="text-green-600">Enterprise Grade Security</Badge>
          </div>
        </div>

        {message && (
          <Alert className={`mb-6 border-2 ${
            messageType === 'error' ? 'border-red-300 bg-red-50 text-red-800' : 
            messageType === 'success' ? 'border-green-300 bg-green-50 text-green-800' : 
            'border-blue-300 bg-blue-50 text-blue-800'
          }`}>
            <AlertDescription className="font-medium">{message}</AlertDescription>
          </Alert>
        )}

        <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-3">
          {methods.map((method) => (
            <Card key={method.id} className="relative hover:shadow-lg transition-all duration-200 border-2">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-3">
                    <div className="p-2 rounded-full bg-blue-50 text-blue-600">
                      {method.icon}
                    </div>
                    <div>
                      <CardTitle className="text-lg">{method.name}</CardTitle>
                      <CardDescription className="text-sm">{method.description}</CardDescription>
                    </div>
                  </div>
                  {getStatusBadge(method.status)}
                </div>
              </CardHeader>
              <CardContent>
                {method.id === 'sms' && (
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="phone-sms" className="text-sm font-medium">Phone Number</Label>
                      <Input
                        id="phone-sms"
                        type="tel"
                        placeholder="+91 7903835951"
                        value={phoneNumber}
                        onChange={(e) => setPhoneNumber(e.target.value)}
                        className="mt-1"
                      />
                    </div>
                    <Button 
                      onClick={handleSendSMS} 
                      disabled={loading}
                      className="w-full bg-green-600 hover:bg-green-700"
                    >
                      {loading ? '📱 Sending...' : '📱 Send SMS OTP'}
                    </Button>
                  </div>
                )}

                {method.id === 'voice' && (
                  <div className="space-y-4">
                    <div>
                      <Label htmlFor="phone-voice" className="text-sm font-medium">Phone Number</Label>
                      <Input
                        id="phone-voice"
                        type="tel"
                        placeholder="+91 7903835951"
                        value={phoneNumber}
                        onChange={(e) => setPhoneNumber(e.target.value)}
                        className="mt-1"
                      />
                    </div>
                    <Button 
                      onClick={handleSendVoice} 
                      disabled={loading}
                      className="w-full bg-purple-600 hover:bg-purple-700"
                    >
                      {loading ? '📞 Calling...' : '📞 Call My Phone'}
                    </Button>
                  </div>
                )}

                {method.id === 'email' && (
                  <div className="space-y-4">
                    <div className="p-3 bg-blue-50 rounded-lg border border-blue-200">
                      <p className="text-sm text-blue-800">
                        📧 OTP will be sent to your registered email address
                      </p>
                    </div>
                    <Button 
                      onClick={handleSendEmail} 
                      disabled={loading}
                      className="w-full bg-blue-600 hover:bg-blue-700"
                    >
                      {loading ? '📧 Sending...' : '📧 Send Email OTP'}
                    </Button>
                  </div>
                )}

                {method.id === 'totp' && (
                  <div className="space-y-4">
                    <div className="p-4 border rounded-lg bg-gradient-to-r from-green-50 to-blue-50">
                      <p className="text-sm font-medium text-green-800">
                        📱 Scan QR code with your authenticator app
                      </p>
                      <p className="text-xs text-green-600 mt-2">
                        Google Authenticator, Authy, or Microsoft Authenticator
                      </p>
                    </div>
                    <Button variant="outline" className="w-full border-green-300 hover:bg-green-50">
                      🔐 Setup Authenticator App
                    </Button>
                  </div>
                )}

                {method.id === 'backup' && (
                  <div className="space-y-4">
                    <div className="p-3 bg-yellow-50 rounded-lg border border-yellow-200">
                      <p className="text-sm text-yellow-800">
                        🔑 Generate backup codes for account recovery
                      </p>
                      <p className="text-xs text-yellow-600 mt-1">
                        Use if you lose access to other methods
                      </p>
                    </div>
                    <Button 
                      onClick={handleGenerateBackupCodes} 
                      disabled={loading}
                      className="w-full bg-yellow-600 hover:bg-yellow-700"
                    >
                      {loading ? '🔑 Generating...' : '🔑 Generate Backup Codes'}
                    </Button>
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Status Summary */}
        <Card className="mt-8">
          <CardHeader>
            <CardTitle className="flex items-center">
              <Shield className="h-5 w-5 mr-2 text-green-600" />
              2FA Security Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid md:grid-cols-2 gap-4">
              <div>
                <h4 className="font-medium mb-2">✅ Working Methods:</h4>
                <ul className="space-y-1 text-sm text-green-700">
                  <li>• TOTP (Authenticator Apps)</li>
                  <li>• SMS OTP (+917903835951 verified)</li>
                  <li>• Voice OTP (Custom TwiML)</li>
                  <li>• Backup Codes (Crypto-secure)</li>
                </ul>
              </div>
              <div>
                <h4 className="font-medium mb-2">⚠️ Needs Attention:</h4>
                <ul className="space-y-1 text-sm text-yellow-700">
                  <li>• Email OTP (Gmail App Password issue)</li>
                  <li>• Twilio Verify voice calls (disabled)</li>
                </ul>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Backup Codes Modal */}
        {showBackupCodes && backupCodes.length > 0 && (
          <div className="fixed inset-0 bg-black/50 flex items-center justify-center p-4 z-50">
            <Card className="w-full max-w-md">
              <CardHeader>
                <CardTitle className="flex items-center">
                  <Key className="h-5 w-5 mr-2 text-yellow-600" />
                  Your Backup Codes
                </CardTitle>
                <CardDescription>
                  Save these codes securely. Each can only be used once.
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                  {backupCodes.map((code, index) => (
                    <div key={index} className="p-2 bg-gray-100 rounded text-center border">
                      {code}
                    </div>
                  ))}
                </div>
                <div className="flex space-x-2">
                  <Button onClick={downloadBackupCodes} variant="outline" className="flex-1">
                    <Download className="h-4 w-4 mr-2" />
                    💾 Download
                  </Button>
                  <Button onClick={() => setShowBackupCodes(false)} className="flex-1">
                    ✅ Done
                  </Button>
                </div>
                <Alert className="border-yellow-300 bg-yellow-50">
                  <AlertDescription className="text-xs text-yellow-800">
                    ⚠️ Store these codes in a safe place. They will not be shown again!
                  </AlertDescription>
                </Alert>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  )
}
