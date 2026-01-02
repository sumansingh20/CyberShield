
'use client'

import { useState, useEffect } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Input } from '@/src/ui/components/ui/input'
import { Label } from '@/src/ui/components/ui/label'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Badge } from '@/src/ui/components/ui/badge'
import { Shield, ShieldCheck, ShieldX, Copy, Eye, EyeOff, Smartphone, Key } from 'lucide-react'
import { useRouter } from 'next/navigation'
import Image from 'next/image'

interface Setup2FAData {
  secret: string
  qrCode: string
  manualEntryKey: string
  issuer: string
  accountName: string
}

export default function Setup2FA() {
  const router = useRouter()
  const [step, setStep] = useState<'setup' | 'verify' | 'complete' | 'disable'>('setup')
  const [setupData, setSetupData] = useState<Setup2FAData | null>(null)
  const [verificationCode, setVerificationCode] = useState('')
  const [password, setPassword] = useState('')
  const [backupCodes, setBackupCodes] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [success, setSuccess] = useState('')
  const [showSecret, setShowSecret] = useState(false)
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false)

  useEffect(() => {
    // Check current 2FA status
    checkTwoFactorStatus()
  }, [])

  const checkTwoFactorStatus = async () => {
    try {
      const token = localStorage.getItem('accessToken')
      if (!token) {
        router.push('/login')
        return
      }

      // For now, we'll get the user info from the profile API
      const response = await fetch('/api/user/profile', {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      if (response.ok) {
        const userData = await response.json()
        setTwoFactorEnabled(userData.user?.twoFactorEnabled || false)
        if (userData.user?.twoFactorEnabled) {
          setStep('disable')
        }
      }
    } catch (error) {
      console.error('Error checking 2FA status:', error)
    }
  }

  const generateSetup = async () => {
    setLoading(true)
    setError('')
    try {
      const token = localStorage.getItem('accessToken')
      if (!token) {
        router.push('/login')
        return
      }

      const response = await fetch('/api/auth/2fa/setup', {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`
        }
      })

      const data = await response.json()

      if (response.ok) {
        setSetupData(data)
        setStep('verify')
      } else {
        setError(data.error || 'Failed to generate 2FA setup')
      }
    } catch (error) {
      setError('Network error occurred')
    } finally {
      setLoading(false)
    }
  }

  const verifyAndEnable = async () => {
    if (!verificationCode.trim()) {
      setError('Please enter the verification code')
      return
    }

    setLoading(true)
    setError('')
    try {
      const token = localStorage.getItem('accessToken')
      const response = await fetch('/api/auth/2fa/setup', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ code: verificationCode })
      })

      const data = await response.json()

      if (response.ok) {
        setBackupCodes(data.backupCodes)
        setSuccess('2FA enabled successfully!')
        setStep('complete')
        setTwoFactorEnabled(true)
      } else {
        setError(data.error || 'Failed to verify code')
      }
    } catch (error) {
      setError('Network error occurred')
    } finally {
      setLoading(false)
    }
  }

  const disable2FA = async () => {
    if (!password.trim()) {
      setError('Please enter your password')
      return
    }

    setLoading(true)
    setError('')
    try {
      const token = localStorage.getItem('accessToken')
      const response = await fetch('/api/auth/2fa/setup', {
        method: 'DELETE',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`
        },
        body: JSON.stringify({ password })
      })

      const data = await response.json()

      if (response.ok) {
        setSuccess('2FA disabled successfully!')
        setTwoFactorEnabled(false)
        setStep('setup')
        setPassword('')
      } else {
        setError(data.error || 'Failed to disable 2FA')
      }
    } catch (error) {
      setError('Network error occurred')
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setSuccess('Copied to clipboard!')
    setTimeout(() => setSuccess(''), 2000)
  }

  const downloadBackupCodes = () => {
    const content = `CyberShield 2FA Backup Codes\n\nThese codes can be used to access your account if you lose your authenticator device.\nEach code can only be used once.\n\n${backupCodes.join('\n')}\n\nGenerated: ${new Date().toISOString()}`
    
    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'cybershield-backup-codes.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 py-12 px-4">
      <div className="max-w-2xl mx-auto">
        <div className="text-center mb-8">
          <Shield className="mx-auto h-12 w-12 text-blue-600 mb-4" />
          <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
            Two-Factor Authentication
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Add an extra layer of security to your account
          </p>
        </div>

        {error && (
          <Alert className="mb-6 border-red-200 bg-red-50 text-red-800">
            <ShieldX className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {success && (
          <Alert className="mb-6 border-green-200 bg-green-50 text-green-800">
            <ShieldCheck className="h-4 w-4" />
            <AlertDescription>{success}</AlertDescription>
          </Alert>
        )}

        {step === 'setup' && !twoFactorEnabled && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="h-5 w-5" />
                Enable Two-Factor Authentication
              </CardTitle>
              <CardDescription>
                2FA adds an extra layer of security by requiring a code from your phone in addition to your password.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="bg-blue-50 dark:bg-blue-900/20 p-4 rounded-lg">
                <h3 className="font-semibold text-blue-900 dark:text-blue-100 mb-2">
                  What you'll need:
                </h3>
                <ul className="text-sm text-blue-800 dark:text-blue-200 space-y-1">
                  <li>• An authenticator app (Google Authenticator, Authy, etc.)</li>
                  <li>• Your smartphone or tablet</li>
                  <li>• A few minutes to complete setup</li>
                </ul>
              </div>
              <Button 
                onClick={generateSetup} 
                disabled={loading}
                className="w-full"
              >
                {loading ? 'Setting up...' : 'Start Setup'}
              </Button>
            </CardContent>
          </Card>
        )}

        {step === 'verify' && setupData && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Smartphone className="h-5 w-5" />
                Scan QR Code
              </CardTitle>
              <CardDescription>
                Use your authenticator app to scan the QR code below
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-6">
              <div className="flex justify-center">
                <div className="bg-white p-4 rounded-lg">
                  <Image 
                    src={setupData.qrCode} 
                    alt="2FA QR Code" 
                    width={200} 
                    height={200}
                    className="border"
                  />
                </div>
              </div>
              
              <div className="space-y-2">
                <Label htmlFor="manual-key">Manual Entry Key (if you can't scan):</Label>
                <div className="flex items-center gap-2">
                  <Input
                    id="manual-key"
                    value={showSecret ? setupData.manualEntryKey : '••••••••••••••••'}
                    readOnly
                    className="font-mono text-sm"
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowSecret(!showSecret)}
                  >
                    {showSecret ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => copyToClipboard(setupData.manualEntryKey)}
                  >
                    <Copy className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              <div className="space-y-2">
                <Label htmlFor="verification-code">Enter the 6-digit code from your app:</Label>
                <Input
                  id="verification-code"
                  value={verificationCode}
                  onChange={(e) => setVerificationCode(e.target.value)}
                  placeholder="123456"
                  maxLength={6}
                  className="text-center text-lg font-mono"
                />
              </div>

              <div className="flex gap-2">
                <Button 
                  variant="outline" 
                  onClick={() => setStep('setup')}
                  className="flex-1"
                >
                  Back
                </Button>
                <Button 
                  onClick={verifyAndEnable} 
                  disabled={loading || verificationCode.length !== 6}
                  className="flex-1"
                >
                  {loading ? 'Verifying...' : 'Verify & Enable'}
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {step === 'complete' && backupCodes.length > 0 && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldCheck className="h-5 w-5 text-green-600" />
                2FA Enabled Successfully!
              </CardTitle>
              <CardDescription>
                Save these backup codes in a secure place. You can use them to access your account if you lose your authenticator device.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert className="border-yellow-200 bg-yellow-50">
                <Key className="h-4 w-4" />
                <AlertDescription className="text-yellow-900">
                  <strong>Important:</strong> Each backup code can only be used once. Store them securely!
                </AlertDescription>
              </Alert>

              <div className="bg-gray-50 dark:bg-gray-800 p-4 rounded-lg">
                <div className="grid grid-cols-2 gap-2 font-mono text-sm">
                  {backupCodes.map((code, index) => (
                    <Badge key={index} variant="secondary" className="justify-center p-2">
                      {code}
                    </Badge>
                  ))}
                </div>
              </div>

              <div className="flex gap-2">
                <Button onClick={downloadBackupCodes} variant="outline" className="flex-1">
                  Download Codes
                </Button>
                <Button 
                  onClick={() => router.push('/dashboard')} 
                  className="flex-1"
                >
                  Continue to Dashboard
                </Button>
              </div>
            </CardContent>
          </Card>
        )}

        {step === 'disable' && twoFactorEnabled && (
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <ShieldX className="h-5 w-5 text-red-600" />
                Disable Two-Factor Authentication
              </CardTitle>
              <CardDescription>
                This will remove the extra security layer from your account. Enter your password to confirm.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <Alert className="border-red-200 bg-red-50">
                <ShieldX className="h-4 w-4" />
                <AlertDescription className="text-red-900">
                  <strong>Warning:</strong> Disabling 2FA will make your account less secure.
                </AlertDescription>
              </Alert>

              <div className="space-y-2">
                <Label htmlFor="password">Current Password:</Label>
                <Input
                  id="password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="Enter your password"
                />
              </div>

              <div className="flex gap-2">
                <Button 
                  variant="outline" 
                  onClick={() => router.push('/dashboard')}
                  className="flex-1"
                >
                  Cancel
                </Button>
                <Button 
                  variant="destructive"
                  onClick={disable2FA} 
                  disabled={loading || !password.trim()}
                  className="flex-1"
                >
                  {loading ? 'Disabling...' : 'Disable 2FA'}
                </Button>
              </div>
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  )
}
