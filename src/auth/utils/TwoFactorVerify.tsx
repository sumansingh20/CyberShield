'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Input } from '@/src/ui/components/ui/input'
import { Label } from '@/src/ui/components/ui/label'
import { Alert, AlertDescription } from '@/src/ui/components/ui/alert'
import { Shield, ShieldCheck, ShieldX, Smartphone, Key } from 'lucide-react'
import { useRouter } from 'next/navigation'

interface TwoFactorVerifyProps {
  tempToken: string
  userEmail: string
  onSuccess: (token: string, user: any) => void
  onBack: () => void
}

export default function TwoFactorVerify({ 
  tempToken, 
  userEmail, 
  onSuccess, 
  onBack 
}: TwoFactorVerifyProps) {
  const router = useRouter()
  const [verificationCode, setVerificationCode] = useState('')
  const [isBackupCode, setIsBackupCode] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')

  const verify2FA = async () => {
    if (!verificationCode.trim()) {
      setError('Please enter the verification code')
      return
    }

    setLoading(true)
    setError('')
    
    try {
      const response = await fetch('/api/auth/2fa/verify', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ 
          tempToken, 
          code: verificationCode,
          isBackupCode 
        })
      })

      const data = await response.json()

      if (response.ok) {
        // Store the final token
        localStorage.setItem('accessToken', data.token)
        
        // Call success callback
        onSuccess(data.token, data.user)
        
        // Redirect to dashboard
        router.push('/dashboard')
      } else {
        setError(data.error || 'Verification failed')
      }
    } catch (error) {
      setError('Network error occurred')
    } finally {
      setLoading(false)
    }
  }

  const handleCodeChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const value = e.target.value.replace(/[^0-9A-Z]/g, '').toUpperCase()
    setVerificationCode(value)
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter' && verificationCode.trim()) {
      verify2FA()
    }
  }

  return (
    <div className="min-h-screen bg-gray-50 dark:bg-gray-900 flex items-center justify-center py-12 px-4">
      <div className="max-w-md w-full">
        <div className="text-center mb-8">
          <Shield className="mx-auto h-12 w-12 text-blue-600 mb-4" />
          <h1 className="text-2xl font-bold text-gray-900 dark:text-white">
            Two-Factor Authentication
          </h1>
          <p className="text-gray-600 dark:text-gray-400 mt-2">
            Enter the code from your authenticator app
          </p>
        </div>

        {error && (
          <Alert className="mb-6 border-red-200 bg-red-50 text-red-800">
            <ShieldX className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-lg">
              {isBackupCode ? (
                <>
                  <Key className="h-5 w-5" />
                  Backup Code
                </>
              ) : (
                <>
                  <Smartphone className="h-5 w-5" />
                  Authenticator Code
                </>
              )}
            </CardTitle>
            <CardDescription>
              {isBackupCode 
                ? 'Enter one of your backup codes'
                : 'Open your authenticator app and enter the 6-digit code'
              }
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-2">
              <Label htmlFor="verification-code">
                {isBackupCode ? 'Backup Code' : 'Verification Code'}
              </Label>
              <Input
                id="verification-code"
                value={verificationCode}
                onChange={handleCodeChange}
                onKeyPress={handleKeyPress}
                placeholder={isBackupCode ? 'ABCD12' : '123456'}
                maxLength={isBackupCode ? 8 : 6}
                className="text-center text-lg font-mono"
                autoComplete="off"
                autoFocus
              />
            </div>

            <div className="text-sm text-gray-600 dark:text-gray-400 text-center">
              Signing in as: <strong>{userEmail}</strong>
            </div>

            <Button 
              onClick={verify2FA} 
              disabled={loading || !verificationCode.trim()}
              className="w-full"
            >
              {loading ? 'Verifying...' : 'Verify'}
            </Button>

            <div className="text-center space-y-2">
              <button
                type="button"
                onClick={() => setIsBackupCode(!isBackupCode)}
                className="text-sm text-blue-600 hover:text-blue-800 dark:text-blue-400 dark:hover:text-blue-200"
              >
                {isBackupCode 
                  ? 'Use authenticator app instead'
                  : 'Use backup code instead'
                }
              </button>
              
              <div>
                <button
                  type="button"
                  onClick={onBack}
                  className="text-sm text-gray-600 hover:text-gray-800 dark:text-gray-400 dark:hover:text-gray-200"
                >
                  ← Back to login
                </button>
              </div>
            </div>
          </CardContent>
        </Card>

        <div className="mt-6 text-center">
          <Alert className="border-blue-200 bg-blue-50 text-blue-900 dark:bg-blue-900/20 dark:text-blue-100">
            <ShieldCheck className="h-4 w-4" />
            <AlertDescription className="text-sm">
              <strong>Security tip:</strong> Never share your 2FA codes with anyone. 
              CyberShield will never ask for your codes.
            </AlertDescription>
          </Alert>
        </div>
      </div>
    </div>
  )
}
