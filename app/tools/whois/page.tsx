"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Badge } from "@/src/ui/components/ui/badge"
import { Alert, AlertDescription } from "@/src/ui/components/ui/alert"
import { Search, Copy, CheckCircle, AlertCircle, Loader2, Globe, Calendar, User, Building } from "lucide-react"
import Link from "next/link"

interface WhoisResult {
  domain: string
  registrar?: string
  registrationDate?: string
  expirationDate?: string
  lastUpdated?: string
  nameServers?: string[]
  status?: string[]
  registrant?: {
    name?: string
    organization?: string
    country?: string
  }
  raw?: string
  status_code: 'success' | 'error'
  message?: string
}

export default function WhoisLookupPage() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<WhoisResult | null>(null)
  const [copiedText, setCopiedText] = useState('')

  const performLookup = async () => {
    if (!domain.trim()) return

    setLoading(true)
    setResult(null)

    try {
      const response = await fetch('/api/tools/whois', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ domain: domain.trim() })
      })

      const data = await response.json()
      
      if (data.success && data.data) {
        // Convert API response format to expected frontend format
        setResult({
          domain: data.data.domain,
          whoisData: data.data.whoisData,
          status_code: 'success',
          ...data.data
        })
      } else {
        setResult({
          domain,
          status_code: 'error',
          message: data.message || 'WHOIS lookup failed'
        })
      }
    } catch (error) {
      setResult({
        domain,
        status_code: 'error',
        message: 'Failed to perform WHOIS lookup. Please try again.'
      })
    } finally {
      setLoading(false)
    }
  }

  const copyToClipboard = async (text: string) => {
    try {
      await navigator.clipboard.writeText(text)
      setCopiedText(text)
      setTimeout(() => setCopiedText(''), 2000)
    } catch (err) {
      console.error('Failed to copy text: ', err)
    }
  }

  const handleKeyPress = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') {
      performLookup()
    }
  }

  const formatDomainInput = (input: string) => {
    return input.replace(/^https?:\/\//, '').replace(/\/$/, '')
  }

  const formatDate = (dateString?: string) => {
    if (!dateString) return 'Not available'
    try {
      return new Date(dateString).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'long',
        day: 'numeric'
      })
    } catch {
      return dateString
    }
  }

  const getStatusColor = (status?: string[]) => {
    if (!status || status.length === 0) return 'default'
    const statusStr = status.join(' ').toLowerCase()
    if (statusStr.includes('active') || statusStr.includes('ok')) return 'default'
    if (statusStr.includes('pending') || statusStr.includes('hold')) return 'secondary'
    if (statusStr.includes('expired') || statusStr.includes('suspended')) return 'destructive'
    return 'outline'
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-green-50 to-emerald-50 dark:from-gray-900 dark:to-gray-800">
      <div className="container mx-auto px-4 sm:px-6 lg:px-8 py-6 sm:py-8 max-w-6xl">
        {/* Header */}
        <div className="text-center mb-6 sm:mb-8">
          <Link 
            href="/tools" 
            className="inline-flex items-center text-green-600 hover:text-green-800 transition-colors mb-4 text-sm sm:text-base"
          >
            ← Back to Tools
          </Link>
          <div className="flex flex-col sm:flex-row items-center justify-center gap-2 sm:gap-3 mb-4">
            <Search className="h-6 w-6 sm:h-8 sm:w-8 text-green-600" />
            <h1 className="text-2xl sm:text-3xl lg:text-4xl font-bold text-gray-900 dark:text-white text-center">
              WHOIS Lookup Tool
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
            Discover domain registration information, ownership details, and administrative data 
            for any domain name.
          </p>
        </div>

        {/* Input Section */}
        <Card className="max-w-2xl mx-auto mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Globe className="h-5 w-5" />
              Domain Information Lookup
            </CardTitle>
            <CardDescription>
              Enter a domain name to retrieve its registration information
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="flex gap-2">
              <Input
                placeholder="example.com"
                value={domain}
                onChange={(e) => setDomain(formatDomainInput(e.target.value))}
                onKeyPress={handleKeyPress}
                disabled={loading}
                className="flex-1"
              />
              <Button 
                onClick={performLookup} 
                disabled={loading || !domain.trim()}
                className="px-6"
              >
                {loading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin mr-2" />
                    Looking up...
                  </>
                ) : (
                  'Lookup WHOIS'
                )}
              </Button>
            </div>
            
            <div className="text-sm text-gray-500 dark:text-gray-400">
              <strong>Examples:</strong> google.com, github.com, stackoverflow.com
            </div>
          </CardContent>
        </Card>

        {/* Results Section */}
        {result && (
          <div className="max-w-4xl mx-auto">
            {result.status_code === 'error' ? (
              <Alert className="mb-6">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  {result.message || 'An error occurred while performing the WHOIS lookup.'}
                </AlertDescription>
              </Alert>
            ) : (
              <>
                <div className="text-center mb-6">
                  <div className="flex items-center justify-center gap-2 mb-2">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                    <span className="text-lg font-semibold">WHOIS Lookup Complete</span>
                  </div>
                  <Badge variant="outline" className="text-lg px-4 py-1">
                    {result.domain}
                  </Badge>
                </div>

                <div className="grid gap-6 md:grid-cols-2">
                  {/* Registration Information */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <Calendar className="h-5 w-5" />
                        Registration Details
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      {result.registrar && (
                        <div className="flex justify-between items-start">
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-300">Registrar:</span>
                          <div className="text-right">
                            <span className="text-sm font-mono">{result.registrar}</span>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(result.registrar || '')}
                              className="ml-2 h-6 w-6 p-0"
                            >
                              {copiedText === result.registrar ? (
                                <CheckCircle className="h-3 w-3 text-green-500" />
                              ) : (
                                <Copy className="h-3 w-3" />
                              )}
                            </Button>
                          </div>
                        </div>
                      )}

                      {result.registrationDate && (
                        <div className="flex justify-between">
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-300">Created:</span>
                          <span className="text-sm">{formatDate(result.registrationDate)}</span>
                        </div>
                      )}

                      {result.lastUpdated && (
                        <div className="flex justify-between">
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-300">Updated:</span>
                          <span className="text-sm">{formatDate(result.lastUpdated)}</span>
                        </div>
                      )}

                      {result.expirationDate && (
                        <div className="flex justify-between">
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-300">Expires:</span>
                          <span className="text-sm">{formatDate(result.expirationDate)}</span>
                        </div>
                      )}

                      {result.status && result.status.length > 0 && (
                        <div>
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-300 block mb-2">Status:</span>
                          <div className="flex flex-wrap gap-1">
                            {result.status.map((status, index) => (
                              <Badge 
                                key={index} 
                                variant={getStatusColor(result.status)}
                                className="text-xs"
                              >
                                {status}
                              </Badge>
                            ))}
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Registrant Information */}
                  <Card>
                    <CardHeader>
                      <CardTitle className="flex items-center gap-2">
                        <User className="h-5 w-5" />
                        Registrant Information
                      </CardTitle>
                    </CardHeader>
                    <CardContent className="space-y-4">
                      {result.registrant?.name && (
                        <div className="flex justify-between items-start">
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-300">Name:</span>
                          <span className="text-sm text-right">{result.registrant.name}</span>
                        </div>
                      )}

                      {result.registrant?.organization && (
                        <div className="flex justify-between items-start">
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-300">Organization:</span>
                          <span className="text-sm text-right">{result.registrant.organization}</span>
                        </div>
                      )}

                      {result.registrant?.country && (
                        <div className="flex justify-between">
                          <span className="text-sm font-medium text-gray-600 dark:text-gray-300">Country:</span>
                          <span className="text-sm">{result.registrant.country}</span>
                        </div>
                      )}

                      {(!result.registrant || Object.keys(result.registrant).length === 0) && (
                        <div className="text-center py-4 text-gray-500 dark:text-gray-400">
                          <Building className="h-8 w-8 mx-auto mb-2 opacity-50" />
                          <p className="text-sm">Registrant information is private or not available</p>
                        </div>
                      )}
                    </CardContent>
                  </Card>

                  {/* Name Servers */}
                  {result.nameServers && result.nameServers.length > 0 && (
                    <Card className="md:col-span-2">
                      <CardHeader>
                        <CardTitle>Name Servers</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <div className="grid gap-2 md:grid-cols-2">
                          {result.nameServers.map((ns, index) => (
                            <div 
                              key={index}
                              className="p-3 bg-gray-50 dark:bg-gray-800 rounded-lg flex justify-between items-center"
                            >
                              <span className="font-mono text-sm">{ns}</span>
                              <Button
                                variant="ghost"
                                size="sm"
                                onClick={() => copyToClipboard(ns)}
                                className="h-6 w-6 p-0"
                              >
                                {copiedText === ns ? (
                                  <CheckCircle className="h-3 w-3 text-green-500" />
                                ) : (
                                  <Copy className="h-3 w-3" />
                                )}
                              </Button>
                            </div>
                          ))}
                        </div>
                      </CardContent>
                    </Card>
                  )}
                </div>
              </>
            )}
          </div>
        )}

        {/* Info Section */}
        {!result && (
          <div className="max-w-4xl mx-auto grid md:grid-cols-2 gap-6 mt-8">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">About WHOIS</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-gray-600 dark:text-gray-300 space-y-2">
                <p>WHOIS lookups help you discover:</p>
                <ul className="list-disc list-inside space-y-1 ml-4">
                  <li>Domain registration and expiration dates</li>
                  <li>Registrar and registrant information</li>
                  <li>Name server configurations</li>
                  <li>Administrative and technical contacts</li>
                  <li>Domain status and availability</li>
                </ul>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Privacy Notice</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-gray-600 dark:text-gray-300 space-y-2">
                <p>Many domains use privacy protection services that hide:</p>
                <ul className="list-disc list-inside space-y-1 ml-4">
                  <li>Personal contact information</li>
                  <li>Registrant name and address</li>
                  <li>Phone and email details</li>
                </ul>
                <p className="mt-2">This is a standard privacy practice and completely normal.</p>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  )
}
