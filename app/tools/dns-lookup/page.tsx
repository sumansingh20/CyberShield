"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Badge } from "@/src/ui/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Alert, AlertDescription } from "@/src/ui/components/ui/alert"
import { Globe, Search, Copy, CheckCircle, AlertCircle, Loader2 } from "lucide-react"
import Link from "next/link"

interface DNSRecord {
  type: string
  value: string
  ttl?: number
  priority?: number
}

interface DNSResult {
  domain: string
  records: {
    A?: DNSRecord[]
    AAAA?: DNSRecord[]
    MX?: DNSRecord[]
    NS?: DNSRecord[]
    CNAME?: DNSRecord[]
    TXT?: DNSRecord[]
    SOA?: DNSRecord[]
  }
  status: 'success' | 'error'
  message?: string
}

const recordTypes = [
  { type: 'A', description: 'IPv4 Address Records' },
  { type: 'AAAA', description: 'IPv6 Address Records' },
  { type: 'MX', description: 'Mail Exchange Records' },
  { type: 'NS', description: 'Name Server Records' },
  { type: 'CNAME', description: 'Canonical Name Records' },
  { type: 'TXT', description: 'Text Records' },
  { type: 'SOA', description: 'Start of Authority Records' }
]

export default function DNSLookupPage() {
  const [domain, setDomain] = useState('')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<DNSResult | null>(null)
  const [copiedText, setCopiedText] = useState('')

  const performLookup = async () => {
    if (!domain.trim()) return

    setLoading(true)
    setResult(null)

    try {
      const response = await fetch('/api/tools/dns-lookup', {
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
          records: data.data.records,
          status: 'success' as const
        })
      } else {
        setResult({
          domain,
          records: {},
          status: 'error' as const,
          message: data.message || 'DNS lookup failed'
        })
      }
    } catch (error) {
      setResult({
        domain,
        records: {},
        status: 'error' as const,
        message: 'Failed to perform DNS lookup. Please try again.'
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
    // Remove protocol if present
    return input.replace(/^https?:\/\//, '').replace(/\/$/, '')
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-gray-900 dark:to-gray-800">
      <div className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="text-center mb-8">
          <Link 
            href="/tools" 
            className="inline-flex items-center text-blue-600 hover:text-blue-800 transition-colors mb-4"
          >
            ← Back to Tools
          </Link>
          <div className="flex items-center justify-center gap-3 mb-4">
            <Globe className="h-8 w-8 text-blue-600" />
            <h1 className="text-3xl font-bold text-gray-900 dark:text-white">
              DNS Lookup Tool
            </h1>
          </div>
          <p className="text-gray-600 dark:text-gray-300 max-w-2xl mx-auto">
            Perform comprehensive DNS record lookups to analyze domain configurations, 
            mail servers, and network infrastructure.
          </p>
        </div>

        {/* Input Section */}
        <Card className="max-w-2xl mx-auto mb-8">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Search className="h-5 w-5" />
              Domain Lookup
            </CardTitle>
            <CardDescription>
              Enter a domain name to analyze its DNS records
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
                  'Lookup DNS'
                )}
              </Button>
            </div>
            
            <div className="text-sm text-gray-500 dark:text-gray-400">
              <strong>Examples:</strong> google.com, github.com, cloudflare.com
            </div>
          </CardContent>
        </Card>

        {/* Results Section */}
        {result && (
          <div className="max-w-6xl mx-auto">
            {result.status === 'error' ? (
              <Alert className="mb-6">
                <AlertCircle className="h-4 w-4" />
                <AlertDescription>
                  {result.message || 'An error occurred while performing the DNS lookup.'}
                </AlertDescription>
              </Alert>
            ) : (
              <>
                <div className="text-center mb-6">
                  <div className="flex items-center justify-center gap-2 mb-2">
                    <CheckCircle className="h-5 w-5 text-green-500" />
                    <span className="text-lg font-semibold">DNS Lookup Complete</span>
                  </div>
                  <Badge variant="outline" className="text-lg px-4 py-1">
                    {result.domain}
                  </Badge>
                </div>

                <Tabs defaultValue="A" className="w-full">
                  <TabsList className="grid w-full grid-cols-7">
                    {recordTypes.map(({ type }) => (
                      <TabsTrigger key={type} value={type} className="text-sm">
                        {type}
                      </TabsTrigger>
                    ))}
                  </TabsList>

                  {recordTypes.map(({ type, description }) => (
                    <TabsContent key={type} value={type}>
                      <Card>
                        <CardHeader>
                          <CardTitle className="flex items-center justify-between">
                            <span>{type} Records</span>
                            <Badge variant="secondary">
                              {result.records[type as keyof typeof result.records]?.length || 0} found
                            </Badge>
                          </CardTitle>
                          <CardDescription>{description}</CardDescription>
                        </CardHeader>
                        <CardContent>
                          {result.records[type as keyof typeof result.records]?.length ? (
                            <div className="space-y-3">
                              {result.records[type as keyof typeof result.records]?.map((record, index) => (
                                <div 
                                  key={index} 
                                  className="p-4 bg-gray-50 dark:bg-gray-800 rounded-lg border"
                                >
                                  <div className="flex items-center justify-between">
                                    <div className="flex-1">
                                      <div className="font-mono text-sm break-all">
                                        {record.value}
                                      </div>
                                      <div className="flex gap-4 mt-2 text-xs text-gray-500">
                                        {record.ttl && <span>TTL: {record.ttl}s</span>}
                                        {record.priority && <span>Priority: {record.priority}</span>}
                                      </div>
                                    </div>
                                    <Button
                                      variant="ghost"
                                      size="sm"
                                      onClick={() => copyToClipboard(record.value)}
                                      className="ml-2 shrink-0"
                                    >
                                      {copiedText === record.value ? (
                                        <CheckCircle className="h-4 w-4 text-green-500" />
                                      ) : (
                                        <Copy className="h-4 w-4" />
                                      )}
                                    </Button>
                                  </div>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="text-center py-8 text-gray-500 dark:text-gray-400">
                              <AlertCircle className="h-8 w-8 mx-auto mb-2 opacity-50" />
                              <p>No {type} records found for this domain</p>
                            </div>
                          )}
                        </CardContent>
                      </Card>
                    </TabsContent>
                  ))}
                </Tabs>
              </>
            )}
          </div>
        )}

        {/* Info Section */}
        {!result && (
          <div className="max-w-4xl mx-auto grid md:grid-cols-2 gap-6 mt-8">
            <Card>
              <CardHeader>
                <CardTitle className="text-lg">About DNS Lookup</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-gray-600 dark:text-gray-300 space-y-2">
                <p>DNS (Domain Name System) lookup helps you:</p>
                <ul className="list-disc list-inside space-y-1 ml-4">
                  <li>Find IP addresses for domains</li>
                  <li>Discover mail server configurations</li>
                  <li>Identify name servers and DNS setup</li>
                  <li>Analyze domain security records</li>
                </ul>
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-lg">Record Types</CardTitle>
              </CardHeader>
              <CardContent className="text-sm text-gray-600 dark:text-gray-300 space-y-2">
                <div className="space-y-1">
                  <div><strong>A:</strong> IPv4 addresses</div>
                  <div><strong>AAAA:</strong> IPv6 addresses</div>
                  <div><strong>MX:</strong> Mail exchange servers</div>
                  <div><strong>NS:</strong> Authoritative name servers</div>
                  <div><strong>CNAME:</strong> Canonical name aliases</div>
                  <div><strong>TXT:</strong> Text records (SPF, DKIM, etc.)</div>
                  <div><strong>SOA:</strong> Start of authority</div>
                </div>
              </CardContent>
            </Card>
          </div>
        )}
      </div>
    </div>
  )
}
