'use client'

import { useState } from 'react'
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/src/ui/components/ui/card'
import { Button } from '@/src/ui/components/ui/button'
import { Input } from '@/src/ui/components/ui/input'
import { Label } from '@/src/ui/components/ui/label'
import { Textarea } from '@/src/ui/components/ui/textarea'
import { Badge } from '@/src/ui/components/ui/badge'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/src/ui/components/ui/tabs'
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/src/ui/components/ui/select'
import { useApi } from '@/src/ui/hooks/useApi'
import { useToast } from '@/src/ui/hooks/use-toast'
import { Loader2, Search, Shield, AlertTriangle, CheckCircle, Info, Globe, FileText, Folder } from 'lucide-react'

interface DirectoryBustResult {
  target: string
  wordlist: string
  summary: string
  directories: {
    path: string
    status: number
    size: number
    contentType?: string
    title?: string
    redirect?: string
  }[]
  files: {
    path: string
    status: number
    size: number
    contentType?: string
    title?: string
  }[]
  totalFound: number
  totalRequests: number
  scanTime: number
  timestamp: string
}

export default function DirectoryBusterPage() {
  const [target, setTarget] = useState('')
  const [wordlist, setWordlist] = useState('common')
  const [extensions, setExtensions] = useState('txt,html,php,asp,aspx,js')
  const [results, setResults] = useState<DirectoryBustResult | null>(null)
  const [loading, setLoading] = useState(false)
  
  const { apiCall } = useApi()
  const { toast } = useToast()

  const handleScan = async () => {
    if (!target.trim()) {
      toast({
        title: "Error",
        description: "Please enter a target URL",
        variant: "destructive",
      })
      return
    }

    // Basic URL validation
    if (!target.match(/^https?:\/\/.+/)) {
      toast({
        title: "Error",
        description: "Please enter a valid URL (including http:// or https://)",
        variant: "destructive",
      })
      return
    }

    setLoading(true)
    try {
      const response = await apiCall('/api/tools/directory-buster', {
        method: 'POST',
        body: JSON.stringify({
          target: target.trim(),
          wordlist,
          extensions: extensions.split(',').map(ext => ext.trim()).filter(Boolean)
        })
      })

      if (response?.success) {
        setResults(response.data)
        toast({
          title: "Success",
          description: `Directory bust completed. Found ${response.data.totalFound} items.`
        })
      } else {
        toast({
          title: "Error",
          description: response?.message || "Directory bust failed",
          variant: "destructive",
        })
      }
    } catch (error) {
      console.error('Directory bust error:', error)
      toast({
        title: "Error",
        description: "Failed to perform directory bust",
        variant: "destructive",
      })
    } finally {
      setLoading(false)
    }
  }

  const getStatusColor = (status: number) => {
    if (status >= 200 && status < 300) return 'bg-green-100 text-green-800'
    if (status >= 300 && status < 400) return 'bg-blue-100 text-blue-800'
    if (status >= 400 && status < 500) return 'bg-yellow-100 text-yellow-800'
    if (status >= 500) return 'bg-red-100 text-red-800'
    return 'bg-gray-100 text-gray-800'
  }

  const formatFileSize = (bytes: number) => {
    if (bytes === 0) return '0 B'
    const k = 1024
    const sizes = ['B', 'KB', 'MB', 'GB']
    const i = Math.floor(Math.log(bytes) / Math.log(k))
    return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
  }

  return (
    <div className="container mx-auto px-4 py-8 max-w-6xl">
      {/* Header */}
      <div className="mb-8">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-2 bg-purple-100 dark:bg-purple-900/20 rounded-lg">
            <Search className="w-6 h-6 text-purple-600 dark:text-purple-400" />
          </div>
          <div>
            <h1 className="text-3xl font-bold">Directory Buster</h1>
            <p className="text-muted-foreground">Discover hidden directories and files on web servers</p>
          </div>
        </div>
        
        <div className="flex flex-wrap gap-2">
          <Badge variant="outline" className="text-purple-600">
            <Folder className="w-3 h-3 mr-1" />
            Directory Discovery
          </Badge>
          <Badge variant="outline" className="text-blue-600">
            <FileText className="w-3 h-3 mr-1" />
            File Enumeration
          </Badge>
          <Badge variant="outline" className="text-orange-600">
            <Globe className="w-3 h-3 mr-1" />
            Web Security
          </Badge>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Scan Configuration */}
        <div className="lg:col-span-1">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Shield className="w-5 h-5" />
                Scan Configuration
              </CardTitle>
              <CardDescription>
                Configure your directory busting parameters
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label htmlFor="target">Target URL</Label>
                <Input
                  id="target"
                  placeholder="https://example.com"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className="mt-1"
                />
              </div>

              <div>
                <Label htmlFor="wordlist">Wordlist</Label>
                <Select value={wordlist} onValueChange={setWordlist}>
                  <SelectTrigger className="mt-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="common">Common (1000 entries)</SelectItem>
                    <SelectItem value="medium">Medium (5000 entries)</SelectItem>
                    <SelectItem value="large">Large (20000 entries)</SelectItem>
                    <SelectItem value="web">Web-focused</SelectItem>
                    <SelectItem value="admin">Admin panels</SelectItem>
                    <SelectItem value="backup">Backup files</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div>
                <Label htmlFor="extensions">File Extensions</Label>
                <Input
                  id="extensions"
                  placeholder="txt,html,php,asp,aspx,js"
                  value={extensions}
                  onChange={(e) => setExtensions(e.target.value)}
                  className="mt-1"
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Comma-separated list of extensions to check
                </p>
              </div>

              <Button 
                onClick={handleScan} 
                disabled={loading} 
                className="w-full"
              >
                {loading ? (
                  <>
                    <Loader2 className="w-4 h-4 mr-2 animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Search className="w-4 h-4 mr-2" />
                    Start Directory Bust
                  </>
                )}
              </Button>

              {/* Warning */}
              <div className="p-4 bg-yellow-50 dark:bg-yellow-900/20 rounded-lg">
                <div className="flex items-start gap-2">
                  <AlertTriangle className="w-4 h-4 text-yellow-600 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-yellow-800 dark:text-yellow-200">
                    <p className="font-medium mb-1">Ethical Use Only</p>
                    <p className="text-xs">Only use this tool on systems you own or have explicit permission to test.</p>
                  </div>
                </div>
              </div>

              {/* Information */}
              <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                <div className="flex items-start gap-2">
                  <Info className="w-4 h-4 text-blue-600 mt-0.5 flex-shrink-0" />
                  <div className="text-sm text-blue-800 dark:text-blue-200">
                    <p className="font-medium mb-1">Common Discoveries:</p>
                    <ul className="space-y-1 text-xs">
                      <li>• Admin panels (/admin, /manager)</li>
                      <li>• Backup files (*.bak, *.old)</li>
                      <li>• Config files (config.php, .env)</li>
                      <li>• Hidden directories (/test, /dev)</li>
                    </ul>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Results */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader>
              <CardTitle>Directory Bust Results</CardTitle>
              <CardDescription>
                {results 
                  ? `Scan completed in ${results.scanTime}ms - ${results.totalRequests} requests made` 
                  : 'Results will appear here after scanning'
                }
              </CardDescription>
            </CardHeader>
            <CardContent>
              {loading && (
                <div className="flex items-center justify-center py-12">
                  <div className="text-center">
                    <Loader2 className="w-8 h-8 animate-spin mx-auto mb-4 text-purple-600" />
                    <p className="text-sm text-muted-foreground">Discovering hidden directories and files...</p>
                  </div>
                </div>
              )}

              {results && !loading && (
                <Tabs defaultValue="summary" className="w-full">
                  <TabsList className="grid w-full grid-cols-4">
                    <TabsTrigger value="summary">Summary</TabsTrigger>
                    <TabsTrigger value="directories">Directories ({results.directories.length})</TabsTrigger>
                    <TabsTrigger value="files">Files ({results.files.length})</TabsTrigger>
                    <TabsTrigger value="raw">Raw Data</TabsTrigger>
                  </TabsList>
                  
                  <TabsContent value="summary" className="mt-4">
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                      <div className="p-4 bg-green-50 dark:bg-green-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-green-800 dark:text-green-200">Found Items</p>
                            <p className="text-2xl font-bold text-green-600">{results.totalFound}</p>
                          </div>
                          <CheckCircle className="w-8 h-8 text-green-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-purple-50 dark:bg-purple-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-purple-800 dark:text-purple-200">Directories</p>
                            <p className="text-2xl font-bold text-purple-600">{results.directories.length}</p>
                          </div>
                          <Folder className="w-8 h-8 text-purple-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-blue-800 dark:text-blue-200">Files</p>
                            <p className="text-2xl font-bold text-blue-600">{results.files.length}</p>
                          </div>
                          <FileText className="w-8 h-8 text-blue-600" />
                        </div>
                      </div>
                      <div className="p-4 bg-orange-50 dark:bg-orange-900/20 rounded-lg">
                        <div className="flex items-center justify-between">
                          <div>
                            <p className="text-sm font-medium text-orange-800 dark:text-orange-200">Requests</p>
                            <p className="text-2xl font-bold text-orange-600">{results.totalRequests}</p>
                          </div>
                          <Search className="w-8 h-8 text-orange-600" />
                        </div>
                      </div>
                    </div>

                    <div className="p-4 bg-gray-50 dark:bg-gray-900/20 rounded-lg">
                      <h3 className="font-medium mb-2">Scan Summary</h3>
                      <p className="text-sm text-muted-foreground">{results.summary}</p>
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="directories" className="mt-4">
                    <div className="space-y-3">
                      {results.directories.map((dir, index) => (
                        <div key={index} className="p-4 border rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <Folder className="w-4 h-4 text-purple-600" />
                              <span className="font-mono text-sm">{dir.path}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge className={getStatusColor(dir.status)}>
                                {dir.status}
                              </Badge>
                              <span className="text-xs text-muted-foreground">
                                {formatFileSize(dir.size)}
                              </span>
                            </div>
                          </div>
                          
                          {dir.title && (
                            <p className="text-sm text-muted-foreground mb-1">Title: {dir.title}</p>
                          )}
                          {dir.contentType && (
                            <p className="text-sm text-muted-foreground mb-1">Content-Type: {dir.contentType}</p>
                          )}
                          {dir.redirect && (
                            <p className="text-sm text-muted-foreground">Redirects to: {dir.redirect}</p>
                          )}
                        </div>
                      ))}
                      {results.directories.length === 0 && (
                        <div className="text-center py-8 text-muted-foreground">
                          No directories discovered
                        </div>
                      )}
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="files" className="mt-4">
                    <div className="space-y-3">
                      {results.files.map((file, index) => (
                        <div key={index} className="p-4 border rounded-lg">
                          <div className="flex items-center justify-between mb-2">
                            <div className="flex items-center gap-2">
                              <FileText className="w-4 h-4 text-blue-600" />
                              <span className="font-mono text-sm">{file.path}</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge className={getStatusColor(file.status)}>
                                {file.status}
                              </Badge>
                              <span className="text-xs text-muted-foreground">
                                {formatFileSize(file.size)}
                              </span>
                            </div>
                          </div>
                          
                          {file.title && (
                            <p className="text-sm text-muted-foreground mb-1">Title: {file.title}</p>
                          )}
                          {file.contentType && (
                            <p className="text-sm text-muted-foreground">Content-Type: {file.contentType}</p>
                          )}
                        </div>
                      ))}
                      {results.files.length === 0 && (
                        <div className="text-center py-8 text-muted-foreground">
                          No files discovered
                        </div>
                      )}
                    </div>
                  </TabsContent>
                  
                  <TabsContent value="raw" className="mt-4">
                    <Textarea
                      value={JSON.stringify(results, null, 2)}
                      readOnly
                      className="font-mono text-sm h-96"
                    />
                  </TabsContent>
                </Tabs>
              )}

              {!results && !loading && (
                <div className="text-center py-12">
                  <Search className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
                  <p className="text-muted-foreground">Enter a target URL and start scanning to view results</p>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}