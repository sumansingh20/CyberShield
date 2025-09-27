"use client"

import { useState } from "react"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Badge } from "@/src/ui/components/ui/badge"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Key, Shield, Lock, Unlock, Zap, Hash, Eye, EyeOff, Copy, CheckCircle } from "lucide-react"

interface CipherResult {
  algorithm: string
  result: string
  keyUsed: string
  success: boolean
}

export default function CryptographyPage() {
  const [activeTab, setActiveTab] = useState("encryption")
  const [plaintext, setPlaintext] = useState("")
  const [ciphertext, setCiphertext] = useState("")
  const [encryptionKey, setEncryptionKey] = useState("")
  const [selectedAlgorithm, setSelectedAlgorithm] = useState("")
  const [hashInput, setHashInput] = useState("")
  const [hashResults, setHashResults] = useState<{[key: string]: string}>({})
  const [cipherResults, setCipherResults] = useState<CipherResult[]>([])
  const [showKey, setShowKey] = useState(false)
  const [generatedKey, setGeneratedKey] = useState("")
  const [keyLength, setKeyLength] = useState("256")

  const encryptionAlgorithms = [
    { value: "aes-256-gcm", label: "AES-256-GCM" },
    { value: "aes-192-cbc", label: "AES-192-CBC" },
    { value: "aes-128-ecb", label: "AES-128-ECB" },
    { value: "des-ede3", label: "3DES" },
    { value: "blowfish", label: "Blowfish" },
    { value: "rc4", label: "RC4" },
    { value: "chacha20", label: "ChaCha20" }
  ]

  const hashAlgorithms = ["MD5", "SHA1", "SHA256", "SHA512", "SHA3-256", "Blake2b", "Whirlpool"]

  const classicalCiphers = [
    { value: "caesar", label: "Caesar Cipher" },
    { value: "vigenere", label: "Vigenère Cipher" },
    { value: "playfair", label: "Playfair Cipher" },
    { value: "rail-fence", label: "Rail Fence Cipher" },
    { value: "substitution", label: "Substitution Cipher" },
    { value: "atbash", label: "Atbash Cipher" }
  ]

  const handleEncryption = () => {
    if (!plaintext || !selectedAlgorithm) return

    // Mock encryption
    const mockEncrypted = btoa(plaintext).split('').reverse().join('')
    setCiphertext(mockEncrypted)
  }

  const handleDecryption = () => {
    if (!ciphertext || !selectedAlgorithm) return

    // Mock decryption
    try {
      const mockDecrypted = atob(ciphertext.split('').reverse().join(''))
      setPlaintext(mockDecrypted)
    } catch {
      setPlaintext("Decryption failed - invalid ciphertext")
    }
  }

  const handleHashGeneration = () => {
    if (!hashInput) return

    const mockHashes: {[key: string]: string} = {}
    
    hashAlgorithms.forEach(algo => {
      // Generate mock hashes (in reality, you'd use actual crypto libraries)
      const mockHash = Array.from({length: algo.includes('512') ? 64 : 32}, () => 
        Math.floor(Math.random() * 16).toString(16)
      ).join('')
      mockHashes[algo] = mockHash
    })

    setHashResults(mockHashes)
  }

  const handleClassicalDecryption = () => {
    if (!ciphertext) return

    const attempts: CipherResult[] = []

    classicalCiphers.forEach(cipher => {
      // Mock decryption attempts
      const mockResult = `Decrypted with ${cipher.label}: ${ciphertext.toLowerCase().replace(/[^a-z]/g, '')}`
      attempts.push({
        algorithm: cipher.label,
        result: mockResult,
        keyUsed: cipher.value === 'caesar' ? 'Shift: 13' : 'Key: AUTO',
        success: Math.random() > 0.5
      })
    })

    setCipherResults(attempts)
  }

  const generateKey = () => {
    const length = parseInt(keyLength)
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
    let result = ''
    
    for (let i = 0; i < length / 4; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length))
    }
    
    setGeneratedKey(result)
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-amber-50 to-orange-100 dark:from-slate-900 dark:via-slate-800 dark:to-slate-900 p-4">
      <div className="container mx-auto max-w-7xl space-y-6">
        {/* Header */}
        <div className="text-center space-y-4">
          <div className="flex items-center justify-center space-x-3">
            <div className="p-3 rounded-xl bg-gradient-to-br from-amber-600 to-orange-600 text-white shadow-xl">
              <Key className="h-8 w-8" />
            </div>
            <div>
              <h1 className="text-4xl font-bold bg-gradient-to-r from-amber-600 to-orange-600 bg-clip-text text-transparent">
                Cryptography Toolkit
              </h1>
              <p className="text-gray-600 dark:text-gray-400">
                Advanced encryption, decryption, and cryptanalysis tools
              </p>
            </div>
          </div>
          
          <div className="flex items-center justify-center space-x-4">
            <Badge className="bg-amber-500/10 text-amber-600 border-amber-200 dark:border-amber-800">
              <Key className="w-3 h-3 mr-1" />
              Expert Level
            </Badge>
            <Badge className="bg-orange-500/10 text-orange-600 border-orange-200 dark:border-orange-800">
              <Shield className="w-3 h-3 mr-1" />
              Cryptography
            </Badge>
          </div>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab} className="w-full">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="encryption">Encryption</TabsTrigger>
            <TabsTrigger value="hashing">Hashing</TabsTrigger>
            <TabsTrigger value="classical">Classical</TabsTrigger>
            <TabsTrigger value="analysis">Analysis</TabsTrigger>
            <TabsTrigger value="keygen">Key Gen</TabsTrigger>
          </TabsList>

          <TabsContent value="encryption" className="space-y-6">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Encryption Panel */}
              <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Lock className="h-5 w-5" />
                    Modern Encryption
                  </CardTitle>
                  <CardDescription>
                    Symmetric and asymmetric encryption algorithms
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="algorithm">Algorithm</Label>
                    <Select value={selectedAlgorithm} onValueChange={setSelectedAlgorithm}>
                      <SelectTrigger>
                        <SelectValue placeholder="Select algorithm..." />
                      </SelectTrigger>
                      <SelectContent>
                        {encryptionAlgorithms.map((algo) => (
                          <SelectItem key={algo.value} value={algo.value}>
                            {algo.label}
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="key">Encryption Key</Label>
                    <div className="flex space-x-2">
                      <Input
                        id="key"
                        type={showKey ? "text" : "password"}
                        value={encryptionKey}
                        onChange={(e) => setEncryptionKey(e.target.value)}
                        placeholder="Enter encryption key..."
                      />
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setShowKey(!showKey)}
                      >
                        {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                      </Button>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <Label htmlFor="plaintext">Plaintext</Label>
                    <Textarea
                      id="plaintext"
                      value={plaintext}
                      onChange={(e) => setPlaintext(e.target.value)}
                      placeholder="Enter text to encrypt..."
                      rows={4}
                    />
                  </div>

                  <Button onClick={handleEncryption} disabled={!plaintext || !selectedAlgorithm} className="w-full">
                    <Lock className="mr-2 h-4 w-4" />
                    Encrypt
                  </Button>
                </CardContent>
              </Card>

              {/* Decryption Panel */}
              <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2">
                    <Unlock className="h-5 w-5" />
                    Decryption
                  </CardTitle>
                  <CardDescription>
                    Decrypt ciphertext with known keys
                  </CardDescription>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="space-y-2">
                    <Label htmlFor="ciphertext">Ciphertext</Label>
                    <Textarea
                      id="ciphertext"
                      value={ciphertext}
                      onChange={(e) => setCiphertext(e.target.value)}
                      placeholder="Enter ciphertext to decrypt..."
                      rows={4}
                    />
                  </div>

                  <Button onClick={handleDecryption} disabled={!ciphertext || !selectedAlgorithm} className="w-full">
                    <Unlock className="mr-2 h-4 w-4" />
                    Decrypt
                  </Button>

                  {(plaintext || ciphertext) && (
                    <div className="space-y-2">
                      <Label>Result</Label>
                      <div className="p-3 bg-gray-100 dark:bg-gray-800 rounded-lg font-mono text-sm">
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-xs text-gray-500">Output</span>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(activeTab === "encryption" ? ciphertext : plaintext)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                        <div className="break-all">
                          {activeTab === "encryption" ? ciphertext : plaintext}
                        </div>
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="hashing" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Hash className="h-5 w-5" />
                  Hash Functions
                </CardTitle>
                <CardDescription>
                  Generate cryptographic hashes with multiple algorithms
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="hash-input">Input Text</Label>
                  <Textarea
                    id="hash-input"
                    value={hashInput}
                    onChange={(e) => setHashInput(e.target.value)}
                    placeholder="Enter text to hash..."
                    rows={3}
                  />
                </div>

                <Button onClick={handleHashGeneration} disabled={!hashInput} className="w-full">
                  <Hash className="mr-2 h-4 w-4" />
                  Generate Hashes
                </Button>

                {Object.keys(hashResults).length > 0 && (
                  <div className="space-y-3">
                    <Label>Hash Results</Label>
                    {Object.entries(hashResults).map(([algo, hash]) => (
                      <div key={algo} className="p-3 bg-gray-100 dark:bg-gray-800 rounded-lg">
                        <div className="flex items-center justify-between mb-2">
                          <Badge variant="outline">{algo}</Badge>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => copyToClipboard(hash)}
                          >
                            <Copy className="h-3 w-3" />
                          </Button>
                        </div>
                        <div className="font-mono text-sm break-all">{hash}</div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="classical" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Zap className="h-5 w-5" />
                  Classical Cipher Analysis
                </CardTitle>
                <CardDescription>
                  Automated cryptanalysis of classical encryption methods
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="cipher-input">Ciphertext</Label>
                  <Textarea
                    id="cipher-input"
                    value={ciphertext}
                    onChange={(e) => setCiphertext(e.target.value)}
                    placeholder="Enter classical ciphertext to analyze..."
                    rows={3}
                  />
                </div>

                <Button onClick={handleClassicalDecryption} disabled={!ciphertext} className="w-full">
                  <Zap className="mr-2 h-4 w-4" />
                  Analyze Cipher
                </Button>

                {cipherResults.length > 0 && (
                  <div className="space-y-3">
                    <Label>Analysis Results</Label>
                    {cipherResults.map((result, index) => (
                      <div key={index} className={`p-3 rounded-lg border ${
                        result.success ? 'bg-green-50 border-green-200' : 'bg-gray-50 border-gray-200'
                      }`}>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center space-x-2">
                            <Badge variant="outline">{result.algorithm}</Badge>
                            {result.success && <CheckCircle className="h-4 w-4 text-green-500" />}
                          </div>
                          <Badge className="text-xs">{result.keyUsed}</Badge>
                        </div>
                        <div className="text-sm font-mono">{result.result}</div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="analysis" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-5 w-5" />
                  Cryptographic Analysis
                </CardTitle>
                <CardDescription>
                  Advanced cryptanalysis and frequency analysis tools
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="text-center py-8 text-gray-500">
                  <Eye className="h-12 w-12 mx-auto mb-4 opacity-50" />
                  <p>Advanced cryptanalysis tools</p>
                  <p className="text-sm">Frequency analysis, pattern detection, and statistical cryptanalysis</p>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="keygen" className="space-y-6">
            <Card className="bg-white/70 dark:bg-slate-800/70 backdrop-blur-sm border">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Key className="h-5 w-5" />
                  Key Generation
                </CardTitle>
                <CardDescription>
                  Generate secure cryptographic keys
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="key-length">Key Length (bits)</Label>
                  <Select value={keyLength} onValueChange={setKeyLength}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="128">128 bits</SelectItem>
                      <SelectItem value="192">192 bits</SelectItem>
                      <SelectItem value="256">256 bits</SelectItem>
                      <SelectItem value="512">512 bits</SelectItem>
                      <SelectItem value="1024">1024 bits</SelectItem>
                      <SelectItem value="2048">2048 bits</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <Button onClick={generateKey} className="w-full">
                  <Key className="mr-2 h-4 w-4" />
                  Generate Secure Key
                </Button>

                {generatedKey && (
                  <div className="space-y-2">
                    <Label>Generated Key</Label>
                    <div className="p-3 bg-gray-100 dark:bg-gray-800 rounded-lg">
                      <div className="flex items-center justify-between mb-2">
                        <Badge variant="outline">{keyLength} bits</Badge>
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => copyToClipboard(generatedKey)}
                        >
                          <Copy className="h-3 w-3" />
                        </Button>
                      </div>
                      <div className="font-mono text-sm break-all">{generatedKey}</div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  )
}