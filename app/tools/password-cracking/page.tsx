"use client"

import React, { useState } from 'react'
import { Button } from "@/src/ui/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Textarea } from "@/src/ui/components/ui/textarea"
import { Badge } from "@/src/ui/components/ui/badge"
import { Progress } from "@/src/ui/components/ui/progress"
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/src/ui/components/ui/tabs"
import { Alert, AlertDescription } from "@/src/ui/components/ui/alert"
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/src/ui/components/ui/select"
import { 
  Key, 
  Lock,
  Unlock,
  AlertTriangle, 
  Zap, 
  Eye,
  Terminal,
  Hash,
  ArrowLeft,
  Play,
  RefreshCw,
  CheckCircle,
  XCircle,
  Shield,
  Clock,
  Target,
  Database
} from 'lucide-react'
import Link from 'next/link'

interface PasswordCrackingResult {
  hashType: string;
  hashInput: string;
  crackingMethod: string;
  results: {
    cracked: boolean;
    plaintext?: string;
    attempts: number;
    timeElapsed: string;
    hashRate: string;
  };
  hashAnalysis: {
    algorithm: string;
    saltDetected: boolean;
    complexity: 'Low' | 'Medium' | 'High' | 'Very High';
    estimatedStrength: number;
    vulnerabilities: string[];
  };
  dictionaryStats?: {
    wordsTotal: number;
    wordsTested: number;
    rulesApplied: number;
  };
  bruteForceStats?: {
    charset: string;
    maxLength: number;
    combinations: string;
    progress: number;
  };
  recommendations: string[];
  summary: string;
}

export default function PasswordCrackingToolPage() {
  const [hashInput, setHashInput] = useState('')
  const [hashType, setHashType] = useState('auto')
  const [attackMethod, setAttackMethod] = useState('dictionary')
  const [wordlist, setWordlist] = useState('common')
  const [customWordlist, setCustomWordlist] = useState('')
  const [bruteForceCharset, setBruteForceCharset] = useState('lowercase')
  const [maxLength, setMaxLength] = useState('8')
  const [rules, setRules] = useState(['common', 'leetspeak'])
  const [results, setResults] = useState<PasswordCrackingResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [progress, setProgress] = useState(0)
  const [error, setError] = useState<string | null>(null)

  const handleCrack = async () => {
    if (!hashInput.trim()) {
      setError('Please enter a hash to crack')
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)
    setProgress(0)

    // Simulate progress
    const progressInterval = setInterval(() => {
      setProgress(prev => Math.min(prev + Math.random() * 3, 85))
    }, 2000)

    try {
      const response = await fetch('/api/tools/password-cracking', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({
          hashInput: hashInput.trim(),
          hashType,
          attackMethod,
          wordlist,
          customWordlist: customWordlist.trim(),
          bruteForceCharset,
          maxLength: parseInt(maxLength),
          rules,
        }),
      })

      if (!response.ok) {
        throw new Error('Failed to perform password cracking')
      }

      const data = await response.json()
      setResults(data)
      setProgress(100)
    } catch (err) {
      setError(err instanceof Error ? err.message : 'An error occurred')
    } finally {
      clearInterval(progressInterval)
      setLoading(false)
    }
  }

  const handleRuleToggle = (rule: string) => {
    setRules(prev => 
      prev.includes(rule) 
        ? prev.filter(r => r !== rule)
        : [...prev, rule]
    )
  }

  const getComplexityColor = (complexity: string) => {
    switch (complexity) {
      case 'Low': return 'bg-red-500 text-white'
      case 'Medium': return 'bg-yellow-500 text-black'
      case 'High': return 'bg-blue-500 text-white'
      case 'Very High': return 'bg-green-500 text-white'
      default: return 'bg-gray-500 text-white'
    }
  }

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-900 via-green-900 to-slate-900 p-4">
      <div className="max-w-6xl mx-auto">
        {/* Header */}
        <div className="flex items-center gap-4 mb-8">
          <Link href="/tools" className="p-2 hover:bg-white/10 rounded-lg transition-colors">
            <ArrowLeft className="w-5 h-5 text-white" />
          </Link>
          <div>
            <h1 className="text-3xl font-bold text-white mb-2">Password Cracking Tool</h1>
            <p className="text-gray-300">
              Hash cracking and password analysis with multiple attack methods
            </p>
          </div>
        </div>

        {/* Configuration Form */}
        <Card className="mb-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Key className="w-5 h-5" />
              Password Cracking Configuration
            </CardTitle>
            <CardDescription className="text-gray-300">
              Configure hash cracking parameters and attack methods
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label htmlFor="hashInput" className="text-gray-200">Hash to Crack</Label>
              <Textarea
                id="hashInput"
                placeholder="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8&#10;$2b$12$GVJJOl7GvJ9nD1KJ0KJ0K.rQ2Q2Q2Q2Q2Q2Q2Q2Q2Q2Q2Q2Q2Q&#10;8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
                value={hashInput}
                onChange={(e) => setHashInput(e.target.value)}
                className="bg-slate-700 border-slate-600 text-white placeholder-gray-400 font-mono"
                rows={4}
              />
            </div>

            <div className="grid md:grid-cols-2 gap-4">
              <div className="space-y-2">
                <Label htmlFor="hashType" className="text-gray-200">Hash Type</Label>
                <Select value={hashType} onValueChange={setHashType}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="auto">Auto Detect</SelectItem>
                    <SelectItem value="md5">MD5</SelectItem>
                    <SelectItem value="sha1">SHA1</SelectItem>
                    <SelectItem value="sha256">SHA256</SelectItem>
                    <SelectItem value="sha512">SHA512</SelectItem>
                    <SelectItem value="bcrypt">bcrypt</SelectItem>
                    <SelectItem value="scrypt">scrypt</SelectItem>
                    <SelectItem value="argon2">Argon2</SelectItem>
                    <SelectItem value="ntlm">NTLM</SelectItem>
                    <SelectItem value="lm">LM</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-2">
                <Label htmlFor="attackMethod" className="text-gray-200">Attack Method</Label>
                <Select value={attackMethod} onValueChange={setAttackMethod}>
                  <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-slate-700 border-slate-600">
                    <SelectItem value="dictionary">Dictionary Attack</SelectItem>
                    <SelectItem value="bruteforce">Brute Force</SelectItem>
                    <SelectItem value="hybrid">Hybrid (Dict + Rules)</SelectItem>
                    <SelectItem value="mask">Mask Attack</SelectItem>
                    <SelectItem value="combinator">Combinator Attack</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {(attackMethod === 'dictionary' || attackMethod === 'hybrid') && (
              <div className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="wordlist" className="text-gray-200">Wordlist</Label>
                  <Select value={wordlist} onValueChange={setWordlist}>
                    <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-700 border-slate-600">
                      <SelectItem value="common">Common Passwords</SelectItem>
                      <SelectItem value="rockyou">RockYou (14M passwords)</SelectItem>
                      <SelectItem value="top1000">Top 1000 Passwords</SelectItem>
                      <SelectItem value="leaked">Leaked Password Lists</SelectItem>
                      <SelectItem value="names">Names & Places</SelectItem>
                      <SelectItem value="keyboard">Keyboard Patterns</SelectItem>
                      <SelectItem value="custom">Custom Wordlist</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {wordlist === 'custom' && (
                  <div>
                    <Label htmlFor="customWordlist" className="text-gray-200">Custom Wordlist</Label>
                    <Textarea
                      id="customWordlist"
                      placeholder="password&#10;123456&#10;admin&#10;qwerty&#10;letmein&#10;password123"
                      value={customWordlist}
                      onChange={(e) => setCustomWordlist(e.target.value)}
                      className="bg-slate-700 border-slate-600 text-white placeholder-gray-400"
                      rows={6}
                    />
                  </div>
                )}

                {attackMethod === 'hybrid' && (
                  <div>
                    <Label className="text-gray-200 mb-2 block">Rules (Mutations)</Label>
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                      {[
                        { id: 'common', label: 'Common Rules' },
                        { id: 'leetspeak', label: 'Leetspeak (l33t)' },
                        { id: 'case', label: 'Case Variations' },
                        { id: 'append-numbers', label: 'Append Numbers' },
                        { id: 'prepend-numbers', label: 'Prepend Numbers' },
                        { id: 'special-chars', label: 'Special Characters' },
                        { id: 'keyboard-walk', label: 'Keyboard Walking' },
                        { id: 'reverse', label: 'Reverse Words' }
                      ].map((rule) => (
                        <div key={rule.id} className="flex items-center space-x-2">
                          <input
                            type="checkbox"
                            id={rule.id}
                            checked={rules.includes(rule.id)}
                            onChange={() => handleRuleToggle(rule.id)}
                            className="rounded"
                            aria-label={rule.label}
                          />
                          <Label 
                            htmlFor={rule.id} 
                            className="text-gray-300 text-sm cursor-pointer"
                          >
                            {rule.label}
                          </Label>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {attackMethod === 'bruteforce' && (
              <div className="grid md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label htmlFor="bruteForceCharset" className="text-gray-200">Character Set</Label>
                  <Select value={bruteForceCharset} onValueChange={setBruteForceCharset}>
                    <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-700 border-slate-600">
                      <SelectItem value="lowercase">Lowercase (a-z)</SelectItem>
                      <SelectItem value="uppercase">Uppercase (A-Z)</SelectItem>
                      <SelectItem value="mixed-case">Mixed Case (a-zA-Z)</SelectItem>
                      <SelectItem value="alphanumeric">Alphanumeric (a-zA-Z0-9)</SelectItem>
                      <SelectItem value="all-printable">All Printable</SelectItem>
                      <SelectItem value="custom">Custom Charset</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                <div className="space-y-2">
                  <Label htmlFor="maxLength" className="text-gray-200">Maximum Length</Label>
                  <Select value={maxLength} onValueChange={setMaxLength}>
                    <SelectTrigger className="bg-slate-700 border-slate-600 text-white">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent className="bg-slate-700 border-slate-600">
                      <SelectItem value="4">4 characters</SelectItem>
                      <SelectItem value="6">6 characters</SelectItem>
                      <SelectItem value="8">8 characters</SelectItem>
                      <SelectItem value="10">10 characters</SelectItem>
                      <SelectItem value="12">12 characters</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}

            <Button 
              onClick={handleCrack}
              disabled={loading}
              className="w-full bg-green-600 hover:bg-green-700"
            >
              {loading ? (
                <>
                  <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  Cracking Password...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Start Password Cracking
                </>
              )}
            </Button>

            {loading && (
              <div className="space-y-2">
                <div className="flex justify-between text-sm text-gray-300">
                  <span>Attempting to crack hash...</span>
                  <span>{Math.round(progress)}%</span>
                </div>
                <Progress value={progress} className="bg-slate-600" />
              </div>
            )}
          </CardContent>
        </Card>

        {/* Error Display */}
        {error && (
          <Alert className="mb-6 bg-red-900/50 border-red-500 text-red-200">
            <AlertTriangle className="h-4 w-4" />
            <AlertDescription>{error}</AlertDescription>
          </Alert>
        )}

        {/* Results */}
        {results && (
          <div className="space-y-6">
            {/* Summary Card */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-white">
                  <Target className="w-5 h-5" />
                  Password Cracking Results
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-green-400">
                      {results.results.cracked ? <CheckCircle className="w-8 h-8 mx-auto" /> : <XCircle className="w-8 h-8 mx-auto" />}
                    </div>
                    <div className="text-sm text-gray-300">
                      {results.results.cracked ? 'Cracked' : 'Not Cracked'}
                    </div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-purple-400">
                      {results.results.attempts.toLocaleString()}
                    </div>
                    <div className="text-sm text-gray-300">Attempts</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-blue-400">
                      {results.results.hashRate}
                    </div>
                    <div className="text-sm text-gray-300">Hash Rate</div>
                  </div>
                  <div className="text-center p-4 bg-slate-700/50 rounded-lg">
                    <div className="text-2xl font-bold text-orange-400">
                      {results.results.timeElapsed}
                    </div>
                    <div className="text-sm text-gray-300">Time Elapsed</div>
                  </div>
                </div>

                {results.results.cracked && results.results.plaintext && (
                  <Alert className="mb-4 bg-green-900/50 border-green-500 text-green-200">
                    <CheckCircle className="h-4 w-4" />
                    <AlertDescription>
                      <strong>Password Cracked:</strong> 
                      <code className="ml-2 text-green-300 bg-green-800/50 px-2 py-1 rounded">
                        {results.results.plaintext}
                      </code>
                    </AlertDescription>
                  </Alert>
                )}

                <div className="mb-4">
                  <h3 className="text-lg font-semibold text-white mb-2">Analysis Summary</h3>
                  <p className="text-gray-300">{results.summary}</p>
                </div>

                {/* Hash Analysis */}
                <div className="bg-slate-700/30 rounded-lg p-4">
                  <h4 className="font-medium text-white mb-3">Hash Analysis</h4>
                  <div className="grid md:grid-cols-2 gap-4">
                    <div className="space-y-2">
                      <div className="flex justify-between">
                        <span className="text-gray-300">Algorithm:</span>
                        <Badge variant="outline" className="text-blue-400 border-blue-400">
                          {results.hashAnalysis.algorithm}
                        </Badge>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-300">Salt Detected:</span>
                        <span className={results.hashAnalysis.saltDetected ? 'text-green-400' : 'text-red-400'}>
                          {results.hashAnalysis.saltDetected ? 'Yes' : 'No'}
                        </span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-gray-300">Complexity:</span>
                        <Badge className={getComplexityColor(results.hashAnalysis.complexity)}>
                          {results.hashAnalysis.complexity}
                        </Badge>
                      </div>
                    </div>
                    <div>
                      <span className="text-gray-300 block mb-2">Estimated Strength:</span>
                      <div className="flex items-center gap-2">
                        <Progress value={results.hashAnalysis.estimatedStrength} className="bg-slate-600 flex-1" />
                        <span className="text-sm text-gray-400">{results.hashAnalysis.estimatedStrength}%</span>
                      </div>
                    </div>
                  </div>

                  {results.hashAnalysis.vulnerabilities.length > 0 && (
                    <div className="mt-4">
                      <h5 className="font-medium text-red-400 mb-2">Vulnerabilities:</h5>
                      <div className="space-y-1">
                        {results.hashAnalysis.vulnerabilities.map((vuln, index) => (
                          <div key={index} className="text-sm text-red-300 bg-red-900/20 p-2 rounded">
                            {vuln}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Detailed Results */}
            <Card className="bg-slate-800/50 backdrop-blur-sm border-slate-700">
              <CardHeader>
                <CardTitle className="text-white">Attack Statistics</CardTitle>
              </CardHeader>
              <CardContent>
                <Tabs defaultValue="stats" className="space-y-4">
                  <TabsList className="bg-slate-700">
                    <TabsTrigger value="stats">Statistics</TabsTrigger>
                    <TabsTrigger value="recommendations">Recommendations</TabsTrigger>
                  </TabsList>

                  <TabsContent value="stats" className="space-y-4">
                    {results.dictionaryStats && (
                      <Card className="bg-slate-700/30">
                        <CardHeader>
                          <CardTitle className="text-white">Dictionary Attack Statistics</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="grid md:grid-cols-3 gap-4">
                            <div className="text-center p-3 bg-slate-800/50 rounded">
                              <div className="text-xl font-bold text-blue-400">
                                {results.dictionaryStats.wordsTotal.toLocaleString()}
                              </div>
                              <div className="text-sm text-gray-300">Total Words</div>
                            </div>
                            <div className="text-center p-3 bg-slate-800/50 rounded">
                              <div className="text-xl font-bold text-green-400">
                                {results.dictionaryStats.wordsTested.toLocaleString()}
                              </div>
                              <div className="text-sm text-gray-300">Words Tested</div>
                            </div>
                            <div className="text-center p-3 bg-slate-800/50 rounded">
                              <div className="text-xl font-bold text-purple-400">
                                {results.dictionaryStats.rulesApplied}
                              </div>
                              <div className="text-sm text-gray-300">Rules Applied</div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    )}

                    {results.bruteForceStats && (
                      <Card className="bg-slate-700/30">
                        <CardHeader>
                          <CardTitle className="text-white">Brute Force Statistics</CardTitle>
                        </CardHeader>
                        <CardContent>
                          <div className="space-y-3">
                            <div className="flex justify-between">
                              <span className="text-gray-300">Character Set:</span>
                              <code className="text-green-400 bg-slate-800 px-2 py-1 rounded text-sm">
                                {results.bruteForceStats.charset}
                              </code>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-300">Maximum Length:</span>
                              <span className="text-blue-400">{results.bruteForceStats.maxLength} characters</span>
                            </div>
                            <div className="flex justify-between">
                              <span className="text-gray-300">Total Combinations:</span>
                              <span className="text-orange-400">{results.bruteForceStats.combinations}</span>
                            </div>
                            <div>
                              <span className="text-gray-300 block mb-2">Progress:</span>
                              <div className="flex items-center gap-2">
                                <Progress value={results.bruteForceStats.progress} className="bg-slate-600 flex-1" />
                                <span className="text-sm text-gray-400">{results.bruteForceStats.progress}%</span>
                              </div>
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    )}
                  </TabsContent>

                  <TabsContent value="recommendations" className="space-y-4">
                    <Card className="bg-slate-700/30">
                      <CardHeader>
                        <CardTitle className="text-white">Security Recommendations</CardTitle>
                      </CardHeader>
                      <CardContent>
                        <ul className="space-y-3">
                          {results.recommendations.map((rec, index) => (
                            <li key={index} className="flex items-start gap-2">
                              <Shield className="w-5 h-5 text-blue-400 mt-0.5 flex-shrink-0" />
                              <span className="text-gray-300">{rec}</span>
                            </li>
                          ))}
                        </ul>
                      </CardContent>
                    </Card>
                  </TabsContent>
                </Tabs>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Educational Information */}
        <Card className="mt-6 bg-slate-800/50 backdrop-blur-sm border-slate-700">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-white">
              <Terminal className="w-5 h-5" />
              About Password Cracking
            </CardTitle>
          </CardHeader>
          <CardContent className="text-gray-300 space-y-4">
            <div className="grid md:grid-cols-2 gap-6">
              <div>
                <h4 className="font-semibold mb-2 text-white">Attack Methods:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• <strong>Dictionary:</strong> Common password lists</li>
                  <li>• <strong>Brute Force:</strong> Try all combinations</li>
                  <li>• <strong>Hybrid:</strong> Dictionary with mutations</li>
                  <li>• <strong>Mask:</strong> Pattern-based attacks</li>
                  <li>• <strong>Rainbow Tables:</strong> Pre-computed hashes</li>
                </ul>
              </div>
              <div>
                <h4 className="font-semibold mb-2 text-white">Defense Strategies:</h4>
                <ul className="space-y-1 text-sm">
                  <li>• Use strong, unique passwords</li>
                  <li>• Implement proper salt and key stretching</li>
                  <li>• Use modern hashing algorithms (Argon2, bcrypt)</li>
                  <li>• Enable multi-factor authentication</li>
                  <li>• Regular password policy enforcement</li>
                </ul>
              </div>
            </div>

            <Alert className="bg-amber-900/20 border-amber-500/50 text-amber-200">
              <AlertTriangle className="h-4 w-4" />
              <AlertDescription>
                <strong>Ethical Use Only:</strong> Password cracking should only be performed on your own systems 
                or with explicit permission. Use this knowledge to improve password security practices.
              </AlertDescription>
            </Alert>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}