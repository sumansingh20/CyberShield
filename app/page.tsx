"use client"

import { useEffect } from "react"
import { useRouter } from "next/navigation"
import { useAuth } from "@/contexts/AuthContext"
import { ThemeToggle } from "@/components/ThemeToggle"
import { Button } from "@/components/ui/button"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, Lock, Zap, Users, ArrowRight, Star, CheckCircle } from "lucide-react"
import Link from "next/link"

export default function HomePage() {
  const { isAuthenticated, isLoading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    // Add safety check to prevent router issues
    if (!isLoading && isAuthenticated && router) {
      try {
        router.push("/dashboard")
      } catch (error) {
        console.error('Navigation error:', error)
      }
    }
  }, [isAuthenticated, isLoading, router])

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center gradient-bg">
        <div className="spinner w-8 h-8"></div>
      </div>
    )
  }

  return (
    <div className="min-h-screen gradient-bg">
      {/* Navigation */}
      <nav className="border-b border-border/50 glass backdrop-blur-xl sticky top-0 z-50">
        <div className="container mx-auto px-4 py-4 flex items-center justify-between">
          <div className="flex items-center space-x-3">
            <div className="p-2 rounded-lg bg-primary/10 glow">
              <Shield className="h-6 w-6 text-primary" />
            </div>
            <div>
              <h1 className="text-lg font-bold">Unified Toolkit</h1>
              <p className="text-xs text-muted-foreground">For New Pen-Testers</p>
            </div>
          </div>
          <div className="flex items-center space-x-4">
            <ThemeToggle />
            <div className="hidden sm:flex items-center space-x-2">
              <Link href="/login">
                <Button variant="ghost" size="sm">
                  Sign In
                </Button>
              </Link>
              <Link href="/register">
                <Button size="sm" className="glow-hover">
                  Get Started
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </nav>

      {/* Hero Section */}
      <section className="relative overflow-hidden">
        <div className="absolute inset-0 bg-cyber-grid opacity-10"></div>
        <div className="container mx-auto px-4 py-20 relative z-10">
          <div className="text-center animate-fade-in">
            <div className="flex justify-center mb-6">
              <div className="p-4 rounded-full bg-primary/10 glow animate-pulse-glow">
                <Shield className="h-16 w-16 text-primary" />
              </div>
            </div>
            <h1 className="text-5xl md:text-6xl font-bold mb-6 bg-gradient-to-r from-primary to-primary/60 bg-clip-text text-transparent">
              Unified Toolkit for New Pen-Testers
            </h1>
            <p className="text-xl text-muted-foreground mb-8 max-w-3xl mx-auto leading-relaxed">
              A comprehensive cybersecurity learning platform that brings together essential penetration testing tools
              in one modern, secure interface. Perfect for beginners and professionals alike.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center mb-8">
              <Link href="/register">
                <Button size="lg" className="w-full sm:w-auto glow-hover group">
                  Get Started
                  <ArrowRight className="ml-2 h-4 w-4 group-hover:translate-x-1 transition-transform" />
                </Button>
              </Link>
              <Link href="/login">
                <Button variant="outline" size="lg" className="w-full sm:w-auto glass hover:glow-hover bg-transparent">
                  Sign In
                </Button>
              </Link>
            </div>
            <div className="flex items-center justify-center gap-6 text-sm text-muted-foreground">
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-success" />
                <span>Free to use</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-success" />
                <span>Open source</span>
              </div>
              <div className="flex items-center gap-2">
                <CheckCircle className="h-4 w-4 text-success" />
                <span>Secure by design</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20">
        <div className="container mx-auto px-4">
          <div className="text-center mb-16 animate-slide-up">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Everything You Need for Penetration Testing</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
              Our platform integrates the most essential security tools with enterprise-grade authentication and a
              beautiful, intuitive interface.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
            {[
              {
                icon: Shield,
                title: "Security Tools",
                description: "Nmap, Nikto, Sublist3r, and more integrated tools for comprehensive testing.",
                color: "text-blue-500",
                bgColor: "bg-blue-500/10",
              },
              {
                icon: Lock,
                title: "Secure Authentication",
                description: "2FA with email and SMS, reCAPTCHA protection, and JWT-based sessions.",
                color: "text-green-500",
                bgColor: "bg-green-500/10",
              },
              {
                icon: Zap,
                title: "Modern Interface",
                description: "CLI-style output with typing effects, copy-to-clipboard, and export features.",
                color: "text-yellow-500",
                bgColor: "bg-yellow-500/10",
              },
              {
                icon: Users,
                title: "Learning Focused",
                description: "Designed specifically for new penetration testers to learn and practice.",
                color: "text-purple-500",
                bgColor: "bg-purple-500/10",
              },
            ].map((feature, index) => (
              <Card
                key={index}
                className="glass-card hover:glow-hover transition-all duration-300 animate-slide-up"
                style={{ animationDelay: `${index * 0.1}s` }}
              >
                <CardHeader>
                  <div className={`p-3 rounded-lg ${feature.bgColor} w-fit mb-2`}>
                    <feature.icon className={`h-6 w-6 ${feature.color}`} />
                  </div>
                  <CardTitle>{feature.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription>{feature.description}</CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Tools Section */}
      <section className="py-20 relative">
        <div className="absolute inset-0 bg-muted/20"></div>
        <div className="container mx-auto px-4 relative z-10">
          <div className="text-center mb-16">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Integrated Security Tools</h2>
            <p className="text-muted-foreground max-w-2xl mx-auto text-lg">
              Access professional-grade penetration testing tools through our secure web interface.
            </p>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
            {[
              { name: "Port Scanner", desc: "Nmap integration for network discovery", icon: "🔍" },
              { name: "Subdomain Enum", desc: "Find subdomains with Sublist3r", icon: "🌐" },
              { name: "Vulnerability Scanner", desc: "Web app scanning with Nikto", icon: "🛡️" },
              { name: "WHOIS Lookup", desc: "Domain registration information", icon: "📋" },
              { name: "DNS Information", desc: "DNS records and zone data", icon: "🔗" },
              { name: "HTTP Headers", desc: "Analyze response headers", icon: "📄" },
            ].map((tool, index) => (
              <Card
                key={index}
                className="glass-card hover:glow-hover transition-all duration-300 animate-slide-up"
                style={{ animationDelay: `${index * 0.1}s` }}
              >
                <CardHeader>
                  <div className="flex items-center gap-3">
                    <span className="text-2xl">{tool.icon}</span>
                    <CardTitle className="text-lg">{tool.name}</CardTitle>
                  </div>
                </CardHeader>
                <CardContent>
                  <CardDescription>{tool.desc}</CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20">
        <div className="container mx-auto px-4 text-center">
          <div className="glass-card p-12 max-w-4xl mx-auto">
            <h2 className="text-3xl md:text-4xl font-bold mb-4">Ready to Start Your Cybersecurity Journey?</h2>
            <p className="text-muted-foreground mb-8 max-w-2xl mx-auto text-lg">
              Join thousands of security professionals who trust our platform for their penetration testing needs.
            </p>
            <div className="flex flex-col sm:flex-row gap-4 justify-center">
              <Link href="/register">
                <Button size="lg" className="w-full sm:w-auto glow-hover group">
                  Create Your Account
                  <ArrowRight className="ml-2 h-4 w-4 group-hover:translate-x-1 transition-transform" />
                </Button>
              </Link>
              <Link href="/login">
                <Button variant="outline" size="lg" className="w-full sm:w-auto glass hover:glow-hover bg-transparent">
                  Sign In Instead
                </Button>
              </Link>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border/50 glass backdrop-blur-xl">
        <div className="container mx-auto px-4 py-8">
          <div className="flex flex-col md:flex-row items-center justify-between">
            <div className="flex items-center space-x-3 mb-4 md:mb-0">
              <Shield className="h-5 w-5 text-primary" />
              <span className="text-sm text-muted-foreground">
                © 2025 Unified Toolkit for New Pen-Testers. Developed by Suman.
              </span>
            </div>
            <div className="flex items-center space-x-4">
              <div className="flex items-center gap-1">
                <Star className="h-4 w-4 text-yellow-500 fill-current" />
                <span className="text-sm text-muted-foreground">Open Source</span>
              </div>
              <div className="flex items-center gap-1">
                <Shield className="h-4 w-4 text-green-500" />
                <span className="text-sm text-muted-foreground">Secure</span>
              </div>
            </div>
          </div>
        </div>
      </footer>
    </div>
  )
}
