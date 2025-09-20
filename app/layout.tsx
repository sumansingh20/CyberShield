import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import "./globals.css"
import { AuthProvider } from "@/contexts/AuthContext"
import { ThemeProvider } from "@/contexts/ThemeContext"
import { Toaster } from "@/components/ui/toaster"
import { ThemeBackground } from "@/components/ThemeBackground"
import ErrorBoundary from "@/components/ErrorBoundary"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "Unified Toolkit for New Pen-Testers",
  description: "Unified Toolkit for New Pen-Testers - Complete penetration testing platform with integrated security tools - Developed by Suman Singh",
  generator: 'Next.js',
  keywords: ["penetration testing", "cybersecurity", "security tools", "pentest", "nmap", "vulnerability scanner", "unified toolkit"],
  authors: [{ name: "Suman Singh" }],
  creator: "Suman Singh",
}

export default function RootLayout({
  children,
}: {
  children: React.ReactNode
}) {
  return (
    <html lang="en" suppressHydrationWarning>
      <body className={inter.className}>
        <ErrorBoundary>
          <ThemeProvider>
            <AuthProvider>
              <ThemeBackground />
              {children}
              <Toaster />
            </AuthProvider>
          </ThemeProvider>
        </ErrorBoundary>
      </body>
    </html>
  )
}
