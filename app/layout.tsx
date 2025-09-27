import type React from "react"
import type { Metadata } from "next"
import { Inter } from "next/font/google"
import "./globals.css"
import { AuthProvider } from "@/src/auth/utils/AuthContext"
import { ThemeProvider } from "@/src/ui/components/theme-provider"
import { Toaster } from "@/src/ui/components/ui/toaster"
import ErrorBoundary from "@/src/ui/components/ErrorBoundary"

const inter = Inter({ subsets: ["latin"] })

export const metadata: Metadata = {
  title: "CyberShield - Advanced Cybersecurity Testing Platform",
  description: "CyberShield - Professional penetration testing and cybersecurity assessment platform with integrated security tools. Developed by Suman Singh.",
  generator: 'Next.js',
  keywords: [
    "cybershield", 
    "cybersecurity", 
    "penetration testing", 
    "security tools", 
    "pentest", 
    "nmap", 
    "vulnerability scanner", 
    "security audit", 
    "pentest tools",
    "network security",
    "web security"
  ],
  authors: [{ name: "Suman Singh" }],
  creator: "Suman Singh",
  metadataBase: new URL('https://cybershield-platform.netlify.app'),
  openGraph: {
    title: 'CyberShield - Advanced Cybersecurity Testing Platform',
    description: 'Professional penetration testing and cybersecurity assessment platform',
    url: 'https://cybershield-platform.netlify.app',
    siteName: 'CyberShield',
    type: 'website',
  },
  twitter: {
    card: 'summary_large_image',
    title: 'CyberShield - Advanced Cybersecurity Testing Platform',
    description: 'Professional penetration testing and cybersecurity assessment platform',
  },
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      'max-video-preview': -1,
      'max-image-preview': 'large',
      'max-snippet': -1,
    },
  },
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
          <ThemeProvider
            attribute="class"
            defaultTheme="system"
            enableSystem
            disableTransitionOnChange
          >
            <AuthProvider>
              {children}
              <Toaster />
            </AuthProvider>
          </ThemeProvider>
        </ErrorBoundary>
      </body>
    </html>
  )
}
