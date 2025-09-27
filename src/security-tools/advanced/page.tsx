"use client"
import React from "react"
import { Card, CardContent, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import Link from "next/link"
import { ArrowRight } from "lucide-react"

const advancedTools = [
  {
    name: "Cryptography",
    description: "Tools for encryption, decryption, and cryptographic analysis.",
    link: "/tools/advanced/cryptography",
  },
  {
    name: "Digital Forensics",
    description: "Tools for analyzing digital evidence.",
    link: "/tools/advanced/digital-forensics",
  },
  {
    name: "Directory Buster",
    description: "Discover hidden directories and files on web servers.",
    link: "/tools/advanced/directory-buster",
  },
  {
    name: "OSINT",
    description: "Gather open-source intelligence.",
    link: "/tools/advanced/osint",
  },
  {
    name: "Social Engineering",
    description: "Tools and resources for social engineering campaigns.",
    link: "/tools/advanced/social-engineering",
  },
  {
    name: "Wireless Security",
    description: "Tools for auditing and securing wireless networks.",
    link: "/tools/advanced/wireless-security",
  },
]

export default function AdvancedToolsPage() {
  return (
    <div className="container mx-auto px-4 py-8">
      <h1 className="text-4xl font-bold mb-8">Advanced Tools</h1>
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {advancedTools.map((tool) => (
          <Link href={tool.link} key={tool.name} className="group">
            <Card className="h-full transition-all duration-300 hover:shadow-lg hover:border-primary">
              <CardHeader>
                <CardTitle className="flex items-center justify-between">
                  {tool.name}
                  <ArrowRight className="w-5 h-5 text-gray-400 group-hover:text-primary transition-colors" />
                </CardTitle>
              </CardHeader>
              <CardContent>
                <p className="text-muted-foreground">{tool.description}</p>
              </CardContent>
            </Card>
          </Link>
        ))}
      </div>
    </div>
  )
}
