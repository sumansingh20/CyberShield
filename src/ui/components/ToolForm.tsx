"use client"

import type React from "react"

import { useState } from "react"
import { Button } from "@/src/ui/components/ui/button"
import { Input } from "@/src/ui/components/ui/input"
import { Label } from "@/src/ui/components/ui/label"
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/src/ui/components/ui/card"
import { Play, Loader2 } from "lucide-react"

interface ToolFormProps {
  title: string
  description: string
  inputLabel: string
  inputPlaceholder: string
  onSubmit: (input: string) => void
  isLoading: boolean
  inputType?: string
}

export function ToolForm({
  title,
  description,
  inputLabel,
  inputPlaceholder,
  onSubmit,
  isLoading,
  inputType = "text",
}: ToolFormProps) {
  const [input, setInput] = useState("")

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    if (input.trim()) {
      onSubmit(input.trim())
    }
  }

  return (
    <Card className="glass-card animate-fade-in">
      <CardHeader>
        <CardTitle className="flex items-center gap-3">
          <div className="p-2 rounded-lg bg-primary/10">
            <Play className="h-5 w-5 text-primary" />
          </div>
          {title}
        </CardTitle>
        <CardDescription className="text-base leading-relaxed">{description}</CardDescription>
      </CardHeader>
      <CardContent>
        <form onSubmit={handleSubmit} className="space-y-6">
          <div className="space-y-3">
            <Label htmlFor="input" className="text-sm font-medium">
              {inputLabel}
            </Label>
            <Input
              id="input"
              type={inputType}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              placeholder={inputPlaceholder}
              required
              className="glass focus-ring transition-all duration-200"
              disabled={isLoading}
            />
          </div>
          <Button
            type="submit"
            disabled={isLoading || !input.trim()}
            className="w-full glow-hover group transition-all duration-200"
            size="lg"
          >
            {isLoading ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Running Scan...
              </>
            ) : (
              <>
                <Play className="mr-2 h-4 w-4 group-hover:scale-110 transition-transform" />
                Run Scan
              </>
            )}
          </Button>
        </form>
      </CardContent>
    </Card>
  )
}
