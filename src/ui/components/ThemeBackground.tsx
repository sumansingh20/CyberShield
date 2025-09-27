"use client"

import { useTheme } from "next-themes"
import { useEffect, useState } from "react"

export function ThemeBackground() {
  const { resolvedTheme } = useTheme()
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  if (!mounted) return null

  return (
    <div className="fixed inset-0 pointer-events-none z-0 overflow-hidden">
      {/* Matrix Rain Effect */}
      {resolvedTheme === "matrix" && (
        <div className="matrix-rain">
          {Array.from({ length: 20 }).map((_, i) => (
            <div
              key={i}
              className="absolute text-green-500 font-mono text-sm opacity-20 animate-matrix-rain"
              style={{
                left: `${i * 5}%`,
                animationDelay: `${i * 0.5}s`,
                animationDuration: `${15 + Math.random() * 10}s`,
              }}
            >
              {Array.from({ length: 20 }).map((_, j) => (
                <div key={j} className="block">
                  {String.fromCharCode(0x30a0 + Math.random() * 96)}
                </div>
              ))}
            </div>
          ))}
        </div>
      )}

      {/* Cyberpunk Grid */}
      {resolvedTheme === "cyberpunk" && (
        <div className="absolute inset-0 cyberpunk-grid opacity-10">
          <div className="absolute inset-0 bg-gradient-to-br from-pink-500/5 via-purple-500/5 to-blue-500/5 animate-cyberpunk-pulse"></div>
        </div>
      )}

      {/* Neon Grid */}
      {resolvedTheme === "neon" && (
        <div className="absolute inset-0 neon-grid opacity-10">
          <div className="absolute inset-0 bg-gradient-to-br from-cyan-500/5 via-purple-500/5 to-pink-500/5 animate-glow"></div>
        </div>
      )}

      {/* Hacker Terminal Lines */}
      {resolvedTheme === "hacker" && (
        <div className="absolute inset-0">
          {Array.from({ length: 10 }).map((_, i) => (
            <div
              key={i}
              className="absolute h-px bg-red-500/10 animate-pulse"
              style={{
                top: `${i * 10}%`,
                left: 0,
                right: 0,
                animationDelay: `${i * 0.3}s`,
              }}
            />
          ))}
        </div>
      )}

      {/* Terminal Scanlines */}
      {resolvedTheme === "terminal" && (
        <div className="absolute inset-0">
          <div className="absolute inset-0 bg-gradient-to-b from-transparent via-amber-500/5 to-transparent animate-pulse"></div>
          {Array.from({ length: 50 }).map((_, i) => (
            <div
              key={i}
              className="absolute h-px bg-amber-500/5"
              style={{
                top: `${i * 2}%`,
                left: 0,
                right: 0,
              }}
            />
          ))}
        </div>
      )}

      {/* Standard themes get subtle grid */}
      {(resolvedTheme === "dark" || resolvedTheme === "light") && (
        <div className="absolute inset-0 cyber-grid opacity-5"></div>
      )}
    </div>
  )
}
