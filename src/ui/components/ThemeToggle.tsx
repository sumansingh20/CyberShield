"use client"

import { Moon, Sun, Monitor, Zap, Code, Terminal, Palette, Eye } from "lucide-react"
import { Button } from "@/src/ui/components/ui/button"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
  DropdownMenuSeparator,
  DropdownMenuLabel,
} from "@/src/ui/components/ui/dropdown-menu"
import { useTheme } from "next-themes"

const themeIcons = {
  light: Sun,
  dark: Moon,
  system: Monitor,
  cyberpunk: Zap,
  matrix: Code,
  hacker: Terminal,
  neon: Palette,
  terminal: Eye,
}

const themeNames = {
  light: "Light",
  dark: "Dark",
  system: "System",
  cyberpunk: "Cyberpunk",
  matrix: "Matrix",
  hacker: "Hacker",
  neon: "Neon",
  terminal: "Terminal",
}

export function ThemeToggle() {
  const { theme, setTheme, resolvedTheme } = useTheme()

  const CurrentIcon = themeIcons[resolvedTheme as keyof typeof themeIcons] || Moon

  return (
    <DropdownMenu>
      <DropdownMenuTrigger asChild>
        <Button
          variant="outline"
          size="sm"
          className="bg-background/50 backdrop-blur border-border/50 hover:bg-accent/50"
        >
          <CurrentIcon className="h-[1.2rem] w-[1.2rem] transition-all" />
          <span className="sr-only">Toggle theme</span>
        </Button>
      </DropdownMenuTrigger>
      <DropdownMenuContent align="end" className="bg-background/95 backdrop-blur-sm border-border/50 min-w-[160px]">
        <DropdownMenuLabel className="text-xs font-medium text-muted-foreground">Standard Themes</DropdownMenuLabel>
        <DropdownMenuItem
          onClick={() => setTheme("light")}
          className={`cursor-pointer ${theme === "light" ? "bg-accent" : ""}`}
        >
          <Sun className="mr-2 h-4 w-4" />
          <span>Light</span>
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => setTheme("dark")}
          className={`cursor-pointer ${theme === "dark" ? "bg-accent" : ""}`}
        >
          <Moon className="mr-2 h-4 w-4" />
          <span>Dark</span>
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => setTheme("system")}
          className={`cursor-pointer ${theme === "system" ? "bg-accent" : ""}`}
        >
          <Monitor className="mr-2 h-4 w-4" />
          <span>System</span>
        </DropdownMenuItem>

        <DropdownMenuSeparator />
        <DropdownMenuLabel className="text-xs font-medium text-muted-foreground">Hacker Themes</DropdownMenuLabel>

        <DropdownMenuItem
          onClick={() => setTheme("cyberpunk")}
          className={`cursor-pointer ${theme === "cyberpunk" ? "bg-accent" : ""}`}
        >
          <Zap className="mr-2 h-4 w-4 text-pink-500" />
          <span>Cyberpunk</span>
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => setTheme("matrix")}
          className={`cursor-pointer ${theme === "matrix" ? "bg-accent" : ""}`}
        >
          <Code className="mr-2 h-4 w-4 text-green-500" />
          <span>Matrix</span>
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => setTheme("hacker")}
          className={`cursor-pointer ${theme === "hacker" ? "bg-accent" : ""}`}
        >
          <Terminal className="mr-2 h-4 w-4 text-red-500" />
          <span>Hacker</span>
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => setTheme("neon")}
          className={`cursor-pointer ${theme === "neon" ? "bg-accent" : ""}`}
        >
          <Palette className="mr-2 h-4 w-4 text-cyan-500" />
          <span>Neon</span>
        </DropdownMenuItem>
        <DropdownMenuItem
          onClick={() => setTheme("terminal")}
          className={`cursor-pointer ${theme === "terminal" ? "bg-accent" : ""}`}
        >
          <Eye className="mr-2 h-4 w-4 text-amber-500" />
          <span>Terminal</span>
        </DropdownMenuItem>
      </DropdownMenuContent>
    </DropdownMenu>
  )
}
