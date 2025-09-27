#!/usr/bin/env pwsh

# Fix all import paths in CyberShield project
Write-Host "🔧 Fixing import paths in CyberShield..." -ForegroundColor Cyan

$rootPath = "c:\Users\suman\OneDrive\Desktop\CyberShield"
$oldPaths = @{
    '@/contexts/AuthContext' = '@/src/auth/utils/AuthContext'
    '@/hooks/useApi' = '@/src/ui/hooks/useApi'
    '@/hooks/use-toast' = '@/src/ui/hooks/use-toast'
    '@/components/TwoFactorVerify' = '@/src/auth/utils/TwoFactorVerify'
}

# Get all TypeScript and TSX files
$files = Get-ChildItem -Path $rootPath -Recurse -Include "*.ts", "*.tsx" | Where-Object { 
    $_.FullName -notlike "*node_modules*" -and 
    $_.FullName -notlike "*\.next*" -and
    $_.FullName -notlike "*\.git*"
}

$totalFiles = 0
$updatedFiles = 0

foreach ($file in $files) {
    $totalFiles++
    $content = Get-Content -Path $file.FullName -Raw -ErrorAction SilentlyContinue
    
    if ($content) {
        $originalContent = $content
        
        foreach ($oldPath in $oldPaths.Keys) {
            $newPath = $oldPaths[$oldPath]
            $content = $content -replace [regex]::Escape($oldPath), $newPath
        }
        
        if ($content -ne $originalContent) {
            Set-Content -Path $file.FullName -Value $content -NoNewline
            $updatedFiles++
            Write-Host "✅ Updated: $($file.FullName.Replace($rootPath, ''))" -ForegroundColor Green
        }
    }
}

Write-Host ""
Write-Host "📊 Summary:" -ForegroundColor Yellow
Write-Host "- Total files scanned: $totalFiles" -ForegroundColor White
Write-Host "- Files updated: $updatedFiles" -ForegroundColor Green
Write-Host ""
Write-Host "🎉 Import path fixes completed!" -ForegroundColor Green