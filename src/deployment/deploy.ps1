# CyberShield Deployment Script for Windows
# PowerShell script to help deploy to both Vercel and Netlify

Write-Host "CyberShield Deployment Helper" -ForegroundColor Cyan
Write-Host "=================================" -ForegroundColor Cyan

# Check if we're in the right directory
if (-not (Test-Path "package.json")) {
    Write-Host "Error: Please run this script from the project root directory" -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "Installing dependencies..." -ForegroundColor Yellow
pnpm install

# Run build to ensure everything works
Write-Host "Building project..." -ForegroundColor Yellow
pnpm run build

if ($LASTEXITCODE -ne 0) {
    Write-Host "Build failed! Please fix the errors before deploying." -ForegroundColor Red
    exit 1
}

Write-Host "Build successful!" -ForegroundColor Green
Write-Host ""
Write-Host "Ready for deployment!" -ForegroundColor Cyan
Write-Host ""
Write-Host "Deployment Options:" -ForegroundColor White
Write-Host "1. Vercel (Recommended for Next.js):" -ForegroundColor Green
Write-Host "   - Install: npm i -g vercel" -ForegroundColor Gray
Write-Host "   - Deploy: vercel --prod" -ForegroundColor Gray
Write-Host ""
Write-Host "2. Netlify:" -ForegroundColor Blue
Write-Host "   - Install: npm i -g netlify-cli" -ForegroundColor Gray
Write-Host "   - Deploy: netlify deploy --prod --dir=.next" -ForegroundColor Gray
Write-Host ""
Write-Host "Don't forget to set environment variables:" -ForegroundColor Yellow
Write-Host "   - MONGODB_URI" -ForegroundColor Gray
Write-Host "   - JWT_SECRET" -ForegroundColor Gray
Write-Host "   - JWT_REFRESH_SECRET" -ForegroundColor Gray
Write-Host "   - NEXT_PUBLIC_RECAPTCHA_SITE_KEY" -ForegroundColor Gray
Write-Host "   - RECAPTCHA_SECRET_KEY" -ForegroundColor Gray
Write-Host "   - SMTP_* variables" -ForegroundColor Gray
Write-Host "   - TWILIO_* variables" -ForegroundColor Gray