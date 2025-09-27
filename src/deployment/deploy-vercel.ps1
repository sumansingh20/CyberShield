# Vercel Deployment Script for CyberShield
# Run this in PowerShell

Write-Host "🚀 CyberShield Vercel Deployment" -ForegroundColor Green
Write-Host "=================================" -ForegroundColor Green

# Check if Vercel CLI is installed
if (!(Get-Command "vercel" -ErrorAction SilentlyContinue)) {
    Write-Host "❌ Vercel CLI not found. Installing..." -ForegroundColor Yellow
    npm install -g vercel
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install Vercel CLI. Please install manually: npm install -g vercel" -ForegroundColor Red
        exit 1
    }
    Write-Host "✅ Vercel CLI installed successfully!" -ForegroundColor Green
}

# Login to Vercel (if not already logged in)
Write-Host "🔐 Checking Vercel authentication..." -ForegroundColor Cyan
vercel whoami 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Host "📝 Please login to Vercel..." -ForegroundColor Yellow
    vercel login
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to login to Vercel" -ForegroundColor Red
        exit 1
    }
}

Write-Host "✅ Authenticated with Vercel!" -ForegroundColor Green

# Check if we're in the correct directory
if (!(Test-Path "package.json")) {
    Write-Host "❌ package.json not found. Please run this script from the project root." -ForegroundColor Red
    exit 1
}

# Install dependencies
Write-Host "📦 Installing dependencies..." -ForegroundColor Cyan
pnpm install
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Failed to install dependencies" -ForegroundColor Red
    exit 1
}

# Build the project locally to test
Write-Host "🔨 Building project locally..." -ForegroundColor Cyan
pnpm run build
if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Local build failed. Please fix build errors before deploying." -ForegroundColor Red
    exit 1
}

Write-Host "✅ Local build successful!" -ForegroundColor Green

# Deploy to Vercel
Write-Host "🚀 Deploying to Vercel..." -ForegroundColor Magenta
Write-Host "Note: You'll be prompted to configure your project settings." -ForegroundColor Yellow

vercel --prod

if ($LASTEXITCODE -eq 0) {
    Write-Host ""
    Write-Host "🎉 Deployment completed successfully!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Next Steps:" -ForegroundColor Cyan
    Write-Host "1. Visit your Vercel dashboard to view your deployment"
    Write-Host "2. Configure environment variables in Vercel dashboard"
    Write-Host "3. Test your deployed application"
    Write-Host "4. Set up custom domain (optional)"
    Write-Host ""
    Write-Host "🔧 Environment Variables to Configure:" -ForegroundColor Yellow
    Write-Host "- MONGODB_URI"
    Write-Host "- JWT_SECRET"
    Write-Host "- JWT_REFRESH_SECRET" 
    Write-Host "- NEXT_PUBLIC_RECAPTCHA_SITE_KEY"
    Write-Host "- RECAPTCHA_SECRET_KEY"
    Write-Host "- SMTP_USER, SMTP_PASS (Gmail)"
    Write-Host "- TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, etc."
    Write-Host ""
    Write-Host "📚 See docs/DEPLOYMENT_GUIDE.md for detailed setup instructions"
} else {
    Write-Host "❌ Deployment failed. Check the error messages above." -ForegroundColor Red
    exit 1
}