# CyberShield Vercel Deployment Script (PowerShell)
Write-Host "🚀 Deploying CyberShield to Vercel..." -ForegroundColor Green

# Check if vercel is installed
try {
    vercel --version | Out-Null
    Write-Host "✅ Vercel CLI found" -ForegroundColor Green
} catch {
    Write-Host "📦 Installing Vercel CLI..." -ForegroundColor Yellow
    npm install -g vercel
}

# Check git status
Write-Host "🔍 Checking git status..." -ForegroundColor Blue
$gitStatus = git status --porcelain
if ($gitStatus) {
    Write-Host "⚠️  Uncommitted changes found. Please commit first:" -ForegroundColor Yellow
    Write-Host $gitStatus
    exit 1
}

# Deploy to Vercel
Write-Host "🚀 Deploying to production..." -ForegroundColor Green
vercel --prod

Write-Host ""
Write-Host "✅ Deployment complete!" -ForegroundColor Green
Write-Host ""
Write-Host "📝 Next Steps:" -ForegroundColor Cyan
Write-Host "1. Visit your Vercel dashboard" -ForegroundColor White
Write-Host "2. Go to Project Settings > Environment Variables" -ForegroundColor White
Write-Host "3. Add these REQUIRED variables:" -ForegroundColor White
Write-Host "   - MONGODB_URI (your MongoDB Atlas connection string)" -ForegroundColor Yellow
Write-Host "   - JWT_SECRET (secure random string, 32+ characters)" -ForegroundColor Yellow
Write-Host "   - JWT_REFRESH_SECRET (another secure random string)" -ForegroundColor Yellow
Write-Host "   - NEXT_PUBLIC_APP_URL (your vercel app URL)" -ForegroundColor Yellow
Write-Host "   - NODE_ENV=production" -ForegroundColor Yellow
Write-Host ""
Write-Host "🌐 Your app will be live once environment variables are configured!" -ForegroundColor Green