# Netlify Deployment Script for Unified Toolkit (PowerShell)
Write-Host "🚀 Starting Netlify deployment preparation..." -ForegroundColor Green

# Check if required tools are installed
function Check-Dependencies {
    Write-Host "📋 Checking dependencies..." -ForegroundColor Yellow
    
    if (!(Get-Command git -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Git is not installed. Please install Git first." -ForegroundColor Red
        exit 1
    }
    
    if (!(Get-Command node -ErrorAction SilentlyContinue)) {
        Write-Host "❌ Node.js is not installed. Please install Node.js first." -ForegroundColor Red
        exit 1
    }
    
    if (!(Get-Command pnpm -ErrorAction SilentlyContinue)) {
        Write-Host "⚠️  pnpm not found. Installing pnpm..." -ForegroundColor Yellow
        npm install -g pnpm
    }
    
    Write-Host "✅ All dependencies are available." -ForegroundColor Green
}

# Install project dependencies
function Install-Dependencies {
    Write-Host "📦 Installing project dependencies..." -ForegroundColor Yellow
    pnpm install
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Failed to install dependencies." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✅ Dependencies installed successfully." -ForegroundColor Green
}

# Build the project
function Build-Project {
    Write-Host "🔨 Building the project..." -ForegroundColor Yellow
    pnpm build
    
    if ($LASTEXITCODE -ne 0) {
        Write-Host "❌ Build failed. Please check the error messages above." -ForegroundColor Red
        exit 1
    }
    
    Write-Host "✅ Project built successfully." -ForegroundColor Green
}

# Prepare for Git deployment
function Prepare-Git {
    Write-Host "📝 Preparing Git repository..." -ForegroundColor Yellow
    
    # Add all files
    git add .
    
    # Check if there are changes to commit
    $changes = git diff --staged --name-only
    if (!$changes) {
        Write-Host "ℹ️  No changes to commit." -ForegroundColor Cyan
    }
    else {
        Write-Host "💾 Committing changes..." -ForegroundColor Yellow
        $commitMessage = "Prepare for Netlify deployment - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        git commit -m $commitMessage
        
        Write-Host "🚀 Pushing to GitHub..." -ForegroundColor Yellow
        git push origin main
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "❌ Failed to push to GitHub. Please check your git configuration." -ForegroundColor Red
            exit 1
        }
        
        Write-Host "✅ Changes pushed to GitHub successfully." -ForegroundColor Green
    }
}

# Display Netlify deployment instructions
function Show-NetlifyInstructions {
    Write-Host ""
    Write-Host "🎉 Project is ready for Netlify deployment!" -ForegroundColor Green
    Write-Host ""
    Write-Host "📋 Next steps:" -ForegroundColor Cyan
    Write-Host "1. Go to https://app.netlify.com/" -ForegroundColor White
    Write-Host "2. Click 'Add new site' → 'Import an existing project'" -ForegroundColor White
    Write-Host "3. Connect your GitHub account and select this repository" -ForegroundColor White
    Write-Host "4. Configure build settings:" -ForegroundColor White
    Write-Host "   - Build command: pnpm build" -ForegroundColor Gray
    Write-Host "   - Publish directory: .next" -ForegroundColor Gray
    Write-Host "5. Set environment variables in Netlify Dashboard:" -ForegroundColor White
    Write-Host "   - MONGODB_URI: Your MongoDB Atlas connection string" -ForegroundColor Gray
    Write-Host "   - JWT_SECRET: A secure 32+ character string" -ForegroundColor Gray
    Write-Host "   - JWT_REFRESH_SECRET: Another secure 32+ character string" -ForegroundColor Gray
    Write-Host "6. Deploy your site!" -ForegroundColor White
    Write-Host ""
    Write-Host "🔧 Fixed Issues:" -ForegroundColor Yellow
    Write-Host "   ✅ Added .env file with default values" -ForegroundColor Green
    Write-Host "   ✅ Updated MongoDB connection to handle missing env vars" -ForegroundColor Green
    Write-Host "   ✅ Configured Next.js for Netlify deployment" -ForegroundColor Green
    Write-Host "   ✅ Added build-time environment variable defaults" -ForegroundColor Green
    Write-Host ""
    Write-Host "🔗 Your site will be available at: https://random-name.netlify.app" -ForegroundColor Yellow
    Write-Host "💡 You can customize the domain in Netlify site settings" -ForegroundColor Cyan
    Write-Host ""
}

# Main execution
function Main {
    Write-Host "🚀 Unified Toolkit - Netlify Deployment Preparation" -ForegroundColor Magenta
    Write-Host "==================================================" -ForegroundColor Magenta
    Write-Host ""
    
    Check-Dependencies
    Install-Dependencies
    Build-Project
    Prepare-Git
    Show-NetlifyInstructions
    
    Write-Host "🎉 Deployment preparation completed successfully!" -ForegroundColor Green
}

# Run the main function
Main
