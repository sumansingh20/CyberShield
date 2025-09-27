#!/bin/bash

# CyberShield Deployment Script
# This script helps deploy to both Vercel and Netlify

echo "🚀 CyberShield Deployment Helper"
echo "================================="

# Check if we're in the right directory
if [ ! -f "package.json" ]; then
    echo "❌ Error: Please run this script from the project root directory"
    exit 1
fi

# Install dependencies
echo "📦 Installing dependencies..."
pnpm install

# Run build to ensure everything works
echo "🔨 Building project..."
pnpm run build

if [ $? -ne 0 ]; then
    echo "❌ Build failed! Please fix the errors before deploying."
    exit 1
fi

echo "✅ Build successful!"
echo ""
echo "🌐 Ready for deployment!"
echo ""
echo "Deployment Options:"
echo "1. Vercel (Recommended for Next.js):"
echo "   - Install: npm i -g vercel"
echo "   - Deploy: vercel --prod"
echo ""
echo "2. Netlify:"
echo "   - Install: npm i -g netlify-cli"
echo "   - Deploy: netlify deploy --prod --dir=.next"
echo ""
echo "📋 Don't forget to set environment variables:"
echo "   - MONGODB_URI"
echo "   - JWT_SECRET"
echo "   - JWT_REFRESH_SECRET"
echo "   - NEXT_PUBLIC_RECAPTCHA_SITE_KEY"
echo "   - RECAPTCHA_SECRET_KEY"
echo "   - SMTP_* variables"
echo "   - TWILIO_* variables"