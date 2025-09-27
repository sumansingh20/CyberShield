#!/bin/bash

# CyberShield Vercel Deployment Script
echo "🚀 Deploying CyberShield to Vercel..."

# Check if vercel is installed
if ! command -v vercel &> /dev/null; then
    echo "Installing Vercel CLI..."
    npm install -g vercel
fi

# Deploy to Vercel
echo "📦 Building and deploying..."
vercel --prod

echo "✅ Deployment complete!"
echo "📝 Don't forget to configure environment variables in Vercel dashboard"
echo "🌐 Visit your Vercel dashboard to set up:"
echo "   - MONGODB_URI"
echo "   - JWT_SECRET" 
echo "   - JWT_REFRESH_SECRET"
echo "   - NEXT_PUBLIC_APP_URL"