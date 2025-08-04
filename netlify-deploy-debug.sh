#!/bin/bash

echo "🔧 Netlify Deployment Debug Script"
echo "================================="

# Check Node.js version
echo "📋 Node.js version:"
node --version

# Check pnpm version
echo "📋 pnpm version:"
pnpm --version

# Install dependencies
echo "📦 Installing dependencies..."
pnpm install --frozen-lockfile

# Check if .env exists
if [ -f ".env" ]; then
    echo "✅ .env file exists"
else
    echo "⚠️  .env file missing - creating default"
    cat > .env << EOF
MONGODB_URI=mongodb://localhost:27017/unified-toolkit-build
JWT_SECRET=build-time-jwt-secret-change-in-production
JWT_REFRESH_SECRET=build-time-refresh-secret-change-in-production
NEXT_PUBLIC_SITE_URL=https://app.netlify.com
EOF
fi

# Run build
echo "🏗️  Building application..."
pnpm build

echo "✅ Build completed successfully!"
