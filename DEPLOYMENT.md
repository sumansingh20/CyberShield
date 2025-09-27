# 🚀 CyberShield Deployment Guide

This guide will help you deploy CyberShield to various platforms.

## 📋 Prerequisites

Before deploying, ensure you have:

- ✅ GitHub repository with your code
- ✅ MongoDB Atlas cluster set up
- ✅ Environment variables configured
- ✅ Domain name (optional)

## 🌐 Deploy to Vercel (Recommended)

Vercel provides the best Next.js hosting experience with zero configuration.

### Step 1: Prepare Your Repository
Your code is already pushed to GitHub at: `https://github.com/sumansingh20/CyberShield.git`

### Step 2: Connect to Vercel

1. **Visit Vercel**
   - Go to [vercel.com](https://vercel.com)
   - Sign up/login with your GitHub account

2. **Import Repository**
   - Click "New Project"
   - Import `sumansingh20/CyberShield`
   - Vercel will auto-detect Next.js

3. **Configure Environment Variables**
   Add these in Vercel dashboard:

   ```env
   # Database
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/cybershield
   MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/cybershield
   
   # JWT Secrets (generate new ones for production!)
   JWT_SECRET=your-production-jwt-secret-32-chars-min
   JWT_REFRESH_SECRET=your-production-refresh-secret-32-chars-min
   
   # Application
   NODE_ENV=production
   NEXT_PUBLIC_APP_URL=https://your-app.vercel.app
   BASE_URL=https://your-app.vercel.app
   
   # Optional Services
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your-email@gmail.com
   SMTP_PASS=your-app-password
   TWILIO_ACCOUNT_SID=your-twilio-sid
   TWILIO_AUTH_TOKEN=your-twilio-token
   TWILIO_PHONE_NUMBER=+1234567890
   ```

4. **Deploy**
   - Click "Deploy"
   - Vercel will build and deploy automatically
   - Your app will be live at `https://cybershield-xxx.vercel.app`

### Step 3: Custom Domain (Optional)

1. **Add Domain in Vercel**
   - Go to Project Settings > Domains
   - Add your custom domain
   - Configure DNS records as shown

2. **Update Environment Variables**
   ```env
   NEXT_PUBLIC_APP_URL=https://yourdomain.com
   BASE_URL=https://yourdomain.com
   ```

## 🔷 Deploy to Netlify

### Step 1: Build Settings
```bash
# Build command
npm run build

# Publish directory  
.next

# Functions directory
netlify/functions
```

### Step 2: Environment Variables
Add the same variables as Vercel in Netlify dashboard.

### Step 3: Deploy
```bash
# Install Netlify CLI
npm install -g netlify-cli

# Deploy
netlify deploy --build
netlify deploy --prod
```

## 🐳 Deploy with Docker

### Step 1: Build Image
```bash
# Build the Docker image
docker build -t cybershield .

# Run locally
docker run -p 3000:3000 --env-file .env.local cybershield
```

### Step 2: Deploy to Cloud

#### Docker Hub + Cloud Provider
```bash
# Tag and push to Docker Hub
docker tag cybershield username/cybershield:latest
docker push username/cybershield:latest

# Deploy to any cloud provider that supports Docker
```

## ☁️ Deploy to Cloud Providers

### AWS (Amazon Web Services)

#### Using AWS Amplify
1. Connect your GitHub repository
2. Configure build settings:
   ```yaml
   version: 1
   frontend:
     phases:
       preBuild:
         commands:
           - npm install
       build:
         commands:
           - npm run build
     artifacts:
       baseDirectory: .next
       files:
         - '**/*'
   ```

#### Using AWS EC2
```bash
# SSH to your EC2 instance
ssh -i your-key.pem ubuntu@your-server-ip

# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Clone and setup
git clone https://github.com/sumansingh20/CyberShield.git
cd CyberShield
npm install
npm run build

# Start with PM2
npm install -g pm2
pm2 start npm --name "cybershield" -- start
pm2 save
pm2 startup
```

### Google Cloud Platform

#### Using App Engine
Create `app.yaml`:
```yaml
runtime: nodejs18

env_variables:
  NODE_ENV: production
  MONGODB_URI: your-mongodb-uri
  JWT_SECRET: your-jwt-secret
  JWT_REFRESH_SECRET: your-refresh-secret

automatic_scaling:
  min_instances: 1
  max_instances: 10
```

Deploy:
```bash
gcloud app deploy
```

### Microsoft Azure

#### Using App Service
```bash
# Install Azure CLI
az login

# Create resource group
az group create --name cybershield-rg --location eastus

# Create app service plan  
az appservice plan create --name cybershield-plan --resource-group cybershield-rg --sku B1 --is-linux

# Create web app
az webapp create --resource-group cybershield-rg --plan cybershield-plan --name cybershield-app --runtime "NODE|18-lts"

# Deploy from GitHub
az webapp deployment source config --name cybershield-app --resource-group cybershield-rg --repo-url https://github.com/sumansingh20/CyberShield --branch main
```

## 🔧 Post-Deployment Setup

### 1. Test Your Deployment

Visit your deployed app and verify:
- ✅ Homepage loads correctly
- ✅ Login/registration works
- ✅ Database connections are successful
- ✅ Security tools function properly
- ✅ All API endpoints respond

### 2. Security Checklist

- ✅ Use strong, unique JWT secrets in production
- ✅ Enable HTTPS (handled by most platforms automatically)
- ✅ Configure proper CORS headers
- ✅ Set up monitoring and error tracking
- ✅ Enable rate limiting
- ✅ Review and secure all API endpoints

### 3. Performance Optimization

- ✅ Enable compression
- ✅ Configure CDN for static assets
- ✅ Set up database indexing
- ✅ Monitor performance metrics
- ✅ Set up caching strategies

### 4. Monitoring & Analytics

Consider setting up:
- Error tracking (Sentry)
- Performance monitoring (Vercel Analytics)
- User analytics (Google Analytics)
- Uptime monitoring (UptimeRobot)

## 🔍 Troubleshooting

### Common Issues

#### Build Failures
```bash
# Clear cache and rebuild
rm -rf .next node_modules
npm install
npm run build
```

#### Database Connection Issues
- Verify MongoDB Atlas IP whitelist
- Check connection string format
- Ensure database user has proper permissions

#### Environment Variables
- Double-check all required variables are set
- Verify no typos in variable names
- Ensure secrets are properly encoded

#### API Route Issues
- Check function timeout limits
- Verify proper error handling
- Monitor function logs

### Getting Help

- 📖 Check the [main README](README.md)
- 🐛 Open an [issue on GitHub](https://github.com/sumansingh20/CyberShield/issues)
- 💬 Join our [discussions](https://github.com/sumansingh20/CyberShield/discussions)

## 🎉 Congratulations!

Your CyberShield platform should now be live and accessible to users worldwide!

---

**Next Steps:**
- Set up monitoring and alerts
- Configure backups
- Plan for scaling
- Add custom domain
- Set up CI/CD pipeline