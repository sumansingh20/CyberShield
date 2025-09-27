# 🚀 CyberShield Vercel Deployment Guide

## Prerequisites

1. **Vercel Account**: Sign up at [vercel.com](https://vercel.com)
2. **GitHub Repository**: Your code is already on GitHub
3. **Environment Variables**: Required for production deployment

## 🛠️ Environment Variables Setup

Before deploying, you need to configure the following environment variables in Vercel:

### Required Variables:

```env
# Database
MONGODB_URI=your_mongodb_connection_string

# JWT Secrets
JWT_SECRET=your_jwt_secret_key_here
JWT_REFRESH_SECRET=your_jwt_refresh_secret_here

# Google ReCaptcha
NEXT_PUBLIC_RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key

# Twilio (for SMS/Voice OTP)
TWILIO_ACCOUNT_SID=your_twilio_account_sid
TWILIO_AUTH_TOKEN=your_twilio_auth_token
TWILIO_VERIFY_SERVICE_SID=your_twilio_verify_service_sid
TWILIO_PHONE_NUMBER=your_twilio_phone_number

# Gmail (for Email OTP)
GMAIL_USER=your_gmail_address
GMAIL_APP_PASSWORD=your_gmail_app_password

# Production Environment
NODE_ENV=production
NEXT_PUBLIC_API_URL=https://your-vercel-domain.vercel.app
```

## 📦 Deployment Steps

### Method 1: Vercel Dashboard (Recommended)

1. **Connect GitHub Repository**:
   - Go to [vercel.com/dashboard](https://vercel.com/dashboard)
   - Click "Add New..." → "Project"
   - Import your GitHub repository: `sumansingh20/CyberShield`

2. **Configure Project Settings**:
   - **Framework Preset**: Next.js
   - **Build Command**: `pnpm run build`
   - **Output Directory**: `.next`
   - **Install Command**: `pnpm install`
   - **Development Command**: `pnpm run dev`

3. **Set Environment Variables**:
   - Go to Project Settings → Environment Variables
   - Add all required variables listed above
   - Set them for "Production", "Preview", and "Development"

4. **Deploy**:
   - Click "Deploy"
   - Vercel will automatically build and deploy your project

### Method 2: Vercel CLI

```bash
# Install Vercel CLI
npm i -g vercel

# Login to Vercel
vercel login

# Deploy
vercel

# Follow the prompts:
# - Link to existing project or create new
# - Configure build settings
```

## 🔧 Configuration Files

Your project includes these deployment configurations:

- `vercel.json`: Vercel-specific settings
- `next.config.mjs`: Next.js configuration
- `package.json`: Scripts and dependencies

## 🔒 Security Setup

### 1. MongoDB Atlas Setup
- Create a MongoDB Atlas cluster
- Whitelist Vercel's IP ranges or use 0.0.0.0/0 (less secure)
- Get connection string and add to `MONGODB_URI`

### 2. Generate JWT Secrets
```bash
# Generate secure random strings
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

### 3. ReCaptcha Setup
- Go to [Google reCAPTCHA](https://www.google.com/recaptcha/admin)
- Create new site (v2 checkbox)
- Add your Vercel domain
- Get site key and secret key

### 4. Twilio Setup
- Create [Twilio account](https://www.twilio.com)
- Create Verify Service
- Get Account SID, Auth Token, and Service SID
- Buy phone number for SMS

### 5. Gmail App Password
- Enable 2-Factor Authentication on Gmail
- Generate App Password for SMTP access

## 🚀 Post-Deployment

### 1. Verify Deployment
```bash
# Check if deployment is successful
curl https://your-domain.vercel.app/api/health
```

### 2. Create Admin User
Your deployment includes an admin setup script. After deployment, you can use the Vercel CLI to run:

```bash
vercel env pull .env.local
node src/deployment/scripts/create-admin.js
```

### 3. Test Authentication
- Test user registration
- Test 2FA setup (SMS, Email, Voice)
- Test all security tools
- Verify admin dashboard

## 🔍 Monitoring & Debugging

### Vercel Functions
- Go to Vercel Dashboard → Functions tab
- Monitor API endpoints performance
- Check error logs

### Build Logs
- Check build logs in Vercel dashboard
- Monitor for any build warnings or errors

## 🔄 Continuous Deployment

Vercel automatically deploys when you push to your main branch:

1. Push changes to GitHub
2. Vercel detects changes
3. Automatically builds and deploys
4. Preview deployments for pull requests

## 📞 Support

If you encounter issues:

1. Check Vercel build logs
2. Verify all environment variables
3. Test API endpoints locally first
4. Check MongoDB connection
5. Verify third-party service configurations

## 🎉 Success!

Your CyberShield platform should now be live at your Vercel URL with:
- ✅ Enhanced 2FA authentication
- ✅ 100+ security tools
- ✅ AI-powered features  
- ✅ Professional dashboard
- ✅ Production-ready performance

Remember to update your environment variables and test all features thoroughly after deployment!