# Render Deployment Guide for CyberShield

## Render Deployment Steps

### 1. Push Code to GitHub
Make sure your latest code is pushed to GitHub repository.

### 2. Connect to Render
1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Click "New +" → "Web Service"
3. Connect your GitHub account
4. Select `CyberShield` repository
5. Choose the `main` branch

### 3. Build & Start Commands
```bash
Build Command: pnpm install && pnpm run build
Start Command: pnpm run start
```

### 4. Environment Variables
Add these environment variables in Render dashboard:

**Required Variables:**
```
MONGODB_URI=[Your MongoDB Atlas connection string from .env.local]
JWT_SECRET=[Auto-generated secure key]
JWT_REFRESH_SECRET=[Auto-generated secure key]
NODE_ENV=production
```

**Optional Variables (for full functionality):**
```
NEXT_PUBLIC_RECAPTCHA_SITE_KEY=[Get from .env.local]
RECAPTCHA_SECRET_KEY=[Get from .env.local]
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=[Your Gmail address]
SMTP_PASS=[Your Gmail app password]
SMTP_FROM=[Your Gmail address]
TWILIO_ACCOUNT_SID=[Get from .env.local]
TWILIO_AUTH_TOKEN=[Get from .env.local]
TWILIO_API_KEY=[Get from .env.local]
TWILIO_API_SECRET=[Get from .env.local]
TWILIO_PHONE_NUMBER=[Get from .env.local]
TWILIO_VERIFY_SERVICE_SID=[Get from .env.local]
DEFAULT_ADMIN_PASSWORD=[Set secure password]
```

### 5. Deploy Settings
- **Name**: cybershield-platform
- **Region**: Choose closest to your users
- **Branch**: main
- **Root Directory**: (leave empty)
- **Build Command**: `pnpm install && pnpm run build`
- **Start Command**: `pnpm run start`
- **Node Version**: 20
- **Auto-Deploy**: Enabled

### 6. Post-Deployment
After successful deployment:
1. Your app will be available at: `https://cybershield-platform.onrender.com`
2. Test login with: `sanya@cybershield.com` / `sanya123`
3. Verify all security tools are working

## Manual Deployment via CLI

If you prefer command line deployment:

```bash
# Install Render CLI (if not already installed)
npm install -g @render/cli

# Login to Render
render login

# Deploy from current directory
render deploy
```

## Troubleshooting

**Common Issues:**
1. **Build Fails**: Check if all dependencies are in package.json
2. **Environment Variables**: Make sure all required env vars are set
3. **Database Connection**: Verify MongoDB URI is correct
4. **Memory Issues**: Upgrade to paid plan if needed

**Health Check:**
- API Health: `https://your-app.onrender.com/api/test`
- Database: Check MongoDB Atlas connection logs
- Logs: View in Render dashboard under "Logs" tab

## Next Steps
1. Set up custom domain (optional)
2. Configure SSL certificate (automatic)
3. Set up monitoring and alerts
4. Configure backup strategies