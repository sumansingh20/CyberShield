#!/bin/bash

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${GREEN}Preparing for deployment...${NC}"

# Clean build artifacts
echo -e "${YELLOW}Cleaning previous builds...${NC}"
rm -rf .next
rm -rf dist
rm -rf out

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
pnpm install

# Build the application
echo -e "${YELLOW}Building the application...${NC}"
pnpm run build

# Create deployment package
echo -e "${YELLOW}Creating deployment package...${NC}"
mkdir -p deploy
cp -r .next package.json pnpm-lock.yaml deploy/

# Create environment files
echo -e "${YELLOW}Creating environment files...${NC}"
cat > deploy/.env.production << EOL
NODE_ENV=production
MONGODB_URI=your_mongodb_uri
JWT_SECRET=your_jwt_secret
SMTP_HOST=your_smtp_host
SMTP_PORT=587
SMTP_USER=your_smtp_user
SMTP_PASS=your_smtp_password
TWILIO_ACCOUNT_SID=your_twilio_sid
TWILIO_AUTH_TOKEN=your_twilio_token
TWILIO_FROM_NUMBER=your_twilio_number
RECAPTCHA_SITE_KEY=your_recaptcha_site_key
RECAPTCHA_SECRET_KEY=your_recaptcha_secret_key
EOL

echo -e "${GREEN}Deployment package ready!${NC}"
echo -e "You can now deploy the 'deploy' directory to your hosting service."