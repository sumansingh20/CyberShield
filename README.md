# CyberShield - Professional Cybersecurity Platform

![CyberShield Logo](./public/placeholder-logo.svg)

[![Next.js](https://img.shields.io/badge/Next.js-15.5.3-black)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)](https://www.typescriptlang.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green)](https://www.mongodb.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4+-38B2AC)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A comprehensive cybersecurity platform with real network tools, AI-powered threat detection, and professional-grade penetration testing utilities.**

## Table of Contents

- [Overview](#overview)
- [Key Features](#key-features)
- [Tech Stack](#tech-stack)
- [Quick Start](#quick-start)
- [Deployment](#deployment)
- [Security Tools](#security-tools)
- [Environment Variables](#environment-variables)
- [Contributing](#contributing)
- [Support](#support)
- [Team](#team)

## Overview

CyberShield is a modern, full-stack cybersecurity platform built with Next.js 15 and TypeScript. It provides security professionals with a comprehensive suite of real network tools, vulnerability scanners, and AI-powered threat detection capabilities - all accessible through a beautiful, responsive web interface.

## Key Features

### Essential Security Tools

- **Network Scanner**: Comprehensive network discovery with ping and TCP socket connections
- **Port Scanner**: Advanced port scanning with service detection
- **DNS Lookup**: Complete DNS record analysis and zone information
- **WHOIS Lookup**: Domain registration information and ownership details
- **Subdomain Enumeration**: Discover hidden subdomains using Certificate Transparency logs
- **Vulnerability Scanner**: Automated security assessment with HTTP analysis

### Advanced Arsenal

- **Advanced Nmap**: Professional network mapping with stealth techniques
- **HTTP Headers Analyzer**: Security headers and server configuration analysis
- **Directory Buster**: Discover hidden directories and files on web servers
- **WAF Bypass**: Advanced techniques to bypass Web Application Firewalls
- **Wireless Scanner**: WiFi network analysis and security assessment
- **Ping Sweep**: Network range discovery and host enumeration

### Expert Tools

- **Metasploit Integration**: Professional exploitation framework
- **Payload Generator**: Custom payload creation for penetration testing
- **Social Engineering**: Advanced social engineering attack simulation
- **SQL Injection Scanner**: Automated SQL injection vulnerability detection

### AI Security Suite

- **AI Phishing Detection**: Advanced email and URL threat analysis
- **AI Threat Intelligence**: Real-time threat detection and analysis
- **AI Security Assistant**: Intelligent security recommendations
- **AI Fraud Detection**: Financial fraud detection and prevention

## Tech Stack

### Frontend

- **Framework**: Next.js 15.5.3 with App Router
- **Language**: TypeScript 5.0+
- **Styling**: Tailwind CSS 3.4+ with custom themes
- **UI Components**: Radix UI with shadcn/ui
- **State Management**: React Hooks with Context API
- **Authentication**: JWT with refresh tokens

### Backend

- **API**: Next.js API Routes with Edge Runtime
- **Database**: MongoDB Atlas with Mongoose ODM
- **Authentication**: bcryptjs password hashing
- **Security**: Rate limiting, CORS, input validation
- **Email**: Nodemailer with Gmail SMTP
- **SMS**: Twilio integration for 2FA

### Infrastructure

- **Deployment**: Vercel (recommended) or any Node.js hosting
- **Database**: MongoDB Atlas (cloud) or self-hosted MongoDB
- **File Storage**: Local storage with planned cloud integration
- **Monitoring**: Built-in logging and error tracking

## Quick Start

### Prerequisites

- Node.js 18.0 or higher
- MongoDB Atlas account or local MongoDB installation
- Gmail account for email notifications (optional)
- Twilio account for SMS 2FA (optional)

### Installation

1. **Clone the repository**

   ```bash
   git clone https://github.com/sumansingh20/CyberShield.git
   cd CyberShield
   ```

2. **Install dependencies**

   ```bash
   npm install
   # or
   pnpm install
   # or
   yarn install
   ```

3. **Environment Setup**

   Create a `.env.local` file in the root directory:

   ```env
   # Database Configuration
   MONGODB_URI=your_mongodb_connection_string
   
   # JWT Secrets
   JWT_SECRET=your_jwt_secret_key
   JWT_REFRESH_SECRET=your_jwt_refresh_secret
   
   # Optional: Email Configuration (Gmail)
   SMTP_HOST=smtp.gmail.com
   SMTP_PORT=587
   SMTP_USER=your_gmail_address
   SMTP_PASS=your_gmail_app_password
   
   # Optional: Twilio SMS (for 2FA)
   TWILIO_ACCOUNT_SID=your_twilio_sid
   TWILIO_AUTH_TOKEN=your_twilio_token
   TWILIO_PHONE_NUMBER=your_twilio_phone
   ```

4. **Run the development server**

   ```bash
   npm run dev
   # or
   pnpm dev
   # or
   yarn dev
   ```

5. **Open your browser**

   Navigate to <http://localhost:3000> to see the application.

## Deployment

### Vercel (Recommended)

1. Push your code to GitHub
2. Connect your repository to Vercel
3. Configure environment variables in Vercel dashboard
4. Deploy automatically on push to main branch

### Netlify

```bash
npm run build
npm run export
```

Then deploy the `out` folder to Netlify.

### Docker

```bash
docker build -t cybershield .
docker run -p 3000:3000 cybershield
```

### Traditional Hosting

```bash
npm run build
npm start
```

## Security Tools

### Network Scanner

```javascript
const scanResult = await fetch('/api/tools/network-scanner', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target: '192.168.1.0/24',
    ports: '22,80,443,3389',
    timeout: 5000
  })
});
```

### Vulnerability Scanner

```javascript
const vulnScan = await fetch('/api/tools/vuln-scanner', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target: 'https://example.com',
    scanType: 'comprehensive'
  })
});
```

## Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `MONGODB_URI` | MongoDB connection string | ✅ | - |
| `JWT_SECRET` | JWT signing secret | ✅ | - |
| `JWT_REFRESH_SECRET` | JWT refresh token secret | ✅ | - |
| `SMTP_HOST` | Email server hostname | ❌ | smtp.gmail.com |
| `SMTP_PORT` | Email server port | ❌ | 587 |
| `SMTP_USER` | Email username | ❌ | - |
| `SMTP_PASS` | Email password/app password | ❌ | - |
| `TWILIO_ACCOUNT_SID` | Twilio account SID | ❌ | - |
| `TWILIO_AUTH_TOKEN` | Twilio auth token | ❌ | - |
| `TWILIO_PHONE_NUMBER` | Twilio phone number | ❌ | - |
| `NEXT_PUBLIC_APP_URL` | Public app URL | ❌ | <http://localhost:3000> |

## Contributing

We welcome contributions from the community! Please read our contributing guidelines before submitting pull requests.

### Development Setup

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

### Code Style

- Use TypeScript for all new code
- Follow ESLint configuration
- Use Prettier for code formatting
- Write meaningful commit messages

## Security

This platform is designed for authorized security testing and educational purposes only. Users must ensure they have proper authorization before testing any systems.

If you discover a security vulnerability, please email: <security@cybershield.dev>

## Support

- **Documentation**: Check our detailed documentation
- **Issues**: Report bugs on GitHub Issues
- **Discussions**: Join community discussions
- **Email**: <support@cybershield.dev>

## Roadmap

### 2024 Q4

- [ ] Advanced AI threat detection
- [ ] Custom payload templates
- [ ] Team collaboration features
- [ ] Advanced reporting system

### 2025 Q1

- [ ] Mobile application
- [ ] Cloud integration
- [ ] Enterprise features
- [ ] Advanced analytics

## Team

- **Dynamic Trio** - Lead Developers & Security Architects
- **Contributors** - See [Contributors](https://github.com/sumansingh20/CyberShield/contributors)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Next.js team for the amazing framework
- MongoDB team for the robust database
- Tailwind CSS for the utility-first styling
- Radix UI for accessible components
- Open source security community

---

Made with ❤️ by Dynamic Trio
 
 