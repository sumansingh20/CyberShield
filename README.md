# 🛡️ CyberShield - Professional Cybersecurity Platform

<div align="center">

![CyberShield Logo](./public/placeholder-logo.svg)

[![Next.js](https://img.shields.io/badge/Next.js-15.5.3-black)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0+-blue)](https://www.typescriptlang.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green)](https://www.mongodb.com/)
[![Tailwind CSS](https://img.shields.io/badge/Tailwind_CSS-3.4+-38B2AC)](https://tailwindcss.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**A comprehensive cybersecurity platform with real network tools, AI-powered threat detection, and professional-grade penetration testing utilities.**

[🚀 Live Demo](#deployment) | [📖 Documentation](#documentation) | [🛠️ Installation](#installation) | [🔧 Features](#features)

</div>

## 🌟 Overview

CyberShield is a modern, full-stack cybersecurity platform built with Next.js 15 and TypeScript. It provides security professionals with a comprehensive suite of real network tools, vulnerability scanners, and AI-powered threat detection capabilities - all accessible through a beautiful, responsive web interface.

### ✨ Key Highlights

- **🔥 Real Network Operations**: All tools use actual network protocols, not mock data
- **🤖 AI-Powered Security**: Advanced machine learning for threat detection and analysis  
- **⚡ Professional Grade**: Tools trusted by cybersecurity experts worldwide
- **🎨 Modern UI/UX**: Beautiful, responsive interface with real-time updates
- **🔒 Secure by Design**: JWT authentication, MongoDB integration, enterprise security

## 🛠️ Features

### 🎯 Essential Security Tools
- **Network Scanner**: Comprehensive network discovery with ping and TCP socket connections
- **Port Scanner**: Advanced port scanning with service detection  
- **DNS Lookup**: Complete DNS record analysis and zone information
- **WHOIS Lookup**: Domain registration information and ownership details
- **Subdomain Enumeration**: Discover hidden subdomains using Certificate Transparency logs
- **Vulnerability Scanner**: Automated security assessment with HTTP analysis

### ⚔️ Advanced Arsenal
- **Advanced Nmap**: Professional network mapping with stealth techniques
- **HTTP Headers Analyzer**: Security headers and server configuration analysis
- **Directory Buster**: Discover hidden directories and files on web servers
- **OSINT Toolkit**: Information gathering with external threat intelligence
- **Wireless Security**: WiFi network analysis and penetration testing
- **Mobile Security**: Android APK analysis capabilities

### 🎖️ Expert Tools
- **Metasploit Integration**: Professional exploitation framework
- **Burp Suite Interface**: Advanced web application security testing
- **Digital Forensics**: Memory analysis and forensic investigation
- **Cryptography Suite**: Hash cracking and cryptographic analysis

### 🤖 AI Security Suite
- **AI Phishing Detection**: Advanced email and URL threat analysis
- **AI Fraud Detection**: Machine learning fraud detection for financial systems
- **AI Intrusion Detection**: Real-time network intrusion detection
- **AI Threat Intelligence**: Automated threat intelligence gathering
- **AI Security Assistant**: Intelligent security advisory with recommendations

## 🚀 Technology Stack

### Frontend
- **Framework**: Next.js 15.5.3 with App Router
- **Language**: TypeScript 5.0+
- **Styling**: Tailwind CSS 3.4+ with custom components
- **UI Components**: Custom component library with shadcn/ui
- **Icons**: Lucide React icons
- **Animations**: Framer Motion for smooth transitions

### Backend
- **API**: Next.js API Routes with Edge Runtime
- **Database**: MongoDB Atlas with Mongoose ODM
- **Authentication**: JWT with secure HTTP-only cookies
- **Validation**: Zod schema validation
- **Security**: bcrypt password hashing, rate limiting

### Infrastructure
- **Deployment**: Vercel (recommended) or any Node.js hosting
- **Database**: MongoDB Atlas cloud database
- **Email**: Gmail SMTP integration
- **SMS**: Twilio integration for 2FA
- **External APIs**: Certificate Transparency, WHOIS databases

## 📦 Installation

### Prerequisites
- Node.js 18.0 or higher
- npm/yarn/pnpm package manager
- MongoDB Atlas account (or local MongoDB)
- Git

### Quick Start

1. **Clone the repository**
```bash
git clone https://github.com/sumansingh20/CyberShield.git
cd CyberShield
```

2. **Install dependencies**
```bash
pnpm install
# or
npm install
# or  
yarn install
```

3. **Environment Setup**
Create a `.env.local` file in the root directory:

```env
# Database Configuration
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/cybershield?retryWrites=true&w=majority
MONGO_URI=mongodb+srv://username:password@cluster.mongodb.net/cybershield?retryWrites=true&w=majority

# JWT Secrets (generate with openssl rand -hex 32)
JWT_SECRET=your-super-secret-jwt-key-here
JWT_REFRESH_SECRET=your-refresh-secret-key-here

# Application Configuration
NODE_ENV=development
NEXT_PUBLIC_APP_URL=http://localhost:3000
BASE_URL=http://localhost:3000

# Optional: Email & SMS Configuration
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=your-email@gmail.com
SMTP_PASS=your-app-password
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=+1234567890
```

4. **Run the development server**
```bash
pnpm dev
# or
npm run dev
# or
yarn dev
```

5. **Open your browser**
Navigate to [http://localhost:3000](http://localhost:3000)

## 🚀 Deployment

### Deploy to Vercel (Recommended)

1. **Push to GitHub** (already done!)
2. **Connect to Vercel**
   - Visit [vercel.com](https://vercel.com)
   - Import your GitHub repository
   - Add environment variables from your `.env.local`
   - Deploy!

### Deploy to Other Platforms

#### Netlify
```bash
npm run build
npm run export
# Upload dist folder to Netlify
```

#### Docker
```bash
docker build -t cybershield .
docker run -p 3000:3000 cybershield
```

#### Traditional Hosting
```bash
npm run build
npm run start
```

## 📖 Documentation

### Project Structure
```
CyberShield/
├── app/                    # Next.js App Router pages
│   ├── api/               # API routes
│   ├── tools/             # Tool pages
│   └── (auth)/            # Authentication pages
├── src/
│   ├── core/              # Core functionality
│   │   ├── lib/           # Database, models, utilities
│   │   └── types/         # TypeScript type definitions
│   ├── ui/                # UI components and hooks
│   │   ├── components/    # Reusable React components
│   │   ├── hooks/         # Custom React hooks
│   │   └── contexts/      # React Context providers
│   ├── auth/              # Authentication utilities
│   └── security-tools/    # Security tool implementations
├── public/                # Static assets
├── styles/                # Global styles
└── tests/                 # Test files
```

### API Documentation

All API endpoints follow RESTful conventions:

- `GET /api/dashboard/activity` - Fetch recent security activities
- `POST /api/auth/login` - User authentication
- `POST /api/auth/register` - User registration
- `POST /api/tools/network-scanner` - Execute network scan
- `POST /api/tools/vuln-scanner` - Run vulnerability assessment
- `GET /api/tools/dns-lookup` - DNS record lookup
- `GET /api/tools/whois` - WHOIS domain information

### Tool Usage Examples

#### Network Scanner
```javascript
const response = await fetch('/api/tools/network-scanner', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target: '192.168.1.0/24',
    scanType: 'ping',
    ports: '22,80,443'
  })
});
```

#### Vulnerability Scanner
```javascript
const response = await fetch('/api/tools/vuln-scanner', {
  method: 'POST',
  headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({
    target: 'https://example.com',
    scanDepth: 'comprehensive'
  })
});
```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Required | Default |
|----------|-------------|----------|---------|
| `MONGODB_URI` | MongoDB connection string | ✅ | - |
| `JWT_SECRET` | JWT signing secret | ✅ | - |
| `JWT_REFRESH_SECRET` | JWT refresh token secret | ✅ | - |
| `NODE_ENV` | Environment mode | ❌ | development |
| `NEXT_PUBLIC_APP_URL` | Public app URL | ❌ | http://localhost:3000 |
| `SMTP_HOST` | Email server host | ❌ | - |
| `SMTP_PORT` | Email server port | ❌ | 587 |
| `TWILIO_ACCOUNT_SID` | Twilio account SID | ❌ | - |

### Database Setup

1. **Create MongoDB Atlas Cluster**
   - Sign up at [MongoDB Atlas](https://cloud.mongodb.com)
   - Create a new cluster
   - Get connection string

2. **Configure Database Access**
   - Add database user
   - Whitelist IP addresses
   - Update connection string in `.env.local`

## 🧪 Testing

```bash
# Run unit tests
pnpm test

# Run integration tests  
pnpm test:integration

# Run end-to-end tests
pnpm test:e2e

# Run security tests
pnpm test:security
```

## 🤝 Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### Development Setup

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes
4. Run tests: `pnpm test`
5. Commit your changes: `git commit -m 'Add feature'`
6. Push to the branch: `git push origin feature-name`
7. Submit a pull request

### Code Style

- Use TypeScript for all new code
- Follow ESLint configuration
- Use Prettier for formatting
- Write tests for new features
- Document public APIs

## 🛡️ Security

CyberShield takes security seriously:

- **Authentication**: JWT tokens with HTTP-only cookies
- **Authorization**: Role-based access control
- **Encryption**: bcrypt password hashing
- **Rate Limiting**: API endpoint protection
- **Input Validation**: Zod schema validation
- **CSRF Protection**: Cross-site request forgery prevention

### Security Reporting

If you discover a security vulnerability, please email: security@cybershield.dev

## 📊 Performance

- **Lighthouse Score**: 95+ performance rating
- **Core Web Vitals**: Optimized for speed and user experience
- **Bundle Size**: Code splitting and lazy loading
- **Caching**: Aggressive caching strategies
- **CDN**: Static asset optimization

## 🌍 Browser Support

- Chrome 90+
- Firefox 88+
- Safari 14+
- Edge 90+

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Team

- **Suman Singh** - Lead Developer & Security Architect
- **Contributors** - See [Contributors](https://github.com/sumansingh20/CyberShield/contributors)

## 🙏 Acknowledgments

- [Next.js](https://nextjs.org/) - The React framework
- [Tailwind CSS](https://tailwindcss.com/) - Utility-first CSS framework
- [MongoDB](https://www.mongodb.com/) - Database platform
- [Vercel](https://vercel.com/) - Deployment platform
- [Lucide](https://lucide.dev/) - Beautiful icons

## 📞 Support

- **Documentation**: [docs.cybershield.dev](https://docs.cybershield.dev)
- **Issues**: [GitHub Issues](https://github.com/sumansingh20/CyberShield/issues)
- **Discussions**: [GitHub Discussions](https://github.com/sumansingh20/CyberShield/discussions)
- **Email**: support@cybershield.dev

## 🗺️ Roadmap

### 2024 Q4
- [ ] Advanced AI threat detection
- [ ] Real-time collaboration features
- [ ] Mobile app (React Native)
- [ ] Enterprise SSO integration

### 2025 Q1
- [ ] Kubernetes security scanning
- [ ] Cloud security posture management
- [ ] Advanced reporting and analytics
- [ ] Multi-language support

---

<div align="center">

**⭐ Star this repo if you find it useful!**

Made with ❤️ by the CyberShield team

</div>