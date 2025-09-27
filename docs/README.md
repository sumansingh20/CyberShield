# 🛡️ CyberShield - Professional Cybersecurity Testing Platform

A comprehensive, professional-grade cybersecurity testing platform built for penetration testers, security researchers, and cybersecurity professionals. Features real network scanning capabilities, advanced authentication with 2FA, and a modern dark-themed UI.

<div align="center">

[![Next.js](https://img.shields.io/badge/Next.js-15.5.3-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-Atlas-green?style=for-the-badge&logo=mongodb)](https://www.mongodb.com/)
[![Vercel](https://img.shields.io/badge/Vercel-Ready-black?style=for-the-badge&logo=vercel)](https://vercel.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

**[🚀 Live Demo](https://cybershield.vercel.app) • [📖 Quick Start](#-quick-start) • [🔧 Deployment](#-deployment)**

</div>

---

## ✨ Key Features

### 🔐 Advanced Authentication
- **JWT Authentication** with refresh tokens
- **Two-Factor Authentication (2FA)** using TOTP (Google Authenticator, Authy)
- **QR Code Setup** for easy 2FA configuration
- **Backup Codes** for account recovery
- **Activity Logging** for security monitoring
- **Password Reset** with secure email tokens

### 🛠️ Security Tools Suite
- **Network Scanner** - Real TCP port scanning with service detection
- **DNS Lookup** - Comprehensive DNS record analysis
- **WHOIS Lookup** - Domain registration and ownership information
- **Subdomain Enumeration** - Discover subdomains using multiple techniques
- **HTTP Headers Analysis** - Security header inspection and analysis
- **Vulnerability Scanner** - Automated security assessment tools
- **Nmap Integration** - Professional network discovery and security auditing

### 🎨 Modern UI/UX
- **Multiple Theme Support** - Light, Dark, Cyberpunk, Matrix, Hacker, Neon, Terminal
- **Responsive Design** - Works perfectly on desktop, tablet, and mobile
- **Real-time Terminal Output** - Live command execution feedback
- **Glass Morphism Effects** - Modern backdrop blur and transparency
- **Professional Dashboard** - Comprehensive user activity and statistics

### 🔧 Technical Excellence
- **Next.js 15** with App Router and Server Components
- **TypeScript** for type safety and better development experience
- **MongoDB Atlas** integration with optimized queries
- **Real Network Functionality** - Actual TCP connections and network requests
- **Production Ready** - Optimized build configuration and error handling

---

## 🚀 Quick Start

### Prerequisites
- **Node.js 18+** 
- **pnpm** (recommended) or npm
- **MongoDB Atlas account** (free tier available)
- **Git**

### Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/sumansingh20/CyberShield.git
   cd CyberShield
   ```

2. **Install Dependencies**
   ```bash
   pnpm install
   ```

3. **Environment Configuration**
   ```bash
   cp .env.example .env.local
   ```
   
   Edit `.env.local` with your configuration:
   ```env
   # Database
   MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/cybershield
   
   # Authentication
   JWT_SECRET=your-super-secure-jwt-secret-256-bits
   
   # Email (Optional - for password reset)
   EMAIL_HOST=smtp.gmail.com
   EMAIL_PORT=587
   EMAIL_USER=your-email@gmail.com
   EMAIL_PASS=your-app-password
   
   # reCAPTCHA (Optional - for additional security)
   RECAPTCHA_SITE_KEY=your-recaptcha-site-key
   RECAPTCHA_SECRET_KEY=your-recaptcha-secret-key
   ```

4. **Start Development Server**
   ```bash
   pnpm dev
   ```

5. **Access the Application**
   Open [http://localhost:3000](http://localhost:3000) in your browser

### First Time Setup

1. **Register an Account** at `/register`
2. **Set up 2FA** (recommended) at `/2fa-setup`
3. **Explore Security Tools** at `/tools`
4. **View Activity Logs** at `/activity`

---

## 🛠️ Available Security Tools

### Network Analysis
- **Port Scanner** - TCP port scanning with service detection
- **Network Scanner** - Comprehensive network discovery
- **DNS Lookup** - A, AAAA, MX, TXT, NS, CNAME record resolution

### Domain Intelligence
- **WHOIS Lookup** - Domain registration and ownership details
- **Subdomain Enumeration** - Discover subdomains using DNS and web crawling
- **HTTP Headers** - Analyze security headers and server information

### Security Assessment
- **Vulnerability Scanner** - Automated security testing
- **HTTP Analysis** - Request/response inspection
- **SSL/TLS Analysis** - Certificate and encryption assessment

---

## 🚀 Deployment

### Vercel (Recommended)

1. **Fork the Repository** on GitHub
2. **Connect to Vercel**:
   - Go to [vercel.com](https://vercel.com)
   - Import your GitHub repository
   - Configure environment variables
   - Deploy automatically

3. **Environment Variables in Vercel**:
   ```
   MONGODB_URI=mongodb+srv://...
   JWT_SECRET=your-jwt-secret
   EMAIL_HOST=smtp.gmail.com
   EMAIL_PORT=587
   EMAIL_USER=your-email
   EMAIL_PASS=your-password
   ```

---

## 🔧 Configuration

### MongoDB Setup
1. Create a [MongoDB Atlas](https://cloud.mongodb.com) account
2. Create a new cluster (free tier available)
3. Create a database user with read/write permissions
4. Get your connection string and add it to `.env.local`

### 2FA Setup
Two-Factor Authentication works with any TOTP app:
- Google Authenticator
- Authy
- Microsoft Authenticator
- 1Password
- Bitwarden

---

## �️ Security Features

### Authentication Security
- **Secure Password Hashing** with bcryptjs
- **JWT Token Validation** with expiration
- **2FA Protection** using TOTP standards
- **Rate Limiting** on authentication endpoints
- **Activity Logging** for security monitoring

### Application Security
- **Input Sanitization** and validation
- **CORS Protection** for API endpoints
- **Secure Headers** implementation
- **Environment Variable Protection**
- **Error Handling** without information disclosure

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Legal Disclaimer

**IMPORTANT**: This tool is designed for authorized security testing and educational purposes only. Users are responsible for ensuring they have proper authorization before testing any systems or networks. The developers are not responsible for any misuse of this software.

### Ethical Use Guidelines
- Only test systems you own or have explicit permission to test
- Respect rate limits and don't overload target systems
- Follow responsible disclosure practices for any vulnerabilities found
- Comply with local laws and regulations regarding security testing

---

<div align="center">

**Built with ❤️ by [Suman Singh](https://github.com/sumansingh20)**

[⭐ Star this repository](https://github.com/sumansingh20/CyberShield) • [🐛 Report Bug](https://github.com/sumansingh20/CyberShield/issues) • [💡 Request Feature](https://github.com/sumansingh20/CyberShield/issues)

</div>
