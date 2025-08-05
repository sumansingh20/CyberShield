<div align="center">

# 🛡️ Unified Toolkit for New Pen-Testers

*Your Gateway to Professional Cybersecurity*

[![Next.js](https://img.shields.io/badge/Next.js-14.2.18-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.0-blue?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-green?style=for-the-badge&logo=mongodb)](https://www.mongodb.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](https://opensource.org/licenses/MIT)

[![Build Status](https://img.shields.io/badge/Build-Passing-brightgreen?style=for-the-badge)](https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers)
[![Security](https://img.shields.io/badge/Security-Hardened-red?style=for-the-badge)](https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers)
[![Stars](https://img.shields.io/github/stars/sumansingh20/Unified-Toolkit-for-New-Pen-Testers?style=for-the-badge)](https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers/stargazers)
[![Forks](https://img.shields.io/github/forks/sumansingh20/Unified-Toolkit-for-New-Pen-Testers?style=for-the-badge)](https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers/network)

</div>

---

## 📋 Table of Contents

- [🎯 Project Vision](#-project-vision)
- [🚀 Quick Start](#-quick-start)
- [✨ Key Features](#-key-features)
- [🏗️ System Architecture](#️-system-architecture)
- [🛠️ Installation](#️-installation)
- [📁 Project Structure](#-project-structure)
- [🔧 Configuration](#-configuration)
- [🛠️ API Endpoints](#️-api-endpoints)
- [🔒 Security](#-security)
- [📚 Learning Resources](#-learning-resources)
- [🤝 Contributing](#-contributing)
- [🐛 Troubleshooting](#-troubleshooting)
- [🌟 Roadmap](#-roadmap)
- [📞 Support](#-support)

---

## 🌟 Overview

A **comprehensive, enterprise-grade cybersecurity learning platform** that unifies essential penetration testing tools with modern authentication, real-time scanning capabilities, and an intuitive web interface. Designed specifically for aspiring penetration testers and cybersecurity professionals who need a centralized platform to learn, practice, and master security testing methodologies.

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ and npm/pnpm
- MongoDB 7.0+ (local or Atlas)
- Git

### 30-Second Setup

```bash
# 1. Clone the repository
git clone https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers.git
cd Unified-Toolkit-for-New-Pen-Testers

# 2. Install dependencies
npm install

# 3. Setup environment
cp .env.template .env
# Edit .env with your configuration

# 4. Start the application
npm run dev
```

🎉 **That's it!** Open [http://localhost:3000](http://localhost:3000) and start exploring!

### Demo Account

Try the platform immediately with our demo account:
- **Username**: `user@unified.com`
- **Password**: `user123`

---

## ✨ Key Features

<table>
<tr>
<td width="50%">

### 🔐 Authentication & Security
- Multi-factor authentication (2FA)
- JWT with refresh token rotation
- reCAPTCHA v3 integration
- bcrypt password hashing
- Role-based access control

### 🧰 Security Tools Suite
- **Network**: Nmap, Masscan, DNS tools
- **Web**: Nikto, Nuclei, HTTP analyzers
- **OSINT**: Sublist3r, AssetFinder
- **Advanced**: Metasploit, Burp Suite
- **Expert**: Binary analysis, forensics

</td>
<td width="50%">

### 🖥️ Modern Interface
- Real-time terminal output
- Dark/Light theme support
- Mobile-responsive design
- Progressive Web App (PWA)
- Accessibility (WCAG 2.1 AA)

### 📊 Advanced Features
- Scan result export (PDF, JSON)
- Team collaboration
- Performance monitoring
- Audit logging
- API rate limiting

</td>
</tr>
</table>

---

## � Project Vision

This platform bridges the gap between theoretical cybersecurity knowledge and practical application by providing:

- **🌐 Unified Interface**: All essential penetration testing tools accessible through a single, modern web application
- **📚 Educational Focus**: Structured learning path for new penetration testers with guided tutorials and best practices  
- **🛡️ Enterprise Security**: Production-ready authentication and authorization systems
- **🎯 Real-World Simulation**: Realistic testing environment that mirrors professional penetration testing workflows

---

### High-Level Architecture

```mermaid
graph TB
    A[Client Browser] -->|HTTPS| B[Nginx Reverse Proxy]
    B --> C[Next.js Application]
    C --> D[Authentication Middleware]
    C --> E[API Routes]
    C --> F[Security Tools Engine]
    
    D --> G[JWT Token Service]
    D --> H[2FA Service]
    
    E --> I[MongoDB Database]
    E --> J[Rate Limiter]
    
    F --> K[Nmap Service]
    F --> L[Subdomain Service]
    F --> M[Vulnerability Scanner]
    F --> N[DNS Tools]
    
    H --> O[Email Service]
    H --> P[SMS Service]
    
    I --> Q[User Collection]
    I --> R[Scan Logs Collection]
    I --> S[OTP Collection]
```

### Technology Stack Deep Dive

#### Frontend Layer
- **Next.js 14** with App Router for modern React development
- **TypeScript** for type safety and better developer experience
- **Tailwind CSS** for utility-first styling and responsive design
- **shadcn/ui** for consistent, accessible UI components
- **Framer Motion** for smooth animations and transitions
- **React Hook Form** for efficient form handling and validation

#### Backend Layer
- **Next.js API Routes** for serverless function architecture
- **Node.js Runtime** optimized for security tool execution
- **JWT Authentication** with refresh token rotation
- **bcrypt** for secure password hashing (12 rounds)
- **Rate Limiting** using sliding window algorithm
- **Input Sanitization** with comprehensive validation layers

#### Database Layer
- **MongoDB 7.0** for flexible document storage
- **Mongoose ODM** for schema definition and data modeling
- **Connection Pooling** for optimal performance
- **Indexing Strategy** for fast query execution
- **Data Encryption** at rest and in transit

#### Security Tools Integration
- **Native CLI Wrapping** for direct tool execution
- **Sandboxed Execution** with resource limits
- **Output Parsing** with real-time streaming
- **Error Handling** with graceful degradation
- **Timeout Management** to prevent hanging processes

## ✨ Features Deep Dive

### 🔐 Complete Authentication System

Our authentication system implements enterprise-grade security standards:

- **Multi-Factor Registration**: Email, phone number, and username verification
- **Secure Login**: reCAPTCHA v3 integration with risk assessment scoring
- **Two-Factor Authentication (2FA)**: 
  - Email-based OTP with HTML templates
  - SMS integration via Twilio API
  - Time-based OTP with 5-minute expiration
  - Rate limiting (3 attempts per 15 minutes)
- **Password Security**:
  - bcrypt hashing with 12 salt rounds
  - Password strength validation (8+ chars, mixed case, numbers, symbols)
  - Secure password reset flow with OTP verification
- **Session Management**:
  - JWT access tokens (15-minute expiration)
  - Refresh tokens (7-day expiration with rotation)
  - Automatic token refresh on API calls
  - Secure HttpOnly cookie storage

### 🧰 Integrated Security Tools

#### Network Discovery & Enumeration

**Port Scanner (Nmap Integration)**
- **Scan Types**: TCP Connect, SYN Stealth, UDP, Ping sweeps
- **Port Ranges**: Custom ranges, top ports, all ports (1-65535)
- **Service Detection**: Version detection with OS fingerprinting
- **Output Formats**: XML, JSON, and human-readable formats
- **Performance**: Aggressive, normal, and polite timing templates
- **Safety Features**: Target validation, scan logging, rate limiting

**Subdomain Enumeration**
- **Multiple Sources**: Certificate transparency logs, DNS records, search engines
- **Tools Integrated**: Sublist3r, AssetFinder, DNSRecon
- **Passive Discovery**: Non-intrusive subdomain enumeration
- **Active Verification**: DNS resolution validation
- **Wildcard Detection**: Automatic wildcard domain filtering
- **Output Processing**: Deduplication and sorting

#### Web Application Security

**Vulnerability Scanner**
- **Nikto Integration**: Web server vulnerability assessment
- **Nuclei Templates**: 3000+ community-driven vulnerability templates
- **Custom Checks**: SQL injection, XSS, directory traversal detection
- **SSL/TLS Analysis**: Certificate validation and cipher suite testing
- **HTTP Security Headers**: HSTS, CSP, X-Frame-Options analysis
- **Authentication Testing**: Login form and session management testing

**HTTP Analysis Tools**
- **Header Inspection**: Security headers analysis and recommendations
- **Response Analysis**: Status codes, content types, server fingerprinting
- **Cookie Security**: HttpOnly, Secure, SameSite attribute validation
- **CORS Testing**: Cross-origin resource sharing configuration analysis
- **Redirect Chains**: URL redirection analysis and open redirect detection

#### Information Gathering

**WHOIS & DNS Tools**
- **Domain Information**: Registration details, nameservers, contact information
- **DNS Record Analysis**: A, AAAA, MX, TXT, NS, SOA records
- **DNS Zone Transfers**: AXFR attempt and analysis
- **Reverse DNS**: PTR record lookups
- **DNS Security**: DNSSEC validation
- **Geolocation**: IP address geographical mapping

### 🖥️ Modern Web Interface

#### User Experience Design

**Terminal-Style Output**
- **Real-time Streaming**: Live command output with WebSocket connections
- **Syntax Highlighting**: Color-coded output for different tool types
- **Typing Animation**: Realistic terminal typing simulation
- **Command History**: Persistent history across sessions
- **Copy Functionality**: One-click copy to clipboard
- **Export Options**: Save results as TXT, JSON, or PDF

**Responsive Design**
- **Mobile-First**: Optimized for mobile devices and tablets
- **Dark/Light Themes**: System preference detection with manual override
- **Accessibility**: WCAG 2.1 AA compliance with screen reader support
- **Progressive Enhancement**: Works without JavaScript for core features
- **Performance**: Lazy loading, code splitting, and image optimization

#### Interactive Features

**Tool Configuration**
- **Guided Setup**: Step-by-step tool configuration wizards
- **Preset Profiles**: Common scan configurations for different scenarios
- **Custom Parameters**: Advanced users can modify tool-specific options
- **Validation**: Real-time input validation with helpful error messages
- **Save/Load**: Save favorite configurations for repeated use

**Results Management**
- **Search & Filter**: Full-text search across scan results
- **Comparison**: Side-by-side comparison of multiple scans
- **Sharing**: Secure sharing with team members via encrypted links
- **Notifications**: Email alerts for completed scans
- **Integration**: Export to popular penetration testing frameworks

### 🛡️ Security Features & Implementation

#### Defense in Depth Strategy

**Input Validation & Sanitization**
- **Multi-layer Validation**: Client-side, server-side, and database-level validation
- **Command Injection Prevention**: Whitelist-based input filtering with regex patterns
- **SQL Injection Protection**: Parameterized queries with Mongoose ODM
- **XSS Prevention**: Content Security Policy (CSP) with nonce-based script execution
- **Path Traversal Protection**: Sandboxed file system access with chroot jail
- **File Upload Security**: MIME type validation, size limits, virus scanning

**Authentication & Authorization**
- **Zero Trust Architecture**: Every request authenticated and authorized
- **Role-Based Access Control (RBAC)**: Admin, user, and guest permission levels
- **Session Security**: 
  - Secure cookie flags (HttpOnly, Secure, SameSite)
  - Session invalidation on suspicious activity
  - Concurrent session limiting
  - IP address validation
- **Brute Force Protection**: 
  - Account lockout after failed attempts
  - Progressive delays (exponential backoff)
  - CAPTCHA challenges for suspicious behavior
  - Geolocation-based risk assessment

**API Security**
- **Rate Limiting**: 
  - Sliding window algorithm with Redis backing
  - Per-user and per-IP rate limits
  - Different limits for authenticated vs anonymous users
  - Burst allowance for legitimate high-frequency usage
- **Request Validation**:
  - JSON schema validation for all payloads
  - Request size limits (10MB default)
  - Content-Type enforcement
  - Custom header validation
- **Response Security**:
  - Security headers (HSTS, X-Frame-Options, X-Content-Type-Options)
  - Error message sanitization
  - Information disclosure prevention
  - CORS policy enforcement

#### Network & Infrastructure Security

**Container Security**
- **Minimal Base Images**: Alpine Linux with only essential packages
- **Non-root Execution**: All processes run as unprivileged users
- **Resource Limits**: CPU, memory, and disk I/O constraints
- **Network Segmentation**: Isolated container networks with controlled communication
- **Secret Management**: External secret stores (HashiCorp Vault, Docker Secrets)
- **Image Scanning**: Automated vulnerability scanning with Trivy/Clair

**Production Deployment Security**
- **SSL/TLS Configuration**: 
  - TLS 1.3 minimum with strong cipher suites
  - HSTS with preload and includeSubDomains
  - Certificate transparency monitoring
  - OCSP stapling for certificate validation
- **Reverse Proxy Security**:
  - Nginx with security modules (ModSecurity WAF)
  - Request filtering and size limits
  - DoS protection with rate limiting
  - Gzip bomb protection
- **Database Security**:
  - MongoDB authentication with X.509 certificates
  - Network encryption with TLS
  - Field-level encryption for sensitive data
  - Regular security audits and monitoring

## 🚀 Advanced Installation & Configuration

### Development Environment Setup

#### Prerequisites Deep Dive

**System Requirements**
- **Operating System**: Linux (Ubuntu 20.04+ recommended), macOS 10.15+, Windows 10+ with WSL2
- **Hardware**: 8GB RAM minimum (16GB recommended), 20GB free disk space
- **Network**: Unrestricted internet access for tool downloads and updates
- **Permissions**: Sudo/administrator access for security tool installation

**Node.js Environment**
```bash
# Install Node.js 18+ using nvm (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
source ~/.bashrc
nvm install 18
nvm use 18

# Verify installation
node --version  # Should output v18.x.x
npm --version   # Should output 9.x.x or higher
```

**Database Setup Options**

*Option 1: Local MongoDB Installation*
```bash
# Ubuntu/Debian
wget -qO - https://www.mongodb.org/static/pgp/server-7.0.asc | sudo apt-key add -
echo "deb [ arch=amd64,arm64 ] https://repo.mongodb.org/apt/ubuntu focal/mongodb-org/7.0 multiverse" | sudo tee /etc/apt/sources.list.d/mongodb-org-7.0.list
sudo apt-get update
sudo apt-get install -y mongodb-org

# Start and enable MongoDB
sudo systemctl start mongod
sudo systemctl enable mongod

# macOS using Homebrew
brew tap mongodb/brew
brew install mongodb-community@7.0
brew services start mongodb/brew/mongodb-community
```

*Option 2: MongoDB Atlas (Cloud)*
```bash
# Create free cluster at https://cloud.mongodb.com
# Get connection string and add to .env file
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/unified-toolkit?retryWrites=true&w=majority
```

#### Security Tools Installation

**Core Tools Installation Script**
```bash
#!/bin/bash
# tools-install.sh - Automated security tools installation

# Update package manager
sudo apt-get update && sudo apt-get upgrade -y

# Install system dependencies
sudo apt-get install -y curl wget git python3 python3-pip golang-go

# Install Nmap
sudo apt-get install -y nmap

# Install Python-based tools
pip3 install --user sublist3r dnspython requests

# Install Go-based tools
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Install Nikto
sudo apt-get install -y nikto

# Update Nuclei templates
nuclei -update-templates

# Verify installations
echo "Verifying tool installations..."
nmap --version
sublist3r --help > /dev/null && echo "Sublist3r: OK"
assetfinder --help > /dev/null && echo "AssetFinder: OK"
nuclei --version
nikto -Version

echo "All tools installed successfully!"
```

**Docker-based Tool Installation**
```bash
# Alternative: Use Docker containers for tools
docker pull nmap/nmap
docker pull projectdiscovery/nuclei
docker pull hahwul/dalfox

# Create tool wrapper scripts
cat > /usr/local/bin/nmap-docker << 'EOF'
#!/bin/bash
docker run --rm -it nmap/nmap "$@"
EOF

chmod +x /usr/local/bin/nmap-docker
```

### � Production Deployment Strategies

#### Kubernetes Deployment

**Complete Kubernetes Configuration**
```yaml
# k8s-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: unified-toolkit
  labels:
    app: unified-toolkit
spec:
  replicas: 3
  selector:
    matchLabels:
      app: unified-toolkit
  template:
    metadata:
      labels:
        app: unified-toolkit
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 1000
      containers:
      - name: unified-toolkit
        image: unified-toolkit:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: MONGODB_URI
          valueFrom:
            secretKeyRef:
              name: mongo-secret
              key: uri
        resources:
          requests:
            memory: "512Mi"
            cpu: "250m"
          limits:
            memory: "1Gi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /api/health
            port: 3000
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /api/ready
            port: 3000
          initialDelaySeconds: 5
          periodSeconds: 10
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL

---
apiVersion: v1
kind: Service
metadata:
  name: unified-toolkit-service
spec:
  selector:
    app: unified-toolkit
  ports:
  - protocol: TCP
    port: 80
    targetPort: 3000
  type: LoadBalancer

---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: unified-toolkit-ingress
  annotations:
    kubernetes.io/ingress.class: nginx
    cert-manager.io/cluster-issuer: letsencrypt-prod
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
spec:
  tls:
  - hosts:
    - pentesting.yourdomain.com
    secretName: unified-toolkit-tls
  rules:
  - host: pentesting.yourdomain.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: unified-toolkit-service
            port:
              number: 80
```

#### Docker Swarm Configuration

**Production Docker Compose with Swarm**
```yaml
# docker-compose.prod.yml
version: '3.8'

services:
  app:
    image: unified-toolkit:latest
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
    secrets:
      - mongodb_uri
      - jwt_secret
    deploy:
      replicas: 3
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
      update_config:
        parallelism: 1
        delay: 30s
        failure_action: rollback
      resources:
        limits:
          cpus: '0.5'
          memory: 1G
        reservations:
          cpus: '0.25'
          memory: 512M
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/api/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 60s

  mongodb:
    image: mongo:7.0
    ports:
      - "27017:27017"
    environment:
      MONGO_INITDB_ROOT_USERNAME_FILE: /run/secrets/mongo_root_username
      MONGO_INITDB_ROOT_PASSWORD_FILE: /run/secrets/mongo_root_password
    secrets:
      - mongo_root_username
      - mongo_root_password
    volumes:
      - mongodb_data:/data/db
      - ./mongo-init.js:/docker-entrypoint-initdb.d/mongo-init.js:ro
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure
      placement:
        constraints:
          - node.role == manager

  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.prod.conf:/etc/nginx/nginx.conf:ro
      - ./ssl-certs:/etc/nginx/ssl:ro
    deploy:
      replicas: 2
      restart_policy:
        condition: on-failure

  redis:
    image: redis:7-alpine
    command: redis-server --requirepass ${REDIS_PASSWORD}
    deploy:
      replicas: 1
      restart_policy:
        condition: on-failure

secrets:
  mongodb_uri:
    external: true
  jwt_secret:
    external: true
  mongo_root_username:
    external: true
  mongo_root_password:
    external: true

volumes:
  mongodb_data:
    driver: local
```

### 📊 Monitoring & Observability

#### Application Performance Monitoring

**Prometheus Metrics Collection**
```javascript
// lib/monitoring/metrics.js
const promClient = require('prom-client');

// Create a Registry
const register = new promClient.Registry();

// Add default metrics
promClient.collectDefaultMetrics({ register });

// Custom application metrics
const httpRequestDuration = new promClient.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status'],
  buckets: [0.1, 0.5, 1, 2, 5, 10]
});

const activeScans = new promClient.Gauge({
  name: 'active_security_scans',
  help: 'Number of currently active security scans'
});

const scanDuration = new promClient.Histogram({
  name: 'security_scan_duration_seconds',
  help: 'Duration of security scans in seconds',
  labelNames: ['tool', 'target_type'],
  buckets: [5, 10, 30, 60, 120, 300, 600]
});

const failedScans = new promClient.Counter({
  name: 'failed_security_scans_total',
  help: 'Total number of failed security scans',
  labelNames: ['tool', 'error_type']
});

register.registerMetric(httpRequestDuration);
register.registerMetric(activeScans);
register.registerMetric(scanDuration);
register.registerMetric(failedScans);

module.exports = {
  register,
  httpRequestDuration,
  activeScans,
  scanDuration,
  failedScans
};
```

**Grafana Dashboard Configuration**
```json
{
  "dashboard": {
    "title": "Unified Toolkit Monitoring",
    "panels": [
      {
        "title": "HTTP Request Rate",
        "type": "graph",
        "targets": [
          {
            "expr": "rate(http_requests_total[5m])",
            "legendFormat": "{{method}} {{route}}"
          }
        ]
      },
      {
        "title": "Active Security Scans",
        "type": "stat",
        "targets": [
          {
            "expr": "active_security_scans",
            "legendFormat": "Active Scans"
          }
        ]
      },
      {
        "title": "Scan Success Rate",
        "type": "stat",
        "targets": [
          {
            "expr": "rate(successful_scans_total[5m]) / rate(total_scans_total[5m]) * 100",
            "legendFormat": "Success Rate %"
          }
        ]
      },
      {
        "title": "Error Rate by Tool",
        "type": "table",
        "targets": [
          {
            "expr": "rate(failed_security_scans_total[5m]) by (tool)",
            "legendFormat": "{{tool}}"
          }
        ]
      }
    ]
  }
}
```

#### Logging Strategy

**Structured Logging with Winston**
```javascript
// lib/logging/logger.js
const winston = require('winston');
const { ElasticsearchTransport } = require('winston-elasticsearch');

const esTransport = new ElasticsearchTransport({
  level: 'info',
  clientOpts: { node: process.env.ELASTICSEARCH_URL },
  index: 'unified-toolkit-logs'
});

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json(),
    winston.format.printf(({ timestamp, level, message, ...meta }) => {
      return JSON.stringify({
        timestamp,
        level,
        message,
        service: 'unified-toolkit',
        environment: process.env.NODE_ENV,
        ...meta
      });
    })
  ),
  defaultMeta: {
    service: 'unified-toolkit',
    version: process.env.npm_package_version
  },
  transports: [
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      )
    }),
    new winston.transports.File({ 
      filename: 'logs/error.log', 
      level: 'error' 
    }),
    new winston.transports.File({ 
      filename: 'logs/combined.log' 
    })
  ]
});

// Add Elasticsearch transport in production
if (process.env.NODE_ENV === 'production') {
  logger.add(esTransport);
}

module.exports = logger;
```

### 🔧 Advanced Configuration & Tuning

#### Performance Optimization

**Database Query Optimization**
```javascript
// lib/models/optimized-queries.js
const mongoose = require('mongoose');

// Optimized user lookup with lean queries
async function findUserOptimized(userId) {
  return await User.findById(userId)
    .lean() // Returns plain JS object instead of Mongoose document
    .select('username email preferences') // Only select needed fields
    .exec();
}

// Aggregation pipeline for scan statistics
async function getScanStatistics(userId, days = 30) {
  const startDate = new Date();
  startDate.setDate(startDate.getDate() - days);
  
  return await ScanLog.aggregate([
    {
      $match: {
        userId: new mongoose.Types.ObjectId(userId),
        createdAt: { $gte: startDate }
      }
    },
    {
      $group: {
        _id: {
          tool: '$tool',
          date: { $dateToString: { format: '%Y-%m-%d', date: '$createdAt' } }
        },
        count: { $sum: 1 },
        avgDuration: { $avg: '$duration' },
        successCount: {
          $sum: { $cond: [{ $eq: ['$status', 'success'] }, 1, 0] }
        }
      }
    },
    {
      $sort: { '_id.date': -1 }
    }
  ]);
}

// Efficient pagination with cursor-based approach
async function paginateScans(userId, cursor, limit = 20) {
  const query = { userId };
  if (cursor) {
    query._id = { $lt: cursor };
  }
  
  return await ScanLog.find(query)
    .sort({ _id: -1 })
    .limit(limit)
    .lean()
    .exec();
}
```

**Caching Strategy with Redis**
```javascript
// lib/cache/redis-cache.js
const Redis = require('ioredis');
const logger = require('../logging/logger');

class CacheManager {
  constructor() {
    this.redis = new Redis({
      host: process.env.REDIS_HOST || 'localhost',
      port: process.env.REDIS_PORT || 6379,
      password: process.env.REDIS_PASSWORD,
      retryDelayOnFailover: 100,
      enableReadyCheck: false,
      maxRetriesPerRequest: null,
    });

    this.redis.on('error', (err) => {
      logger.error('Redis connection error:', err);
    });
  }

  async get(key) {
    try {
      const value = await this.redis.get(key);
      return value ? JSON.parse(value) : null;
    } catch (error) {
      logger.error('Cache get error:', error);
      return null;
    }
  }

  async set(key, value, ttl = 3600) {
    try {
      await this.redis.setex(key, ttl, JSON.stringify(value));
      return true;
    } catch (error) {
      logger.error('Cache set error:', error);
      return false;
    }
  }

  async del(key) {
    try {
      await this.redis.del(key);
      return true;
    } catch (error) {
      logger.error('Cache delete error:', error);
      return false;
    }
  }

  // Cache scan results with automatic expiration
  async cacheScanResult(scanId, result, duration = 7200) {
    const key = `scan:${scanId}`;
    return await this.set(key, {
      result,
      timestamp: Date.now(),
      ttl: duration
    }, duration);
  }

  // Implement rate limiting with sliding window
  async isRateLimited(identifier, limit, window) {
    const key = `rate_limit:${identifier}`;
    const now = Date.now();
    const pipeline = this.redis.pipeline();
    
    // Remove old entries
    pipeline.zremrangebyscore(key, 0, now - window * 1000);
    
    // Count current entries
    pipeline.zcard(key);
    
    // Add current request
    pipeline.zadd(key, now, now);
    
    // Set expiration
    pipeline.expire(key, window);
    
    const results = await pipeline.exec();
    const currentCount = results[1][1];
    
    return currentCount >= limit;
  }
}

module.exports = new CacheManager();
```

## 🛠️ Installation

### Option 1: Quick Docker Setup (Recommended)

```bash
# Clone and start with Docker Compose
git clone https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers.git
cd Unified-Toolkit-for-New-Pen-Testers

# Start all services
docker-compose up -d

# Access the application
open http://localhost:3000
```

### Option 2: Manual Installation

#### Step 1: Prerequisites

| Requirement | Version | Installation |
|------------|---------|--------------|
| Node.js | 18+ | [Download](https://nodejs.org/) |
| MongoDB | 7.0+ | [Install Guide](https://docs.mongodb.com/manual/installation/) |
| Git | Latest | [Download](https://git-scm.com/) |

#### Step 2: Clone & Setup

```bash
# Clone repository
git clone https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers.git
cd Unified-Toolkit-for-New-Pen-Testers

# Install dependencies  
npm install
# OR with yarn
yarn install
# OR with pnpm
pnpm install
```

#### Step 3: Environment Configuration

```bash
# Copy environment template
cp .env.template .env

# Edit configuration (required)
nano .env
```

**Essential Environment Variables:**

```env
# Database Connection
MONGODB_URI=mongodb://localhost:27017/unified-toolkit

# JWT Secrets (Generate strong secrets!)
JWT_SECRET=your-super-secret-jwt-key-min-32-chars
JWT_REFRESH_SECRET=your-refresh-secret-min-32-chars

# Email Configuration (for 2FA)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# Optional: SMS (Twilio)
TWILIO_ACCOUNT_SID=your-twilio-sid
TWILIO_AUTH_TOKEN=your-twilio-token
TWILIO_PHONE_NUMBER=+1234567890

# Optional: reCAPTCHA
RECAPTCHA_SITE_KEY=your-site-key
RECAPTCHA_SECRET_KEY=your-secret-key
```

#### Step 4: Security Tools Installation

**Automated Installation (Linux/macOS):**

```bash
# Run our installation script
chmod +x scripts/install-tools.sh
./scripts/install-tools.sh
```

**Manual Installation:**

```bash
# Core tools
sudo apt-get install nmap nikto  # Ubuntu/Debian
brew install nmap nikto          # macOS

# Python tools
pip3 install sublist3r dnspython requests

# Go tools
go install github.com/tomnomnom/assetfinder@latest
go install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Update Nuclei templates
nuclei -update-templates
```

#### Step 5: Database Setup

**Option A: Local MongoDB**

```bash
# Start MongoDB service
sudo systemctl start mongod  # Linux
brew services start mongodb-community  # macOS

# Verify connection
mongo --eval "db.runCommand({connectionStatus: 1})"
```

**Option B: MongoDB Atlas (Cloud)**

1. Create account at [MongoDB Atlas](https://cloud.mongodb.com)
2. Create a free cluster
3. Get connection string
4. Update `MONGODB_URI` in `.env`

#### Step 6: Launch Application

```bash
# Development mode
npm run dev

# Production mode
npm run build
npm start

# With PM2 (recommended for production)
npm install -g pm2
pm2 start npm --name "unified-toolkit" -- start
```

### Verification Checklist

- [ ] Application accessible at `http://localhost:3000`
- [ ] Database connection successful
- [ ] Security tools responding to commands
- [ ] Email/SMS services configured (if enabled)
- [ ] No console errors in browser

### Platform-Specific Notes

#### Windows (WSL2 Recommended)

```powershell
# Enable WSL2
wsl --install

# Install Ubuntu
wsl --install -d Ubuntu

# Continue with Linux instructions inside WSL2
```

#### macOS

```bash
# Install Homebrew first
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install required tools
brew install node mongodb-community nmap nikto
```

#### Linux (Ubuntu/Debian)

```bash
# Update package manager
sudo apt-get update && sudo apt-get upgrade -y

# Install Node.js via NodeSource
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt-get install -y nodejs

# Install security tools
sudo apt-get install -y nmap nikto python3-pip golang-go
```

---


### �🐳 Docker Deployment

1. **Using Docker Compose**
\`\`\`bash
# Build and start all services
docker-compose up -d

# View logs
docker-compose logs -f

# Stop services
docker-compose down
\`\`\`

2. **Manual Docker Build**
\`\`\`bash
# Build the image
docker build -t unified-toolkit .

# Run the container
docker run -p 3000:3000 --env-file .env unified-toolkit
\`\`\`

## 📁 Project Structure

<div align="center">

### 🏗️ **Enterprise-Grade Architecture Overview**

*Clean, Scalable, and Production-Ready Structure*

</div>

---

### 🎯 **Core Application Structure**

```
🚀 Unified-Toolkit-for-New-Pen-Testers/
```

#### 📱 **Frontend & Pages** (`app/`)
```
├── 🏠 app/                           # Next.js 14 App Router (Main Application)
│   ├── 🌐 api/                      # RESTful API Routes
│   │   ├── 🔐 auth/                 # Authentication & Security
│   │   │   ├── 🔄 change-password/   # Password management
│   │   │   ├── 🗑️ delete-account/    # Account deletion
│   │   │   ├── 📧 forgot-password/   # Password recovery
│   │   │   ├── 🚪 login/            # User authentication
│   │   │   ├── 👤 profile/          # User profile management
│   │   │   ├── 📝 register/         # Account creation
│   │   │   ├── 🔒 reset-password/   # Password reset
│   │   │   ├── ⚙️ security-settings/ # Security configurations
│   │   │   └── 📱 verify-otp/       # Two-factor authentication
│   │   │
│   │   ├── 🌱 seed/                 # Database Initialization
│   │   │   └── route.ts             # Seed data endpoints
│   │   │
│   │   └── 🛠️ tools/               # Penetration Testing APIs
│   │       ├── 🎯 advanced/         # Advanced Security Tools
│   │       │   ├── 🔐 crypto/       # Cryptography tools
│   │       │   ├── 📂 dirbuster/    # Directory enumeration
│   │       │   ├── 🕵️ forensics/    # Digital forensics
│   │       │   ├── ⚡ masscan/      # Mass port scanning
│   │       │   ├── 📱 mobile/       # Mobile security testing
│   │       │   ├── 🌐 osint/        # Open source intelligence
│   │       │   ├── 🎭 social-engineering/ # Social engineering
│   │       │   └── 📡 wireless/     # Wireless security
│   │       │
│   │       ├── 👨‍💻 expert/           # Expert-Level Tools
│   │       │   ├── 🔬 binary-analysis/    # Binary analysis
│   │       │   ├── 🚫 burpsuite/         # Burp Suite integration
│   │       │   ├── 📦 container-security/ # Container scanning
│   │       │   ├── 💣 metasploit/        # Exploitation framework
│   │       │   └── 🌐 network-analysis/  # Network analysis
│   │       │
│   │       ├── 🌍 dns/              # DNS enumeration
│   │       ├── 📋 http-headers/     # HTTP header analysis
│   │       ├── 🔍 network-scan/     # Network scanning
│   │       ├── 🗺️ nmap/             # Nmap integration
│   │       ├── 🌐 subdomain/        # Subdomain enumeration
│   │       ├── 🔍 vuln-scan/        # Vulnerability scanning
│   │       └── ❓ whois/            # WHOIS lookup
│   │
│   ├── 📊 dashboard/                # Main Control Panel
│   │   └── page.tsx                 # Dashboard interface
│   │
│   ├── 🛠️ tools/                   # Individual Tool Interfaces
│   │   ├── 🎯 advanced/             # Advanced Tool Pages
│   │   │   ├── 🔐 cryptography/     # Crypto analysis UI
│   │   │   ├── 🕵️ digital-forensics/ # Forensics interface
│   │   │   ├── 📂 directory-buster/ # Directory enumeration UI
│   │   │   ├── ⚡ masscan/          # Mass scanning interface
│   │   │   ├── 📱 mobile-security/  # Mobile testing UI
│   │   │   ├── 🌐 osint/            # OSINT tools interface
│   │   │   ├── 🎭 social-engineering/ # Social engineering UI
│   │   │   └── 📡 wireless-security/ # Wireless testing UI
│   │   │
│   │   ├── 👨‍💻 expert/              # Expert Tool Pages
│   │   │   ├── 🔬 binary-analysis/  # Binary analysis UI
│   │   │   ├── 🚫 burp-suite/       # Burp Suite interface
│   │   │   ├── ☁️ cloud-security/   # Cloud security UI
│   │   │   ├── 📦 container-security/ # Container testing UI
│   │   │   ├── 💣 metasploit/       # Exploitation interface
│   │   │   └── 🌐 network-analysis/ # Network analysis UI
│   │   │
│   │   ├── 🌍 dns-lookup/           # DNS lookup interface
│   │   ├── 📋 http-headers/         # Header analysis UI
│   │   ├── 🔍 network-scan/         # Network scanning UI
│   │   ├── 🚪 port-scanner/         # Port scanning interface
│   │   ├── 🌐 subdomain-enum/       # Subdomain enumeration UI
│   │   ├── 🔍 vuln-scanner/         # Vulnerability scanning UI
│   │   └── ❓ whois/               # WHOIS lookup interface
│   │
│   ├── 🔐 Authentication Pages/     # User Authentication Flow
│   │   ├── 🚪 login/ → page.tsx     # Login interface
│   │   ├── 📝 register/ → page.tsx  # Registration form
│   │   ├── 👤 profile/ → page.tsx   # User profile
│   │   ├── 📱 verify-otp/ → page.tsx # OTP verification
│   │   ├── 📧 forgot-password/ → page.tsx # Password recovery
│   │   └── 🔒 reset-password/ → page.tsx  # Password reset
│   │
│   ├── 🎨 globals.css               # Global styling
│   ├── 🏗️ layout.tsx               # Root application layout
│   └── 🏠 page.tsx                  # Landing page
```

#### 🧩 **Components & UI** (`components/`)
```
├── 🧩 components/                   # Reusable React Components
│   ├── 🎨 ui/                       # shadcn/ui Design System
│   │   ├── 🚨 alert.tsx             # Alert notifications
│   │   ├── 👤 avatar.tsx            # User avatars
│   │   ├── 🏷️ badge.tsx             # Status badges
│   │   ├── 🔘 button.tsx            # Interactive buttons
│   │   ├── 📋 card.tsx              # Content cards
│   │   ├── 💬 dialog.tsx            # Modal dialogs
│   │   ├── 📝 form.tsx              # Form components
│   │   ├── 📥 input.tsx             # Input fields
│   │   ├── 🏷️ label.tsx             # Form labels
│   │   ├── 📊 progress.tsx          # Progress indicators
│   │   ├── 📜 scroll-area.tsx       # Custom scrollbars
│   │   ├── 🔽 select.tsx            # Dropdown selectors
│   │   ├── 📱 sidebar.tsx           # Navigation sidebar
│   │   ├── 📊 table.tsx             # Data tables
│   │   ├── 📑 tabs.tsx              # Tab navigation
│   │   ├── 📄 textarea.tsx          # Text areas
│   │   ├── 🍞 toast.tsx             # Toast notifications
│   │   └── 💡 tooltip.tsx           # Helpful tooltips
│   │
│   ├── 📊 DashboardStats.tsx        # Real-time statistics
│   ├── ⏱️ RecentActivity.tsx        # Activity timeline
│   ├── 💻 TerminalOutput.tsx        # CLI-style output
│   ├── 🎨 theme-provider.tsx        # Theme management
│   ├── 🌈 ThemeBackground.tsx       # Dynamic backgrounds
│   ├── 🌓 ThemeToggle.tsx           # Dark/light mode
│   └── 📝 ToolForm.tsx              # Tool input forms
```

#### ⚡ **Business Logic & State** (`contexts/`, `hooks/`, `lib/`)
```
├── 🧠 contexts/                     # React Context Providers
│   ├── 🔐 AuthContext.tsx           # Authentication state
│   └── 🎨 ThemeContext.tsx          # Theme preferences
│
├── 🎣 hooks/                        # Custom React Hooks
│   ├── 📱 use-mobile.tsx            # Mobile responsiveness
│   ├── 🍞 use-toast.ts              # Toast notifications
│   └── 🌐 useApi.ts                 # API call management
│
├── 📚 lib/                          # Core Business Logic
│   ├── 🗃️ models/                   # Database Schemas
│   │   ├── 📱 OTP.ts                # Two-factor authentication
│   │   ├── 📊 ScanLog.ts            # Security scan logs
│   │   └── 👤 User.ts               # User account model
│   │
│   ├── 🛠️ utils/                    # Utility Functions
│   │   ├── 🎯 advanced-tools.ts     # Advanced tool logic
│   │   ├── 🎭 demo-account.ts       # Demo account management
│   │   ├── 📧 email.ts              # Email services
│   │   ├── 👨‍💻 expert-tools.ts      # Expert tool logic
│   │   ├── 🔑 jwt.ts                # JWT token management
│   │   ├── 📱 otp.ts                # OTP generation/validation
│   │   ├── 🛡️ security-tools.ts     # Security tool functions
│   │   └── 📲 sms.ts                # SMS services
│   │
│   ├── 🛡️ middleware/               # API Middleware
│   │   ├── 🔐 auth.ts               # Authentication middleware
│   │   └── ⏱️ rate-limit.ts         # Rate limiting
│   │
│   ├── 🗄️ mongodb.ts               # Database connection
│   └── 🔧 utils.ts                  # General utilities
```

#### 🐳 **Infrastructure & Configuration**
```
├── 🐳 Docker & Deployment/          # Container & Deployment
│   ├── 🐳 Dockerfile                # Container build instructions
│   ├── 🔧 docker-compose.yml        # Multi-service orchestration
│   ├── 🛠️ docker-compose.dev.yml    # Development environment
│   ├── 🚀 docker-compose.prod.yml   # Production environment
│   ├── 🌐 nginx.conf               # Web server configuration
│   └── 📁 nginx/                   # Nginx configurations
│       └── nginx.prod.conf         # Production web config
│
├── 🚀 Deployment Scripts/           # Automated Deployment
│   ├── 💻 deploy.ps1               # PowerShell deployment
│   ├── 🐧 deploy.sh                # Bash deployment script
│   ├── 📋 DEPLOYMENT.md            # Deployment guide
│   └── 👨‍💻 DEVELOPMENT.md          # Development guide
│
├── ⚙️ Configuration Files/          # Project Configuration
│   ├── 📦 package.json             # Dependencies & scripts
│   ├── 🔒 pnpm-lock.yaml           # Dependency lock file
│   ├── 🎨 tailwind.config.ts       # Styling configuration
│   ├── 📝 tsconfig.json            # TypeScript settings
│   ├── 🏗️ next.config.mjs          # Next.js configuration
│   ├── 🚀 next.config.optimized.mjs # Optimized build config
│   ├── 🎨 postcss.config.mjs       # CSS processing
│   └── 🧩 components.json          # UI component config
│
├── 📄 Documentation/               # Project Documentation
│   ├── 📖 README.md               # Main documentation (this file)
│   ├── 📋 PROJECT-SUMMARY.md      # Project overview
│   ├── 🧹 CLEANUP-SUMMARY.md      # Code cleanup notes
│   └── ⚖️ LICENSE                # MIT License
│
├── 🗄️ Database/                   # Database Setup
│   └── 🌱 mongo-init.js           # MongoDB initialization
│
├── 🎨 Assets/                     # Static Resources
│   └── 📁 public/                 # Public assets
│       ├── 🖼️ placeholder-logo.png  # Logo assets
│       ├── 🖼️ placeholder-logo.svg  # Vector logo
│       ├── 👤 placeholder-user.jpg  # User placeholders
│       └── 🖼️ placeholder.svg      # General placeholders
│
└── 🎨 styles/                     # Additional Styling
    └── globals.css                # Global CSS styles
```

---

<div align="center">

### 📊 **Architecture Highlights**

| Component | Technology | Purpose | Lines of Code |
|-----------|------------|---------|---------------|
| **🌐 Frontend** | Next.js 14 + TypeScript | User interface & routing | ~15,000+ |
| **🔌 API Layer** | Next.js API Routes | RESTful backend services | ~8,000+ |
| **🎨 UI Components** | shadcn/ui + Tailwind | Design system | ~5,000+ |
| **🗄️ Database** | MongoDB + Mongoose | Data persistence | ~2,000+ |
| **🔐 Authentication** | JWT + bcrypt | Security & sessions | ~3,000+ |
| **🛠️ Security Tools** | Integrated CLI tools | Penetration testing | ~6,000+ |
| **🐳 Infrastructure** | Docker + Nginx | Deployment & scaling | ~1,000+ |

</div>

## 🔧 Configuration

### Environment Variables

Create a `.env` file based on `.env.template`:

\`\`\`env
# Database
MONGODB_URI=mongodb://localhost:27017/Unified-Toolkit-for-New-Pen-Testers

# JWT Secrets
JWT_SECRET=your-super-secret-jwt-key-here
JWT_REFRESH_SECRET=your-refresh-secret-here

# Email Configuration (Gmail example)
EMAIL_HOST=smtp.gmail.com
EMAIL_PORT=587
EMAIL_USER=your-email@gmail.com
EMAIL_PASS=your-app-password

# SMS Configuration (Twilio)
TWILIO_ACCOUNT_SID=your-twilio-account-sid
TWILIO_AUTH_TOKEN=your-twilio-auth-token
TWILIO_PHONE_NUMBER=+1234567890

# reCAPTCHA
RECAPTCHA_SITE_KEY=your-recaptcha-site-key
RECAPTCHA_SECRET_KEY=your-recaptcha-secret-key
\`\`\`

### Security Tools Setup

The application requires the following tools to be installed:

- **nmap** - Network port scanner
- **sublist3r** - Subdomain enumeration
- **assetfinder** - Alternative subdomain finder
- **nikto** - Web vulnerability scanner
- **nuclei** - Modern vulnerability scanner
- **whois** - Domain information lookup
- **dig** - DNS lookup utility
- **curl** - HTTP client

## 🛠️ API Documentation

### 🔐 Authentication Endpoints

| Method | Endpoint | Description | Required Fields |
|--------|----------|-------------|-----------------|
| `POST` | `/api/auth/register` | User registration | email, username, password, phone |
| `POST` | `/api/auth/login` | User authentication | email/username, password |
| `POST` | `/api/auth/verify-otp` | OTP verification | email, otp_code |
| `POST` | `/api/auth/forgot-password` | Password reset request | email |
| `POST` | `/api/auth/reset-password` | Reset with OTP | email, otp_code, new_password |
| `POST` | `/api/auth/change-password` | Change password | current_password, new_password |
| `POST` | `/api/auth/refresh` | Refresh JWT token | refresh_token |
| `DELETE` | `/api/auth/logout` | User logout | Authorization header |

### 🔧 Security Tools Endpoints

#### Network Scanning

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `POST` | `/api/tools/nmap` | Port scanning | target, ports, scan_type |
| `POST` | `/api/tools/masscan` | High-speed port scan | target, ports, rate |
| `POST` | `/api/tools/network-scan` | Network discovery | network_range, scan_options |

#### Web Security

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `POST` | `/api/tools/vuln-scan` | Vulnerability scanning | target_url, scan_depth |
| `POST` | `/api/tools/http-headers` | HTTP header analysis | target_url |
| `POST` | `/api/tools/nikto` | Web server scanner | target_url, options |

#### Information Gathering

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `POST` | `/api/tools/subdomain` | Subdomain enumeration | domain, tools_list |
| `POST` | `/api/tools/whois` | WHOIS information | domain |
| `POST` | `/api/tools/dns` | DNS record lookup | domain, record_type |

#### Advanced Tools

| Method | Endpoint | Description | Parameters |
|--------|----------|-------------|------------|
| `POST` | `/api/tools/advanced/osint` | OSINT investigation | target, sources |
| `POST` | `/api/tools/advanced/crypto` | Cryptographic analysis | input_data, algorithm |
| `POST` | `/api/tools/expert/metasploit` | Exploitation framework | target, payload |

### 📊 Management Endpoints

| Method | Endpoint | Description | Access Level |
|--------|----------|-------------|--------------|
| `GET` | `/api/scans` | List user scans | User |
| `GET` | `/api/scans/:id` | Get scan details | User (own scans) |
| `DELETE` | `/api/scans/:id` | Delete scan | User (own scans) |
| `GET` | `/api/stats` | User statistics | User |
| `GET` | `/api/admin/users` | User management | Admin |
| `GET` | `/api/admin/system` | System metrics | Admin |

### 📝 Request/Response Examples

#### Authentication Request

```bash
curl -X POST http://localhost:3000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "user@example.com",
    "password": "SecurePass123!"
  }'
```

#### Response

```json
{
  "success": true,
  "data": {
    "user": {
      "id": "user_123",
      "email": "user@example.com",
      "username": "pentester"
    },
    "tokens": {
      "access_token": "eyJhbGciOiJIUzI1NiIs...",
      "refresh_token": "eyJhbGciOiJIUzI1NiIs...",
      "expires_in": 900
    }
  }
}
```

#### Nmap Scan Request

```bash
curl -X POST http://localhost:3000/api/tools/nmap \
  -H "Authorization: Bearer YOUR_JWT_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target": "scanme.nmap.org",
    "ports": "22,80,443",
    "scan_type": "syn"
  }'
```

#### Scan Response

```json
{
  "success": true,
  "scan_id": "scan_456",
  "status": "completed",
  "data": {
    "target": "scanme.nmap.org",
    "ports": [
      {
        "port": 22,
        "state": "open",
        "service": "ssh",
        "version": "OpenSSH 7.4"
      },
      {
        "port": 80,
        "state": "open", 
        "service": "http",
        "version": "Apache 2.4.7"
      }
    ],
    "scan_time": "2024-01-15T10:30:00Z",
    "duration": "5.2s"
  }
}
```

### 🚫 Error Responses

```json
{
  "success": false,
  "error": {
    "code": "VALIDATION_ERROR",
    "message": "Invalid target format",
    "details": {
      "field": "target",
      "expected": "domain or IP address"
    }
  }
}
```
---

## 🔒 Security & Compliance

### 🛡️ Security First Approach

Our platform implements multiple layers of security to protect your data and ensure safe testing:

#### Authentication & Authorization

| Feature | Implementation | Description |
|---------|----------------|-------------|
| **Multi-Factor Auth** | Email + SMS OTP | 5-minute OTP expiration |
| **Password Security** | bcrypt (12 rounds) | Complexity requirements |
| **Session Management** | JWT + Refresh Tokens | 15min access, 7-day refresh |
| **Brute Force Protection** | Rate limiting + CAPTCHA | 3 attempts per 15 minutes |

#### Data Protection

- **🔐 Encryption**: AES-256 for data at rest, TLS 1.3 for transit
- **🔍 Input Validation**: Multi-layer sanitization and validation
- **🚫 Injection Prevention**: Parameterized queries, whitelist filtering
- **🔒 Secure Headers**: HSTS, CSP, X-Frame-Options, etc.

#### Infrastructure Security

- **🐳 Container Security**: Non-root execution, minimal base images
- **🌐 Network Isolation**: Segmented networks with controlled communication
- **📊 Monitoring**: Real-time security event logging
- **🔄 Updates**: Automated security patches and dependency updates



## 🐛 Comprehensive Troubleshooting Guide

### Common Installation Issues

#### Node.js and Dependencies

**Issue: npm install fails with permission errors**
```bash
# Solution 1: Use npm with user directory
mkdir ~/.npm-global
npm config set prefix '~/.npm-global'
echo 'export PATH=~/.npm-global/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

# Solution 2: Use nvm (recommended)
curl -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.39.0/install.sh | bash
nvm install node
nvm use node
```

**Issue: TypeScript compilation errors**
```bash
# Clear Next.js cache
rm -rf .next
npm run build

# Reinstall dependencies
rm -rf node_modules package-lock.json
npm install

# Check TypeScript configuration
npx tsc --noEmit
```

#### Database Connection Issues

**MongoDB Connection Troubleshooting**
```bash
# Check MongoDB status
sudo systemctl status mongod

# View MongoDB logs
sudo journalctl -u mongod -f

# Test connection manually
mongo --eval "db.adminCommand('ismaster')"

# Check network connectivity
telnet localhost 27017
```

**Common MongoDB Errors and Solutions**
```javascript
// Error: MongoNetworkError: failed to connect to server
// Solution: Check if MongoDB is running and accessible
const mongoose = require('mongoose');

async function testConnection() {
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      useNewUrlParser: true,
      useUnifiedTopology: true,
      serverSelectionTimeoutMS: 5000
    });
    console.log('MongoDB connected successfully');
  } catch (error) {
    console.error('MongoDB connection error:', error.message);
    
    // Detailed error handling
    if (error.name === 'MongoNetworkError') {
      console.log('Check if MongoDB is running on the specified host/port');
    } else if (error.name === 'MongoAuthenticationError') {
      console.log('Check your MongoDB credentials');
    }
  }
}
```

#### Security Tools Installation Issues

**Nmap Installation Problems**
```bash
# Ubuntu/Debian - if package not found
sudo apt-get update
sudo apt-get install software-properties-common
sudo add-apt-repository universe
sudo apt-get update
sudo apt-get install nmap

# macOS - if Homebrew fails
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
brew install nmap

# Windows with WSL2
wsl --install -d Ubuntu
# Then follow Ubuntu instructions
```

**Python Tools Installation Issues**
```bash
# If pip3 not found
sudo apt-get install python3-pip

# If sublist3r installation fails
pip3 install --user --upgrade pip
pip3 install --user sublist3r

# For permission issues
python3 -m pip install --user sublist3r

# Virtual environment approach (recommended)
python3 -m venv pentesting-tools
source pentesting-tools/bin/activate
pip install sublist3r dnspython requests
```

### Runtime Issues

#### Application Startup Problems

**Port Already in Use**
```bash
# Find process using port 3000
lsof -i :3000
netstat -tulpn | grep 3000

# Kill process
sudo kill -9 <process_id>

# Use different port
PORT=3001 npm run dev
```

**Environment Variables Not Loading**
```bash
# Check .env file exists and has correct format
cat .env | grep -v '^#' | grep '='

# Validate required variables
node -e "console.log(Object.keys(process.env).filter(k => k.includes('MONGO')))"

# Debug environment loading
node -e "require('dotenv').config(); console.log(process.env.MONGODB_URI)"
```

#### API and Authentication Issues

**JWT Token Issues**
```javascript
// Debug JWT tokens
const jwt = require('jsonwebtoken');

function debugToken(token) {
  try {
    const decoded = jwt.decode(token, { complete: true });
    console.log('Token header:', decoded.header);
    console.log('Token payload:', decoded.payload);
    console.log('Token expires:', new Date(decoded.payload.exp * 1000));
  } catch (error) {
    console.error('Invalid token:', error.message);
  }
}

// Test token verification
function verifyToken(token, secret) {
  try {
    const verified = jwt.verify(token, secret);
    console.log('Token valid:', verified);
  } catch (error) {
    console.error('Token verification failed:', error.message);
  }
}
```

**Email/SMS Service Issues**
```javascript
// Test email configuration
const nodemailer = require('nodemailer');

async function testEmail() {
  const transporter = nodemailer.createTransporter({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false,
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS
    }
  });

  try {
    await transporter.verify();
    console.log('Email server connection successful');
  } catch (error) {
    console.error('Email server error:', error);
  }
}

// Test SMS (Twilio) configuration
const twilio = require('twilio');

function testSMS() {
  try {
    const client = twilio(
      process.env.TWILIO_ACCOUNT_SID,
      process.env.TWILIO_AUTH_TOKEN
    );
    
    client.accounts(process.env.TWILIO_ACCOUNT_SID)
      .fetch()
      .then(account => console.log('Twilio connection successful:', account.friendlyName))
      .catch(error => console.error('Twilio error:', error));
  } catch (error) {
    console.error('Twilio configuration error:', error);
  }
}
```

### Performance Issues

#### Slow Scan Performance

**Optimize Nmap Scans**
```bash
# Fast scan for initial discovery
nmap -T4 -F target.com

# Optimize for large networks
nmap -T4 --min-parallelism 50 --max-parallelism 100 target.com

# Skip DNS resolution for speed
nmap -n target.com

# Use specific scan types for faster results
nmap -sS -T4 target.com  # SYN scan (fastest)
```

**Database Performance Optimization**
```javascript
// Add indexes for frequently queried fields
db.users.createIndex({ "email": 1 })
db.users.createIndex({ "username": 1 })
db.scanLogs.createIndex({ "userId": 1, "createdAt": -1 })
db.scanLogs.createIndex({ "tool": 1, "status": 1 })

// Optimize queries with explain()
db.scanLogs.find({ userId: ObjectId("...") }).explain("executionStats")

// Use aggregation for complex queries
db.scanLogs.aggregate([
  { $match: { userId: ObjectId("...") } },
  { $group: { _id: "$tool", count: { $sum: 1 } } }
])
```

### 🧪 Hands-on Laboratory Exercises

#### Lab 1: Network Reconnaissance

**Objective:** Master network discovery and enumeration techniques

```bash
# Phase 1: Host Discovery
nmap -sn 192.168.1.0/24

# Phase 2: Port Scanning  
nmap -sS -T4 -p- <target_ip>

# Phase 3: Service Detection
nmap -sV -sC <target_ip>

# Phase 4: Vulnerability Assessment
nmap --script vuln <target_ip>
```

**Expected Outcome:** Complete network topology with service inventory

#### Lab 2: Web Application Security Testing

**Objective:** Identify and exploit common web vulnerabilities

```bash
# Reconnaissance
curl -I http://target.com
dirb http://target.com

# Vulnerability Scanning
nikto -h http://target.com
nuclei -u http://target.com

# Manual Testing
sqlmap -u "http://target.com/page?id=1"
```

**Expected Outcome:** Comprehensive security assessment report

#### Lab 3: Wireless Network Assessment

**Objective:** Evaluate wireless security posture

```bash
# Monitor Mode Setup
airmon-ng start wlan0

# Network Discovery
airodump-ng wlan0mon

# WPA/WPA2 Testing
aircrack-ng -w wordlist.txt capture.cap
```

**Expected Outcome:** Wireless security audit with recommendations

### 🎯 Skill Development Milestones

#### Beginner Milestones ✅

- [ ] Successfully perform network discovery scan
- [ ] Identify open ports and services
- [ ] Conduct basic web vulnerability scan
- [ ] Generate professional scan report
- [ ] Understand common attack vectors

#### Intermediate Milestones ✅

- [ ] Exploit SQL injection vulnerability
- [ ] Perform successful privilege escalation
- [ ] Conduct comprehensive OSINT investigation
- [ ] Create custom exploit payload
- [ ] Lead penetration testing project

#### Advanced Milestones ✅

- [ ] Develop custom security tools
- [ ] Design red team campaign
- [ ] Implement security automation
- [ ] Mentor junior team members
- [ ] Achieve industry certification

---

## 🤝 Community & Contribution Guidelines

### Contributing to the Project

#### Development Workflow
1. **Fork and Clone**
   ```bash
   git clone https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers.git
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-amazing-feature
   ```

3. **Development Standards**
   - Follow ESLint and Prettier configurations
   - Write comprehensive tests for new features
   - Update documentation for API changes
   - Follow semantic commit message conventions

4. **Pull Request Process**
   - Ensure all tests pass
   - Update README if necessary
   - Add screenshots for UI changes
   - Request review from maintainers


## 📄 Legal Disclaimer

**IMPORTANT**: This tool is designed for educational purposes and authorized security testing only. Users are responsible for:

- Obtaining proper authorization before testing any systems
- Complying with all applicable laws and regulations
- Using the tool in accordance with ethical hacking principles
- Respecting the privacy and security of others

The developers and contributors of this project are not responsible for any misuse of the tool or any damages resulting from its use.


### 🤝 Contributing to the Project

#### 🔧 Code Contributions

1. **Fork the Repository**
   ```bash
   git clone https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers.git
   ```

2. **Create Feature Branch**
   ```bash
   git checkout -b feature/your-amazing-feature
   ```

3. **Development Guidelines**
   - Follow TypeScript and ESLint configurations
   - Write comprehensive tests (minimum 80% coverage)
   - Update documentation for any API changes
   - Use conventional commit messages

4. **Submit Pull Request**
   - Ensure all tests pass
   - Include screenshots for UI changes
   - Provide detailed description of changes
   - Request review from maintainers

#### 📝 Documentation Contributions

- **📚 Improve Existing Docs**: Fix typos, add clarity, update examples
- **🆕 Create New Guides**: Write tutorials, how-tos, and best practices
- **🌍 Translations**: Help translate content into other languages
- **🎥 Video Content**: Create educational videos and screencasts

#### 🎨 Design Contributions

- **🖌️ UI/UX Improvements**: Enhance user interface and experience
- **📱 Mobile Optimization**: Improve mobile responsiveness
- **🎨 Visual Assets**: Create icons, illustrations, and graphics
- **♿ Accessibility**: Improve accessibility features and compliance


#### 📊 Project Statistics

- **⭐ GitHub Stars**: Track our growth
- **🍴 Forks**: See community involvement  
- **📝 Issues**: Current bugs and features
- **🔄 Pull Requests**: Active development
- **📈 Downloads**: Monthly usage statistics

---

---

<div align="center">

## 📄 Legal & License Information

**📋 License**: [MIT License](LICENSE) - Free for personal and commercial use

**⚖️ Terms of Service**: [Read Here](https://unified-toolkit.com/terms)

**🔒 Privacy Policy**: [Read Here](https://unified-toolkit.com/privacy)

**⚠️ IMPORTANT DISCLAIMER**

This tool is designed for **educational purposes** and **authorized security testing** only. 

Users are responsible for:
- ✅ Obtaining proper authorization before testing any systems
- ✅ Complying with all applicable laws and regulations  
- ✅ Using the tool ethically and responsibly
- ✅ Respecting privacy and security of others

The developers are not responsible for any misuse or damages resulting from use of this tool.

**🎓 Educational Use Only**

*"With great power comes great responsibility"* - Use these tools wisely!

---

### 🔗 Quick Links

[🏠 Homepage](https://unified-toolkit.com) • [📚 Documentation](https://docs.unified-toolkit.com) • [💬 Discord](https://discord.gg/unified-toolkit) • [🐙 GitHub](https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers) • [📧 Contact](mailto:hello@unified-toolkit.com)

---

**Built with ❤️ by [Suman Singh](https://github.com/sumansingh20) and the cybersecurity community**

*"Security is not a product, but a process."* - Bruce Schneier

**⭐ If you found this helpful, please give us a star on GitHub! ⭐**

</div>
