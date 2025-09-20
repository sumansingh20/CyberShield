# 🛡️ Unified Toolkit for New Pen-Testers

Complete penetration testing platform with integrated security tools, authentication, and modern web interface.

<div align="center">

[![Next.js](https://img.shields.io/badge/Next.js-15-black?style=for-the-badge&logo=next.js)](https://nextjs.org/)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.9-blue?style=for-the-badge&logo=typescript)](https://www.typescriptlang.org/)
[![MongoDB](https://img.shields.io/badge/MongoDB-7.0-green?style=for-the-badge&logo=mongodb)](https://www.mongodb.com/)
[![Docker](https://img.shields.io/badge/Docker-Ready-blue?style=for-the-badge&logo=docker)](https://www.docker.com/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg?style=for-the-badge)](LICENSE)

</div>

---

## 🚀 Quick Start

Prerequisites
- Node.js 18+
- MongoDB 7.0+ (local or Atlas)
- Git

Setup
```bash
# 1) Clone
git clone https://github.com/sumansingh20/Unified-Toolkit-for-New-Pen-Testers.git
cd Unified-Toolkit-for-New-Pen-Testers

# 2) Install
pnpm install

# 3) Configure env
cp .env.template .env
# edit .env with your secrets (Mongo URI, JWT, SMTP, etc.)

# 4) Dev
pnpm dev
```

Docker
```bash
# local stack
docker-compose up -d
open http://localhost:3000
```

---

## ✨ Features
- Authentication: JWT + refresh, optional 2FA (email/SMS), reCAPTCHA
- Security tools: Nmap, Subdomain enum, WHOIS, DNS, and more
- UI: Responsive design, themes, real-time output
- API: Next.js App Router endpoints under /api/*
- Deploy: Netlify (frontend + API) and Render/Docker

---

## 🔧 Environment Variables
Create .env from template and set:
- MONGODB_URI
- JWT_SECRET, JWT_REFRESH_SECRET
- EMAIL_HOST, EMAIL_PORT, EMAIL_USER, EMAIL_PASS
- TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_FROM_NUMBER (optional)
- RECAPTCHA_SITE_KEY, RECAPTCHA_SECRET_KEY (optional)
- ALLOWED_ORIGINS (for CORS)

---

## 🐳 Deploy

Netlify
- Repo is connected in Netlify.
- netlify.toml uses the Next.js plugin; API routes served by the app.
- Ensure Netlify env vars mirror your .env where needed.

Render (Backend)
- render.yaml and render.json configured to:
  - build: pnpm install --no-frozen-lockfile && pnpm run build
  - start: node server.js
  - health: /api/health
- Set env in Render dashboard: MONGODB_URI, JWT secrets, SMTP/Twilio, RECAPTCHA, PORT=10000, NODE_ENV=production, ALLOWED_ORIGINS.

Docker (local or other infra)
- Multi-stage Dockerfile builds Next.js, prunes dev deps, and runs server.js.
- docker-compose.yml includes MongoDB service for local development.

---

## 📄 License
MIT License - see LICENSE.

## ⚠️ Disclaimer
For authorized security testing only. Obtain proper authorization before testing any systems.
