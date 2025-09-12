


# Use the official Node.js 18 image
FROM node:18-alpine

# Set working directory
WORKDIR /app

# Install system dependencies for security tools
RUN apk add --no-cache \
    nmap \
    curl \
    bind-tools \
    whois \
    git \
    python3 \
    py3-pip

# Install Python-based tools
RUN pip3 install sublist3r

# Install Go-based tools
RUN wget -O /usr/local/bin/assetfinder https://github.com/tomnomnom/assetfinder/releases/download/v0.1.1/assetfinder-linux-amd64-0.1.1.tgz && \
    tar -xzf /usr/local/bin/assetfinder && \
    chmod +x /usr/local/bin/assetfinder

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY . .

# Build the application
RUN npm run build

# Create non-root user
RUN addgroup -g 1001 -S nodejs
RUN adduser -S nextjs -u 1001

# Change ownership of the app directory
RUN chown -R nextjs:nodejs /app
USER nextjs

# Expose port
EXPOSE 3000

# Set environment to production
ENV NODE_ENV=production

# Start the application
CMD ["npm", "start"]
