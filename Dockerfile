# Multi-stage Docker build for Next.js + Express backend

# 1) Builder stage: install all deps and build
FROM node:20-alpine AS builder

# Ensure compatibility libs
RUN apk add --no-cache libc6-compat

WORKDIR /app

# Enable corepack and pnpm
RUN corepack enable

# Copy lockfiles and install all dependencies
COPY package.json pnpm-lock.yaml ./
RUN pnpm install --no-frozen-lockfile

# Copy source and build
COPY . .
RUN pnpm run build

# Prune dev dependencies to reduce final image size
RUN pnpm prune --prod


# 2) Runner stage: copy build artifacts and run server
FROM node:20-alpine AS runner

WORKDIR /app
ENV NODE_ENV=production

# Copy only necessary files
COPY --from=builder /app/package.json ./
COPY --from=builder /app/next.config.* ./
COPY --from=builder /app/.next ./.next
COPY --from=builder /app/public ./public
COPY --from=builder /app/node_modules ./node_modules
COPY --from=builder /app/server.js ./server.js

# Expose default port (Render/other platforms will inject PORT)
EXPOSE 3000

# Start the Express server which delegates to Next
CMD ["node", "server.js"]
