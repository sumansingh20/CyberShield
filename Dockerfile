# Use Node.js LTS version
FROM node:20-alpine

# Install system dependencies
RUN apk add --no-cache python3 make g++

# Set working directory
WORKDIR /app

# Install pnpm globally
RUN npm install -g pnpm

# Copy package files
COPY package.json pnpm-lock.yaml ./

# Development mode setup
RUN if [ "$NODE_ENV" = "development" ] ; then \
        pnpm install ; \
    else \
        pnpm install --frozen-lockfile --production ; \
    fi

# Copy the rest of the application
COPY . .

# Build the application
RUN pnpm run build

# Expose the port the app runs on
EXPOSE 3000

# Use development command if in development mode, otherwise use production
CMD if [ "$NODE_ENV" = "development" ] ; then \
        pnpm run dev ; \
    else \
        pnpm start ; \
    fi