/** @type {import('next').NextConfig} */
const nextConfig = {
  eslint: {
    ignoreDuringBuilds: true,
  },
  typescript: {
    ignoreBuildErrors: true,
  },
  images: {
    unoptimized: true,
  },
  // Netlify configuration
  trailingSlash: false,
  distDir: '.next',
  // Performance optimizations
  swcMinify: true,
  experimental: {
    optimizePackageImports: ['@radix-ui/react-icons', 'lucide-react'],
  },
  // Optimized webpack configuration
  webpack: (config, { dev, isServer }) => {
    if (dev) {
      // Optimize chunk splitting for development
      config.optimization.splitChunks = {
        chunks: 'all',
        minSize: 20000,
        maxSize: 200000,
        cacheGroups: {
          default: false,
          vendors: false,
          vendor: {
            chunks: 'all',
            test: /[\\/]node_modules[\\/]/,
            name: 'vendor',
            priority: 20,
            enforce: true,
          },
          ui: {
            chunks: 'all',
            test: /[\\/]components[\\/]ui[\\/]/,
            name: 'ui',
            priority: 15,
            enforce: true,
          },
        },
      }
      
      // Reduce bundle analysis time
      config.optimization.usedExports = false
      config.optimization.sideEffects = false
    }
    
    // Node.js polyfills for browser compatibility
    config.resolve.fallback = {
      ...config.resolve.fallback,
      fs: false,
      net: false,
      tls: false,
    }
    
    return config
  },
}

export default nextConfig
