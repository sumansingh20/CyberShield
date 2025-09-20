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
    domains: ['localhost', 'unifiedtoolkit.netlify.app', 'unifiedtoolkit.onrender.com'],
  },
  // Output configuration for static deployment
  output: 'export',
  // API configuration
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000',
  },
  // Netlify configuration
  trailingSlash: false,
  distDir: '.next',
  experimental: {
    optimizePackageImports: ['@radix-ui/react-icons', 'lucide-react'],
  },
  // Exclude API routes from the build
  pageExtensions: ['tsx', 'ts', 'jsx', 'js'].filter(ext => 
    !process.env.NETLIFY || ext.startsWith('page.')
  ),
  // Optimized webpack configuration
  webpack: (config, { dev, isServer }) => {
    // Node.js polyfills for browser compatibility
    if (!isServer) {
      config.resolve.fallback = {
        ...config.resolve.fallback,
        fs: false,
        net: false,
        tls: false,
        crypto: 'crypto-browserify',
        path: false,
        stream: 'stream-browserify',
        buffer: 'buffer/',
        util: 'util/',
        assert: 'assert/',
        https: 'https-browserify',
        http: 'stream-http',
        os: 'os-browserify/browser',
        url: 'url/',
        zlib: 'browserify-zlib'
      }
    }

    // Typescript module resolution
    config.resolve = {
      ...config.resolve,
      modules: ['node_modules', 'lib'],
      extensions: ['.ts', '.tsx', '.js', '.jsx', '.json']
    }
    
    return config
  },
}

export default nextConfig
