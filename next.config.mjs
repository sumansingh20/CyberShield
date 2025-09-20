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
  // Output configuration
  output: 'standalone', // Using standalone for SSR support
  // API configuration
  async rewrites() {
    return process.env.NETLIFY ? [] : [
      {
        source: '/api/:path*',
        destination: process.env.NEXT_PUBLIC_API_URL ? 
          `${process.env.NEXT_PUBLIC_API_URL}/api/:path*` : 
          'http://localhost:3000/api/:path*',
      },
    ];
  },
  env: {
    NEXT_PUBLIC_API_URL: process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3000',
  },
  // Netlify configuration
  trailingSlash: false,
  distDir: '.next',
  experimental: {
    optimizePackageImports: ['@radix-ui/react-icons', 'lucide-react'],
  },
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
