import mongoose from "mongoose"

// MongoDB URI - Priority: Vercel env var, then .env.local, then local fallback
const MONGODB_URI = 
  process.env.MONGODB_URI || 
  process.env.DATABASE_URL || 
  "mongodb://localhost:27017/cybersec-platform"

if (!MONGODB_URI) {
  throw new Error(
    "Please define the MONGODB_URI environment variable inside .env.local or Vercel environment variables"
  )
}

interface MongooseCache {
  conn: typeof mongoose | null
  promise: Promise<typeof mongoose> | null
}

declare global {
  var mongoose: MongooseCache | undefined
}

let cached = global.mongoose

if (!cached) {
  cached = global.mongoose = { conn: null, promise: null }
}

async function connectDB(): Promise<typeof mongoose> {
  if (cached!.conn) {
    return cached!.conn
  }

  if (!cached!.promise) {
    const opts = {
      bufferCommands: false,
      // Production settings for Vercel/Atlas
      serverSelectionTimeoutMS: 5000, // 5 seconds
      connectTimeoutMS: 5000, // 5 seconds  
      socketTimeoutMS: 15000, // 15 seconds
      maxPoolSize: 10, // Maximum number of connections
      minPoolSize: 1, // Minimum number of connections for production
      retryWrites: true,
      retryReads: true,
      autoIndex: process.env.NODE_ENV === 'development', // Only build indexes in development
      maxIdleTimeMS: 30000, // Close connections after 30 seconds of inactivity
    }

    cached!.promise = mongoose.connect(MONGODB_URI, opts)
  }

  try {
    cached!.conn = await cached!.promise
    
    if (process.env.NODE_ENV === 'development') {
      console.log("✅ Connected to MongoDB successfully")
    }
    
    return cached!.conn
  } catch (error) {
    cached!.promise = null
    console.error("❌ MongoDB connection error:", error)
    
    // In production, throw a more user-friendly error
    if (process.env.NODE_ENV === 'production') {
      throw new Error('Database connection failed. Please try again later.')
    }
    
    throw error
  }
}

// Connection event listeners
mongoose.connection.on('connected', () => {
  console.log('🔗 Mongoose connected to MongoDB')
})

mongoose.connection.on('error', (error) => {
  console.error('❌ Mongoose connection error:', error)
})

mongoose.connection.on('disconnected', () => {
  console.log('🔌 Mongoose disconnected from MongoDB')
})

// Handle process termination
process.on('SIGINT', async () => {
  await mongoose.connection.close()
  console.log('🔌 MongoDB connection closed through app termination')
  process.exit(0)
})

export { connectDB }
export default connectDB
