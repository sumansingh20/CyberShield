import mongoose from "mongoose"

// MongoDB URI is required for all environments
const MONGODB_URI = process.env.MONGODB_URI || ""

interface MongooseCache {
  conn: typeof mongoose | null
  promise: Promise<typeof mongoose> | null
}

declare global {
  var myMongoose: MongooseCache | undefined
}

let cached = global.myMongoose

if (!cached) {
  cached = global.myMongoose = { conn: null, promise: null }
}

async function connectDB() {
  // If no MongoDB URI, skip connecting and run in degraded mode.
  if (!MONGODB_URI) {
    console.warn("MONGODB_URI is not set. Database features are disabled.")
    return null as any
  }

  if (cached!.conn) {
    return cached!.conn
  }

  if (!cached!.promise) {
    const opts = {
      bufferCommands: false,
      serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
      connectTimeoutMS: 5000,
      maxPoolSize: 10,
    }

    cached!.promise = mongoose.connect(MONGODB_URI, opts)
  }

  try {
    cached!.conn = await cached!.promise
    console.log("✅ MongoDB connected successfully - Real database active")
  } catch (e) {
    cached!.promise = null
    console.error("❌ MongoDB connection failed:", e)
    throw new Error("Failed to connect to MongoDB. Please check your connection string and database status.")
  }

  return cached!.conn
}

export default connectDB
