import mongoose from "mongoose"

// MongoDB URI is required for all environments
const MONGODB_URI = process.env.MONGODB_URI

if (!MONGODB_URI) {
  throw new Error("MONGODB_URI environment variable is required. Please set up your MongoDB connection string.")
}

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
