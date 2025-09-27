import mongoose from "mongoose"

export interface IOTP extends mongoose.Document {
  userId: mongoose.Types.ObjectId
  email: string
  phone: string
  emailOTP: string
  phoneOTP: string
  purpose: "login" | "forgot-password" | "registration"
  expiresAt: Date
  attempts: number
  maxAttempts: number
  createdAt: Date
}

const otpSchema = new mongoose.Schema(
  {
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
    },
    email: {
      type: String,
      required: true,
    },
    phone: {
      type: String,
      required: true,
    },
    emailOTP: {
      type: String,
      required: true,
    },
    phoneOTP: {
      type: String,
      required: true,
    },
    purpose: {
      type: String,
      enum: ["login", "forgot-password", "registration"],
      required: true,
    },
    expiresAt: {
      type: Date,
      required: true,
      default: () => new Date(Date.now() + 10 * 60 * 1000), // 10 minutes
    },
    attempts: {
      type: Number,
      default: 0,
    },
    maxAttempts: {
      type: Number,
      default: 3,
    },
  },
  {
    timestamps: true,
  },
)

otpSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 })

export default mongoose.models.OTP || mongoose.model<IOTP>("OTP", otpSchema)
