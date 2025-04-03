import mongoose from "mongoose";

const userSchema = mongoose.Schema(
  {
    firstName: { type: String, required: true },
    lastName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ["healthcare_professional", "institution"], required: true },
    phoneNumber: { type: String },
    address: {
      street: String,
      city: String,
      state: String,
      zipCode: String,
      country: String,
    },
    isVerified: { type: Boolean, default: false },
    verificationToken: String,
    passwordResetToken: String,
    passwordResetExpires: Date,
    passwordChangedAt: Date,
    refreshToken: String,
    isCompleted: { type: Boolean, default: false },
    twoFactorEnabled: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now },
    updatedAt: { type: Date, default: Date.now },
  },
  {
    toJSON: { virtuals: true },
    toObject: { virtuals: true }
  }
);

// Middleware to update passwordChangedAt when password is modified
userSchema.pre('save', function(next) {
  if (!this.isModified('password') || this.isNew) return next();

  this.passwordChangedAt = Date.now() - 1000; // Subtract 1 second to ensure token is created after
  next();
});

export default mongoose.model("User", userSchema);