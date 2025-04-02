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
        isCompleted: { type: Boolean, default: false },
        twoFactorEnabled: { type: Boolean, default: false },
        createdAt: { type: Date, default: Date.now },
        updatedAt: { type: Date, default: Date.now },
    }
);

export default mongoose.model("User", userSchema);