import express from "express";
import { getProfile, updateProfile } from "../controllers/userController.js";
import { authenticate } from "../middleware/authMiddleware.js";

const router = express.Router();

router.use(authenticate);

router.get("/profile", getProfile);
router.patch("/profile", updateProfile);

export default router;