import express from "express";
import { getProfile, updateProfile } from "../controllers/userController.js";
import { authenticateUser } from "../middleware/authMiddleware.js";

const router = express.Router();

router.use(authenticateUser);

router.get("/profile", getProfile);
router.patch("/profile", updateProfile);

export default router;