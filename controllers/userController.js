import User from "../models/userModel.js";

export const getProfile = (req, res) => {
  res.json({
    message: "Profile accessed successfully",
    user: req.user,
  });
};

export const updateProfile = async (req, res) => {
  try {
    const updatedUser = await User.findByIdAndUpdate(
      req.user.userId,
      req.body,
      { new: true }
    );
    res.json(updatedUser);
  } catch (error) {
    res.status(400).json({ message: error.message });
  }
};