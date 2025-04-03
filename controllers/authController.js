import User from '../models/userModel.js';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import { sendWelcomeEmail, sendPasswordResetEmail } from '../utils/email.js';

export const signup = async (req, res) => {
  try {
    const { firstName, lastName, email, password, role, phoneNumber } = req.body;

    // Validate required fields
    if (!firstName || !lastName || !email || !password || !role) {
      return res.status(400).json({ 
        success: false,
        message: 'Tous les champs requis doivent être remplis' 
      });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(409).json({ 
        success: false,
        message: 'Cet email est déjà utilisé' 
      });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 12);

    // Create verification token (expires in 24 hours)
    const verificationToken = jwt.sign(
      { email },
      process.env.JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Create new user
    const newUser = await User.create({
      firstName,
      lastName,
      email,
      password: hashedPassword,
      role,
      phoneNumber,
      verificationToken,
      isVerified: false
    });

    // Send welcome email with verification link
    const verificationUrl = `${process.env.FRONTEND_URL}/verify-email/${verificationToken}`;
    await sendWelcomeEmail(email, firstName, verificationUrl);

    // Return response without sensitive data
    res.status(201).json({
      success: true,
      message: 'Compte créé avec succès. Veuillez vérifier votre email.',
      user: {
        _id: newUser._id,
        firstName: newUser.firstName,
        email: newUser.email,
        role: newUser.role
      }
    });

  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Erreur interne du serveur',
      error: error.message 
    });
  }
};

export const login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'Identifiants invalides' 
      });
    }

    // Check if account is verified
    if (!user.isVerified) {
      return res.status(403).json({ 
        success: false,
        message: 'Compte non vérifié. Veuillez vérifier votre email.' 
      });
    }

    // Validate password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ 
        success: false,
        message: 'Identifiants invalides' 
      });
    }

    // Generate tokens
    const accessToken = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
    );

    const refreshToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_REFRESH_SECRET,
      { expiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d' }
    );

    // Save refresh token
    user.refreshToken = refreshToken;
    await user.save();

    // Set HTTP-only cookie for refresh token
    res.cookie('refreshToken', refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
    });

    // Return response
    res.json({
      success: true,
      accessToken,
      expiresIn: process.env.JWT_EXPIRES_IN || 900, // 15 minutes in seconds
      user: {
        _id: user._id,
        firstName: user.firstName,
        email: user.email,
        role: user.role
      }
    });

  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Erreur interne du serveur' 
    });
  }
};

export const verifyEmail = async (req, res) => {
  try {
    const { token } = req.body;
    
    // Verify token and find matching user
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({ 
      email: decoded.email,
      verificationToken: token
    });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Lien de vérification invalide ou expiré' 
      });
    }

    // Update user as verified
    user.isVerified = true;
    user.verificationToken = undefined;
    await user.save();

    res.json({ 
      success: true,
      message: 'Email vérifié avec succès. Vous pouvez maintenant vous connecter.' 
    });

  } catch (error) {
    console.error('Verification error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ 
        success: false,
        message: 'Le lien de vérification a expiré. Veuillez en demander un nouveau.' 
      });
    }
    
    res.status(400).json({ 
      success: false,
      message: 'Lien de vérification invalide' 
    });
  }
};

export const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).json({ 
        success: false,
        message: 'Utilisateur non trouvé' 
      });
    }

    const resetToken = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    user.passwordResetToken = resetToken;
    user.passwordResetExpires = Date.now() + 3600000; // 1 hour
    await user.save();

    const resetUrl = `${process.env.FRONTEND_URL}/reset-password/${resetToken}`;
    await sendPasswordResetEmail(email, resetUrl);

    res.json({
      success: true,
      message: 'Lien de réinitialisation du mot de passe envoyé à votre email'
    });

  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Erreur interne du serveur' 
    });
  }
};

export const resetPassword = async (req, res) => {
  try {
    const { token, newPassword } = req.body;

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findOne({
      _id: decoded.userId,
      passwordResetToken: token,
      passwordResetExpires: { $gt: Date.now() }
    });

    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: 'Lien de réinitialisation invalide ou expiré' 
      });
    }

    user.password = await bcrypt.hash(newPassword, 12);
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.passwordChangedAt = Date.now();
    await user.save();

    res.json({
      success: true,
      message: 'Mot de passe réinitialisé avec succès'
    });

  } catch (error) {
    console.error('Reset password error:', error);
    if (error.name === 'TokenExpiredError') {
      return res.status(400).json({ 
        success: false,
        message: 'Lien de réinitialisation expiré' 
      });
    }
    res.status(400).json({ 
      success: false,
      message: 'Lien de réinitialisation invalide' 
    });
  }
};

export const refreshToken = async (req, res) => {
  try {
    const refreshToken = req.cookies.refreshToken || req.body.refreshToken;
    
    if (!refreshToken) {
      return res.status(401).json({ 
        success: false,
        message: 'Token de rafraîchissement manquant' 
      });
    }

    // Verify refresh token
    const decoded = jwt.verify(refreshToken, process.env.JWT_REFRESH_SECRET);
    const user = await User.findById(decoded.userId);

    // Check if token is valid
    if (!user || user.refreshToken !== refreshToken) {
      return res.status(401).json({ 
        success: false,
        message: 'Token de rafraîchissement invalide' 
      });
    }

    // Generate new access token
    const newAccessToken = jwt.sign(
      { userId: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: process.env.JWT_EXPIRES_IN || '15m' }
    );

    res.json({ 
      success: true,
      accessToken: newAccessToken,
      expiresIn: process.env.JWT_EXPIRES_IN || 900 // 15 minutes in seconds
    });

  } catch (error) {
    console.error('Refresh token error:', error);
    
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        success: false,
        message: 'Session expirée. Veuillez vous reconnecter.' 
      });
    }
    
    res.status(401).json({ 
      success: false,
      message: 'Token de rafraîchissement invalide' 
    });
  }
};

export const logout = async (req, res) => {
  try {
    // Clear refresh token from user and cookie
    const userId = req.user.userId;
    await User.findByIdAndUpdate(userId, { refreshToken: null });

    res.clearCookie('refreshToken');
    res.json({ 
      success: true,
      message: 'Déconnexion réussie' 
    });

  } catch (error) {
    console.error('Logout error:', error);
    res.status(500).json({ 
      success: false,
      message: 'Erreur interne du serveur' 
    });
  }
};