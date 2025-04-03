import nodemailer from 'nodemailer';

 // For PRODUCTION
// const transporter = nodemailer.createTransport({
  

  
//   // host: process.env.EMAIL_HOST,
//   // port: process.env.EMAIL_PORT,
//   // secure: true,  
//   // auth: {
//   //   user: process.env.EMAIL_USER,
//   //   pass: process.env.EMAIL_PASS
//   // },
  

// });

// // Test connection
// transporter.verify(function(error, success) {
//   if (error) {
//     console.log('SMTP Connection Error:', error);
//   } else {
//     console.log('Successfully connected to Mailtrap');
//   }
// });

// export const sendWelcomeEmail = async (email, name, token) => {
//   try {
//     const verificationUrl = `${process.env.FRONTEND_URL}/verify-email?token=${token}`;
    
//     await transporter.sendMail({
//       from: process.env.EMAIL_FROM,
//       to: email,
//       subject: 'Verify Your Email',
//       html: `<p>Click <a href="${verificationUrl}">here</a> to verify</p>`
//     });
//     console.log('Test email sent to Mailtrap inbox');
//   } catch (error) {
//     console.error('Email sending error:', error);
//     throw error;
//   }
// };

// Use hardcoded Mailtrap values temporarily for testing
const transporter = nodemailer.createTransport({
  host: 'sandbox.smtp.mailtrap.io', 
  port: 2525,
  secure: false, 
  auth: {
    user: '7d3a8e0741e418', 
    pass: '0c6904a0cd28d7'  
  },
  tls: {
    rejectUnauthorized: false 
  }
});

// Test connection immediately
transporter.verify(function(error, success) {
  if (error) {
    console.error('❌ SMTP Connection Failed:', error);
  } else {
    console.log('✅ Successfully connected to Mailtrap');
  }
});

export const sendWelcomeEmail = async (email, name, verificationUrl) => {
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_FROM || 'contact@zidi.com',
      to: email,
      subject: 'Vérification de votre email',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2 style="color: #2c3e50;">Bonjour ${name},</h2>
          <p style="color: #34495e; line-height: 1.6;">
            Merci pour votre inscription. Veuillez cliquer sur le bouton ci-dessous pour vérifier votre adresse email:
          </p>
          <div style="text-align: center; margin: 30px 0;">
            <a href="${verificationUrl}" style="
              display: inline-block;
              padding: 12px 24px;
              background-color: #0abab5;
              color: white;
              text-decoration: none;
              border-radius: 4px;
              font-weight: bold;
            ">Vérifier mon email</a>
          </div>
          <p style="color: #7f8c8d; font-size: 14px;">
            Si vous n'avez pas demandé cette inscription, veuillez ignorer cet email.
          </p>
        </div>
      `
    });
    console.log(`Verification email sent to ${email}`);
  } catch (error) {
    console.error('Failed to send welcome email:', error);
    throw new Error('Failed to send verification email');
  }
};

export const sendPasswordResetEmail = async (email, token) => {
  const resetUrl = `${process.env.FRONTEND_URL}/reset-password?token=${token}`;
  await transporter.sendMail({
    from: `"Your App Name" <${process.env.EMAIL_FROM}>`,
    to: email,
    subject: 'Password Reset Request',
    html: `
      <div>
        <h2>Password Reset</h2>
        <p>Click the button below to reset your password:</p>
        <a href="${resetUrl}" style="
          display: inline-block;
          padding: 10px 20px;
          background-color: #4CAF50;
          color: white;
          text-decoration: none;
          border-radius: 5px;
          margin-top: 20px;
        ">Reset Password</a>
        <p>This link expires in 1 hour.</p>
      </div>
    `
  });
};