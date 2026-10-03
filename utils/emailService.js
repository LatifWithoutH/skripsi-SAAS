const nodemailer = require('nodemailer');

// Buat transporter sekali saja agar efisien
const transporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST,
    port: process.env.EMAIL_PORT,
    secure: false, // false untuk port 587
    auth: {
        user: process.env.EMAIL_USER,
        pass: process.env.EMAIL_PASS,
    },
});

// Definisikan fungsinya
const sendInviteEmail = async (email, tempPassword, unitName, roleName) => {
    const mailOptions = {
        from: process.env.EMAIL_FROM,
        to: email,
        subject: 'Undangan Bergabung ke SI-MITRA-DUDIKA',
        html: `
            <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 8px;">
                <h2 style="color: #4f46e5;">Undangan Akses Sistem</h2>
                <p>Halo,</p>
                <p>Anda telah diundang untuk bergabung sebagai pengelola di sistem <strong>SI-MITRA-DUDIKA</strong>.</p>
                
                <div style="background-color: #f3f4f6; padding: 15px; border-radius: 6px; margin: 20px 0;">
                    <p style="margin: 5px 0;"><strong>Peran Akses:</strong> ${roleName.replace('_', ' ').toUpperCase()}</p>
                    <p style="margin: 5px 0;"><strong>Unit/Fakultas:</strong> ${unitName || 'Seluruh Institusi'}</p>
                    <p style="margin: 5px 0;"><strong>Email Login:</strong> ${email}</p>
                    <p style="margin: 5px 0;"><strong>Password Sementara:</strong> <span style="font-family: monospace; background: #e5e7eb; padding: 2px 6px; border-radius: 4px;">${tempPassword}</span></p>
                </div>

                <p>Silakan login di <a href="http://localhost:3000/login" style="color: #4f46e5; text-decoration: none;">http://localhost:3000/login</a> dan ganti password Anda segera setelah login pertama kali.</p>
                
                <p style="color: #6b7280; font-size: 12px; margin-top: 30px;">
                    * Email ini dikirim secara otomatis oleh sistem. Mohon jangan membalas email ini.
                </p>
            </div>
        `
    };

    try {
        await transporter.sendMail(mailOptions);
        console.log(`✅ [EMAIL] Undangan berhasil dikirim ke ${email}`);
        return true;
    } catch (error) {
        console.error('❌ [EMAIL] Gagal mengirim email:', error.message);
        return false;
    }
};

// EKSPOR FUNGSI INI
module.exports = { sendInviteEmail };