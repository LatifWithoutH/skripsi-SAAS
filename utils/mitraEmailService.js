const { Resend } = require('resend');

// Inisialisasi Resend
const resend = new Resend(process.env.RESEND_API_KEY);

/**
 * Mengirim email undangan khusus untuk PIC Mitra Industri
 * @param {string} email - Email PIC Mitra
 * @param {string} companyName - Nama Perusahaan Mitra
 * @param {string} universityName - Nama Universitas yang mengundang
 * @param {string} tempPassword - Password sementara
 */
const sendMitraInviteEmail = async (email, companyName, universityName, tempPassword) => {
    try {
        const { data, error } = await resend.emails.send({
            from: process.env.EMAIL_FROM || 'SI-MITRA-DUDIKA <onboarding@resend.dev>',
            to: [email],
            subject: `Undangan Kerjasama Resmi - ${universityName} x ${companyName}`,
            html: `
                <div style="font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; max-width: 600px; margin: 0 auto; padding: 0; border: 1px solid #e5e7eb; border-radius: 8px; overflow: hidden;">
                    <!-- Header Korporat -->
                    <div style="background-color: #4f46e5; padding: 25px 20px; text-align: center;">
                        <h1 style="color: white; margin: 0; font-size: 24px; letter-spacing: 1px;">SI-MITRA-DUDIKA</h1>
                        <p style="color: #e0e7ff; margin: 5px 0 0 0; font-size: 13px;">Portal Manajemen Kerjasama Industri & Akademik</p>
                    </div>
                    
                    <div style="padding: 30px 25px;">
                        <h2 style="color: #1f2937; margin-top: 0; font-size: 20px;">Halo, Tim ${companyName}!</h2>
                        <p style="color: #4b5563; line-height: 1.6;">
                            Anda telah diundang oleh <strong>${universityName}</strong> untuk bergabung sebagai Mitra Resmi dalam platform digitalisasi MoU/MoA/IA kami.
                        </p>
                        
                        <!-- Box Informasi Login -->
                        <div style="background-color: #f9fafb; padding: 20px; border-radius: 8px; margin: 25px 0; border-left: 4px solid #4f46e5;">
                            <p style="margin: 5px 0; color: #374151; font-size: 14px;"><strong>Perusahaan:</strong> ${companyName}</p>
                            <p style="margin: 5px 0; color: #374151; font-size: 14px;"><strong>Mengundang:</strong> ${universityName}</p>
                            <p style="margin: 5px 0; color: #374151; font-size: 14px;"><strong>Email Login:</strong> ${email}</p>
                            <p style="margin: 15px 0 5px 0; color: #374151; font-size: 14px;"><strong>Password Sementara:</strong></p>
                            <code style="display: block; background: #e5e7eb; padding: 10px; border-radius: 4px; font-size: 18px; font-weight: bold; color: #1f2937; text-align: center; letter-spacing: 2px;">${tempPassword}</code>
                        </div>

                        <p style="color: #4b5563; line-height: 1.6;">
                            Silakan login ke Portal Mitra untuk melihat detail dokumen kerjasama dan mengelola profil perusahaan Anda:
                        </p>
                        
                        <!-- Tombol CTA -->
                        <div style="text-align: center; margin: 35px 0;">
                            <a href="http://localhost:3000/portal-mitra/login" style="background-color: #4f46e5; color: white; padding: 14px 28px; text-decoration: none; border-radius: 6px; font-weight: bold; font-size: 16px; display: inline-block; transition: background 0.3s;">Login ke Portal Mitra</a>
                        </div>
                        
                        <p style="color: #6b7280; font-size: 12px; margin-top: 30px; border-top: 1px solid #e5e7eb; padding-top: 15px; line-height: 1.5;">
                            * Email ini dikirim secara otomatis oleh sistem SI-MITRA-DUDIKA. Mohon jangan membalas email ini. Jika Anda merasa tidak mendaftar, abaikan email ini.
                        </p>
                    </div>
                </div>
            `
        });

        if (error) {
            console.error('❌ [RESEND MITRA] Gagal mengirim email:', error);
            return false;
        }

        console.log(`✅ [RESEND MITRA] Undangan mitra berhasil dikirim ke ${email}. ID: ${data.id}`);
        return true;
    } catch (err) {
        console.error('❌ [RESEND MITRA] Error sistem:', err);
        return false;
    }
};

module.exports = { sendMitraInviteEmail };