const { Resend } = require('resend');
const { getTenantUrl } = require('./urlHelper'); // ✅ 1. IMPORT HELPER BARU

const resend = new Resend(process.env.RESEND_API_KEY);

// ✅ 2. TAMBAHKAN PARAMETER 'tenantSlug' di sini
const sendInviteEmail = async (email, tempPassword, unitName, roleName, tenantSlug) => {
    try {
        // ✅ 3. GENERATE URL DINAMIS (Contoh hasil: http://ums.saas.local:3000/login)
        const loginUrl = getTenantUrl(tenantSlug, '/login');

        const { data, error } = await resend.emails.send({
            from: process.env.EMAIL_FROM || 'SI-MITRA-DUDIKA <onboarding@resend.dev>',
            to: [email],
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

                    <!-- ✅ 4. GUNAKAN VARIABLE loginUrl YANG SUDAH DINAMIS -->
                    <p>Silakan login di <a href="${loginUrl}" style="color: #4f46e5; text-decoration: none; font-weight: bold;">${loginUrl}</a> dan ganti password Anda segera setelah login pertama kali.</p>
                    
                    <p style="color: #6b7280; font-size: 12px; margin-top: 30px;">
                        * Email ini dikirim secara otomatis oleh sistem. Mohon jangan membalas email ini.
                    </p>
                </div>
            `,
        });

        if (error) {
            console.error('❌ [RESEND] Gagal mengirim email:', error);
            return false;
        }

        console.log(`✅ [RESEND] Undangan berhasil dikirim ke ${email}. ID: ${data.id}`);
        return true;
    } catch (err) {
        console.error('❌ [RESEND] Error sistem:', err);
        return false;
    }
};

module.exports = { sendInviteEmail };