// controllers/platformAuthController.js
const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');

// 1. Tampilkan Halaman Login Platform
exports.showLogin = (req, res) => {
    // Cek session KHUSUS platform admin
    if (req.session && req.session.platformAdminId) {
        return res.redirect('/platform/dashboard');
    }
    res.render('platform/login', { error: req.query.error });
};

// 2. Proses Login Platform
exports.handleLogin = async (req, res) => {
    try {
        const { email, password } = req.body;

        // 🔒 PERUBAHAN: Query HANYA ke tabel platform_admins, BUKAN tabel users
        const adminQuery = `
            SELECT id, name, email, password_hash, role
            FROM platform_admins
            WHERE email = $1
        `;
        const result = await pool.query(adminQuery, [email]);
        
        if (result.rows.length === 0) {
            return res.redirect('/platform/login?error=Email atau password salah.');
        }

        const admin = result.rows[0];

        // Verifikasi password
        const isMatch = await bcrypt.compare(password, admin.password_hash);
        if (!isMatch) {
            return res.redirect('/platform/login?error=Email atau password salah.');
        }

        // Set session KHUSUS platform (gunakan prefix 'platform' agar tidak bentrok dengan session tenant)
        req.session.platformAdminId = admin.id;
        req.session.platformRole = admin.role;
        req.session.userName = admin.name;

        res.redirect('/platform/dashboard');
    } catch (err) {
        console.error('❌ [PLATFORM AUTH] Error:', err);
        res.redirect('/platform/login?error=Terjadi kesalahan pada server.');
    }
};

// 3. Logout Platform
exports.logout = (req, res) => {
    req.session.destroy((err) => {
        if (err) console.error('Error saat logout platform:', err);
        res.redirect('/platform/login');
    });
};