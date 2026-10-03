const { pool } = require('../config/database'); // <--- Tambahkan kurung kurawal {}
const bcrypt = require('bcryptjs');

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // 1. Cari user berdasarkan email        
        const userQuery = `
            SELECT u.id, u.name, u.email, u.password_hash, u.status, 
                   u.tenant_id, u.unit_id, r.name as role_name
            FROM users u
            JOIN roles r ON u.role_id = r.id
            WHERE u.email = $1
        `;
        
        const result = await pool.query(userQuery, [email]);    
            
        if (result.rows.length === 0) {
            return res.status(401).render('public/login', { 
                error: 'Email atau password salah.',
                oldInput: { email }
            });
        }

        const user = result.rows[0];

        // 2. Cek status akun
        if (user.status === 'suspended') {
            return res.status(403).render('public/login', { 
                error: 'Akun Anda telah dinonaktifkan. Hubungi admin.',
                oldInput: { email }
            });
        }

        // 3. Verifikasi password (bcrypt)
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            // TODO: Nanti kita log ke tabel audit_logs di sini (Nilai plus keamanan!)
            return res.status(401).render('public/login', { 
                error: 'Email atau password salah.',
                oldInput: { email }
            });
        }

        // 4. Jika sukses, simpan data penting ke Session
        req.session.userId = user.id;
        req.session.tenantId = user.tenant_id;
        req.session.role = user.role_name;
        req.session.userName = user.name;
        req.session.unitId = user.unit_id; // ✅ TAMBAHKAN INI!
        
        // Ambil nama unit jika ada (untuk ditampilkan di UI)
        if (user.unit_id) {
            const unitQuery = `SELECT name FROM units WHERE id = $1`;
            const unitResult = await pool.query(unitQuery, [user.unit_id]);
            if (unitResult.rows.length > 0) {
                req.session.unitName = unitResult.rows[0].name;
            }
        }
        // 5. Redirect sesuai role
        if (user.role_name === 'tenant_owner' || user.role_name === 'it_admin') {
            return res.redirect('/dashboard');
        } else {
            return res.redirect('/dashboard'); // Bisa disesuaikan nanti
        }

    } catch (err) {
        console.error('❌ [AUTH] Error saat login:', err);
        res.status(500).render('public/login', { error: 'Terjadi kesalahan pada server.' });
    }
};

exports.logout = (req, res) => {
    req.session.destroy((err) => {
        if (err) console.error('Error saat logout:', err);
        res.redirect('/login');
    });
};