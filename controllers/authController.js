const { pool } = require('../config/database');
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

        // ✅ GATEKEEPER 1: Cek status user (pending_approval / rejected)
        if (user.status === 'pending_approval') {
            return res.status(403).render('public/login', { 
                error: 'Akun institusi Anda masih dalam proses review oleh admin platform. Silakan cek email secara berkala.',
                oldInput: { email }
            });
        }
        if (user.status === 'rejected') {
            return res.status(403).render('public/login', { 
                error: 'Pendaftaran institusi Anda telah ditolak. Hubungi admin untuk informasi lebih lanjut.',
                oldInput: { email }
            });
        }

        // ✅ GATEKEEPER 2: Cek status tenant
        const tenantQuery = `SELECT status FROM tenants WHERE id = $1`;
        const tenantResult = await pool.query(tenantQuery, [user.tenant_id]);
        const tenant = tenantResult.rows[0];

        if (tenant.status === 'pending_approval') {
             return res.status(403).render('public/login', { 
                 error: 'Akun institusi masih dalam review admin.', 
                 oldInput: { email } 
             });
        }

        if (tenant.status === 'suspended') {
             return res.status(403).render('public/login', { 
                 error: 'Akun institusi Anda telah ditangguhkan. Hubungi admin platform.', 
                 oldInput: { email } 
             });
        }

        // 3. Verifikasi password (bcrypt)
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) {
            // 🛡️ A09 FIX: Catat percobaan login gagal untuk deteksi Brute-Force
            const auditQuery = `
                INSERT INTO audit_logs (tenant_id, user_id, action, target_table, details, ip_address, user_agent)
                VALUES ($1, NULL, 'LOGIN_FAILED', 'users', $2, $3, $4)
            `;
            await pool.query(auditQuery, [
                user.tenant_id, 
                JSON.stringify({ email: email, reason: 'wrong_password' }),
                req.ip || req.connection.remoteAddress,
                req.headers['user-agent'] || 'Unknown'
            ]);

            return res.status(401).render('public/login', { 
                error: 'Email atau password salah.',
                oldInput: { email }
            });
        }

        // 4. Jika sukses, simpan data penting ke Session
        req.session.userId = user.id;
        req.session.tenantId = user.tenant_id; // 🔑 KUNCI MULTI-TENANT
        req.session.role = user.role_name;
        req.session.userName = user.name;
        req.session.unitId = user.unit_id; 
        
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
            return res.redirect('/dashboard'); // Bisa disesuaikan nanti untuk faculty_operator
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