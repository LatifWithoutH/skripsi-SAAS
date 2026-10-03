// PERHATIAN: Sesuai komentar Anda, jika database.js mengexport pool secara langsung (module.exports = pool), 
// maka JANGAN gunakan kurung kurawal {}. Gunakan baris di bawah ini:
const {pool} = require('../config/database'); 

// Jika ternyata database.js mengexport object { pool }, maka gunakan:
// const { pool } = require('../config/database');

// 1. Menampilkan Halaman & Data User
exports.getUsersPage = async (req, res) => {
    try {
        const tenantId = req.session.tenantId;

        // 1. HITUNG STATISTIK REAL-TIME
        const statsQuery = `
            SELECT 
                COUNT(*) FILTER (WHERE status != 'deleted') AS total,
                COUNT(*) FILTER (WHERE status = 'active') AS active,
                COUNT(*) FILTER (WHERE status = 'pending_invite') AS pending
            FROM users 
            WHERE tenant_id = $1
        `;

        // 2. QUERY ROLE & UNIT (Dipindah ke dalam fungsi agar bisa mengakses tenantId)
        const rolesQuery = `SELECT id, name FROM roles WHERE name != 'tenant_owner' ORDER BY name ASC`;
        const unitsQuery = `SELECT id, name, code FROM units WHERE tenant_id = $1 ORDER BY name ASC`;

        // 3. AMBIL DAFTAR USER LENGKAP DENGAN ROLE & UNIT (LEFT JOIN)
        const usersQuery = `
            SELECT 
                u.id, u.name, u.email, u.status, u.created_at,
                r.name AS role_name,
                un.name AS unit_name,
                un.code AS unit_code
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.id
            LEFT JOIN units un ON u.unit_id = un.id
            WHERE u.tenant_id = $1 AND u.status != 'deleted'
            ORDER BY u.created_at DESC
        `;

        // Jalankan semua query secara paralel (Promise.all) agar lebih efisien (hanya 1x tunggu)
        const [statsResult, rolesResult, unitsResult, usersResult] = await Promise.all([
            pool.query(statsQuery, [tenantId]),
            pool.query(rolesQuery),
            pool.query(unitsQuery, [tenantId]),
            pool.query(usersQuery, [tenantId])
        ]);

        // 4. RENDER KE EJS
        res.render('tenant/users', {
            user: { name: req.session.userName, role: req.session.role },
            stats: statsResult.rows[0],
            users: usersResult.rows,
            success: req.query.success,
            error: req.query.error,
            roles: rolesResult.rows,   // <-- WAJIB ADA
            units: unitsResult.rows    // <-- WAJIB ADA
        });

    } catch (err) {
        console.error('❌ [USERS] Error mengambil data:', err);
        res.status(500).send('Terjadi kesalahan saat memuat data pengguna.');
    }
};

// 2. Mengaktifkan User (Ubah status dari pending_invite ke active)
exports.activateUser = async (req, res) => {
    try {
        const userId = req.params.id;
        const tenantId = req.session.tenantId;
        const adminId = req.session.userId;

        // 🔒 KEAMANAN: Pastikan user yang diaktifkan benar-benar milik tenant ini & masih pending
        const checkQuery = `
            SELECT id, name, email FROM users 
            WHERE id = $1 AND tenant_id = $2 AND status = 'pending_invite'
        `;
        const checkResult = await pool.query(checkQuery, [userId, tenantId]);

        if (checkResult.rows.length === 0) {
            return res.redirect('/users?error=not_found_or_already_active');
        }

        const targetUser = checkResult.rows[0];

        // ✅ UPDATE STATUS MENJADI ACTIVE
        const updateQuery = `
            UPDATE users 
            SET status = 'active'
            WHERE id = $1 AND tenant_id = $2
        `;
        await pool.query(updateQuery, [userId, tenantId]);

        // 🛡️ AUDIT LOG: Catat aktivasi user
        const auditQuery = `
            INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address)
            VALUES ($1, $2, 'ACTIVATE_USER', 'users', $3, $4, $5)
        `;
        await pool.query(auditQuery, [
            tenantId,
            adminId,
            userId,
            JSON.stringify({ activated_user: targetUser.email }),
            req.ip
        ]);

        res.redirect('/users?success=activated');

    } catch (err) {
        console.error('❌ [USERS] Error mengaktifkan user:', err);
        res.redirect('/users?error=server_error');
    }
};

// 3. Menghapus User (Soft delete: ubah status jadi 'deleted')
exports.deleteUser = async (req, res) => {
    try {
        const userId = req.params.id;
        const tenantId = req.session.tenantId;
        const adminId = req.session.userId;

        // 🔒 KEAMANAN: Cegah admin menghapus diri sendiri
        if (userId === adminId) {
            return res.redirect('/users?error=cannot_delete_self');
        }

        // 🔒 KEAMANAN: Pastikan user milik tenant ini
        const checkQuery = `SELECT id, email FROM users WHERE id = $1 AND tenant_id = $2 AND status != 'deleted'`;
        const checkResult = await pool.query(checkQuery, [userId, tenantId]);

        if (checkResult.rows.length === 0) {
            return res.redirect('/users?error=not_found');
        }

        const targetUser = checkResult.rows[0];

        // ✅ SOFT DELETE (Ubah status jadi deleted, data tetap ada untuk audit)
        await pool.query(`UPDATE users SET status = 'deleted' WHERE id = $1 AND tenant_id = $2`, [userId, tenantId]);

        // 🛡️ AUDIT LOG
        const auditQuery = `
            INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address)
            VALUES ($1, $2, 'DELETE_USER', 'users', $3, $4, $5)
        `;
        await pool.query(auditQuery, [
            tenantId, adminId, userId,
            JSON.stringify({ deleted_user: targetUser.email }),
            req.ip
        ]);

        res.redirect('/users?success=deleted');

    } catch (err) {
        console.error('❌ [USERS] Error menghapus user:', err);
        res.redirect('/users?error=server_error');
    }
};