const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');

exports.registerTenant = async (req, res) => {
    const client = await pool.connect();
    try {
        // 1. Ambil data dari form (tenant_slug DIHAPUS dari sini)
        const { tenant_name, email, password, confirm_password, subscription_plan, agree_terms } = req.body;

        // 2. VALIDASI BACKEND (Nilai plus keamanan untuk skripsi)
        if (password !== confirm_password) {
            return res.redirect('/register?error=password_mismatch');
        }
        if (!agree_terms) {
            return res.redirect('/register?error=terms_required');
        }

        await client.query('BEGIN'); // Mulai Transaksi Database

        // 3. AUTO-GENERATE SLUG SIMPEL (Hanya untuk memenuhi syarat NOT NULL di DB)
        // Menghapus karakter aneh, ambil 20 huruf pertama, tambah angka acak agar pasti unik
        const baseSlug = tenant_name.toLowerCase().replace(/[^a-z0-9]/g, '').substring(0, 20);
        const finalSlug = `${baseSlug}-${Date.now().toString().slice(-4)}`; 
        // Contoh hasil: "universitasnusantara-8392"

        // 4. Cek apakah email sudah terdaftar
        const checkQuery = `SELECT id FROM users WHERE email = $1`;
        const checkResult = await client.query(checkQuery, [email.toLowerCase()]);
        
        if (checkResult.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.redirect('/register?error=email_exists');
        }

        // 5. Buat Tenant Baru
        const tenantQuery = `
            INSERT INTO tenants (name, slug, subscription_plan, status)
            VALUES ($1, $2, $3, 'active')
            RETURNING id
        `;
        const tenantResult = await client.query(tenantQuery, [
            tenant_name, 
            finalSlug, // Gunakan slug yang di-generate otomatis
            subscription_plan || 'basic'
        ]);
        const newTenantId = tenantResult.rows[0].id;

        // 6. Buat User Owner untuk Tenant tersebut
        const passwordHash = await bcrypt.hash(password, 10);
        const ownerRoleId = 1; // ID 1 adalah 'tenant_owner' di tabel roles (sesuai seed DB kamu)
        
        const userQuery = `
            INSERT INTO users (tenant_id, role_id, name, email, password_hash, status)
            VALUES ($1, $2, $3, $4, $5, 'active')
            RETURNING id
        `;
        const userResult = await client.query(userQuery, [
            newTenantId, 
            ownerRoleId, 
            tenant_name, // Nama user diisi nama institusi (cukup untuk demo)
            email.toLowerCase(), 
            passwordHash
        ]);
        const newUserId = userResult.rows[0].id;

        // 7. AUDIT LOG (Nilai plus besar untuk skripsi: jejak keamanan)
        await client.query(`
            INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address)
            VALUES ($1, $2, 'REGISTER_TENANT', 'tenants', $3, $4, $5)
        `, [
            newTenantId, 
            newUserId, 
            newTenantId, 
            JSON.stringify({ plan: subscription_plan, email: email }), 
            req.ip
        ]);

        await client.query('COMMIT'); // Simpan Perubahan

        // 8. AUTO-LOGIN (UX jauh lebih baik untuk demo: user langsung masuk dashboard)
        req.session.userId = newUserId;
        req.session.tenantId = newTenantId;
        req.session.role = 'tenant_owner';
        req.session.userName = tenant_name;

        res.redirect('/dashboard?success=registered');

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ [REGISTER] Error:', err);
        res.redirect('/register?error=server');
    } finally {
        client.release();
    }
};