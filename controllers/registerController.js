const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');

/**
 * Register Tenant Baru (Institusi & Admin Owner)
 * Flow: Validasi -> Cek Duplikasi -> Transaksi DB (Tenant + User + Audit) -> Redirect
 */
exports.registerTenant = async (req, res) => {
    const client = await pool.connect();
    
    try {
        // 1. Sanitasi Input (Mencegah bug akibat spasi tidak sengaja di awal/akhir)
        const tenant_name = req.body.tenant_name?.trim();
        const email = req.body.email?.trim().toLowerCase();
        const password = req.body.password;
        const confirm_password = req.body.confirm_password;
        const subscription_plan = req.body.subscription_plan || 'starter';
        const agree_terms = req.body.agree_terms === 'on' || req.body.agree_terms === true;
        
        // ✅ BARU: Ambil slug dari input user dan sanitasi
        const rawSlug = req.body.slug?.trim().toLowerCase();

        // 2. VALIDASI BACKEND (Wajib, karena frontend validation bisa di-bypass via Postman/cURL)
        if (!tenant_name || !email || !password || !rawSlug) {
            return res.redirect('/register?error=missing_fields');
        }
        if (password !== confirm_password) {
            return res.redirect('/register?error=password_mismatch');
        }
        if (!agree_terms) {
            return res.redirect('/register?error=terms_required');
        }

        // ✅ PERBAIKAN KRITIS: Regex yang lebih fleksibel namun tetap aman.
        const passwordRegex = /^(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{12,}$/;
        if (!passwordRegex.test(password)) {
            return res.redirect('/register?error=weak_password');
        }

        // ✅ BARU: Validasi Format Slug (hanya huruf kecil, angka, strip, 3-30 karakter)
        const slugRegex = /^[a-z0-9-]{3,30}$/;
        if (!slugRegex.test(rawSlug)) {
            return res.redirect('/register?error=invalid_slug');
        }

        // ✅ BARU: Cek Reserved Subdomains (Sama dengan di tenantResolver.js)
        const RESERVED = ['mitra', 'platform', 'www', 'api', 'admin', 'localhost', 'mail', 'ftp', 'cdn', 'status', 'billing', 'help', 'docs'];
        if (RESERVED.includes(rawSlug)) {
            return res.redirect('/register?error=reserved_slug');
        }

        // 3. Mulai Transaksi Database (ACID Compliance)
        await client.query('BEGIN');

        // 4. Cek Email Duplikat (Global, karena email unik di seluruh platform)
        const checkEmail = await client.query(
            `SELECT id FROM users WHERE email = $1`, 
            [email]
        );
        if (checkEmail.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.redirect('/register?error=email_exists');
        }

        // 5. Cek Nama Tenant Duplikat (Mencegah spam institusi sama)
        const checkTenant = await client.query(
            `SELECT id FROM tenants WHERE LOWER(name) = LOWER($1)`, 
            [tenant_name]
        );
        if (checkTenant.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.redirect('/register?error=tenant_exists');
        }

        // ✅ BARU: Cek Slug Duplikat di Database (Defense in Depth)
        const checkSlug = await client.query(`SELECT id FROM tenants WHERE slug = $1`, [rawSlug]);
        if (checkSlug.rows.length > 0) {
            await client.query('ROLLBACK');
            return res.redirect('/register?error=slug_exists');
        }

        // Gunakan slug yang sudah divalidasi dari user
        const finalSlug = rawSlug;

        // 7. Buat Record Tenant (Status: PENDING_APPROVAL untuk mencegah spam/abuse)
        const tenantQuery = `
            INSERT INTO tenants (name, slug, subscription_plan, status, created_at) 
            VALUES ($1, $2, $3, 'pending_approval', NOW()) 
            RETURNING id
        `;
        const tenantResult = await client.query(tenantQuery, [tenant_name, finalSlug, subscription_plan]);
        const newTenantId = tenantResult.rows[0].id;

        // 8. Buat Record User Owner (role_id = 1 adalah Tenant Owner/Super Admin)
        const passwordHash = await bcrypt.hash(password, 10);
        const userQuery = `
            INSERT INTO users (tenant_id, role_id, name, email, password_hash, status, created_at) 
            VALUES ($1, 1, $2, $3, $4, 'pending_approval', NOW()) 
            RETURNING id
        `;
        const userResult = await client.query(userQuery, [newTenantId, tenant_name, email, passwordHash]);
        const newUserId = userResult.rows[0].id;

        // 9. Audit Log Forensik (Mencatat IP dan User-Agent untuk keperluan investigasi keamanan)
        const userAgent = req.headers['user-agent'] || 'Unknown';
        const auditQuery = `
            INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address, user_agent, created_at) 
            VALUES ($1, $2, 'REGISTER_TENANT_PENDING', 'tenants', $3, $4, $5, $6, NOW())
        `;
        await client.query(auditQuery, [
            newTenantId, 
            newUserId, 
            newTenantId, 
            JSON.stringify({ plan: subscription_plan, email, slug: finalSlug }), 
            req.ip || req.connection.remoteAddress, 
            userAgent
        ]);

        // 10. Commit Transaksi (Semua berhasil, simpan permanen)
        await client.query('COMMIT');

        // 11. ✅ PERBAIKAN: Redirect ke halaman sukses khusus dengan membawa parameter slug
        return res.redirect(`/register-success?slug=${encodeURIComponent(finalSlug)}`);

    } catch (err) {
        // Rollback jika ada error di tengah proses (Mencegah data corrupt/orphaned records)
        await client.query('ROLLBACK');
        console.error('❌ [REGISTER TENANT] Critical Error:', err.message);
        
        // Handle unique constraint violation secara spesifik jika lolos validasi awal (race condition)
        if (err.code === '23505') {
            if (err.constraint === 'tenants_slug_key') {
                return res.redirect('/register?error=slug_exists');
            }
            return res.redirect('/register?error=email_exists');
        }
        
        // Redirect dengan error generic agar tidak membocorkan detail error database ke user
        res.redirect('/register?error=server');
    } finally {
        // Wajib release connection kembali ke pool untuk mencegah memory leak
        client.release();
    }
};