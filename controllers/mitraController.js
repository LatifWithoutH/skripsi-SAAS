const { pool } = require('../config/database');

// 1. Menampilkan Halaman & Data Mitra
exports.getMitraPage = async (req, res) => {
    try {
        const tenantId = req.session.tenantId;
        
        // 🔒 AMAN: Hanya ambil data milik tenant yang sedang login
        const query = `
            SELECT id, name, industry, contact_email, status, contract_start, contract_end, created_at
            FROM mitras 
            WHERE tenant_id = $1 
            ORDER BY created_at DESC
        `;
        const result = await pool.query(query, [tenantId]);

        res.render('tenant/mitra', {
            user: { name: req.session.userName, role: req.session.role },
            mitras: result.rows,
            success: req.query.success === 'true',
            error: req.query.error
        });
    } catch (err) {
        console.error('❌ [MITRA] Error mengambil data:', err);
        res.redirect('/dashboard');
    }
};

// 2. Menyimpan Data Mitra Baru (POST)
exports.createMitra = async (req, res) => {
    try {
        const tenantId = req.session.tenantId;
        const userId = req.session.userId;
        const { name, industry, contact_email, status, contract_start, contract_end } = req.body;

        // 🔒 AMAN: Parameterized Query (Mencegah SQL Injection)
        const insertQuery = `
            INSERT INTO mitras (id, tenant_id, created_by, name, industry, contact_email, status, contract_start, contract_end)
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8)
            RETURNING id
        `;
        
        await pool.query(insertQuery, [
            tenantId, 
            userId, 
            name, 
            industry, 
            contact_email, 
            status || 'active', 
            contract_start || null, 
            contract_end || null
        ]);

        // 🛡️ NILAI PLUS SKRIPSI: Catat aktivitas ke Audit Log
        const auditQuery = `
            INSERT INTO audit_logs (tenant_id, user_id, action, target_table, details, ip_address)
            VALUES ($1, $2, 'CREATE_MITRA', 'mitras', $3, $4)
        `;
        await pool.query(auditQuery, [
            tenantId, 
            userId, 
            JSON.stringify({ mitra_name: name }), 
            req.ip
        ]);

        // Redirect kembali dengan pesan sukses
        res.redirect('/mitra?success=true');

    } catch (err) {
        console.error('❌ [MITRA] Error menyimpan data:', err);
        res.redirect('/mitra?error=true');
    }
};