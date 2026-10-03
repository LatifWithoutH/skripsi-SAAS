const {pool} = require('../config/database');
const bcrypt = require('bcryptjs');

exports.login = async (req, res) => {
    try {
        const { email, password } = req.body;

        // 🔒 ZERO TRUST: Hanya cari di tabel mitra_accounts, BUKAN users
        const query = `
            SELECT id, tenant_id, mitra_id, name, email, password_hash, status 
            FROM mitra_accounts 
            WHERE email = $1
        `;
        const result = await pool.query(query, [email]);

        if (result.rows.length === 0) {
            return res.redirect('/portal-mitra/login?error=invalid_credentials');
        }

        const mitraAccount = result.rows[0];

        if (mitraAccount.status !== 'active') {
            return res.redirect('/portal-mitra/login?error=account_suspended');
        }

        const isMatch = await bcrypt.compare(password, mitraAccount.password_hash);
        if (!isMatch) {
            return res.redirect('/portal-mitra/login?error=invalid_credentials');
        }

        // ✅ Login Berhasil: Simpan session KHUSUS mitra
        req.session.mitraAccountId = mitraAccount.id;
        req.session.mitraId = mitraAccount.mitra_id;
        req.session.tenantId = mitraAccount.tenant_id; // Untuk logging/audit
        req.session.mitraName = mitraAccount.name;

        return res.redirect('/portal-mitra/dashboard');

    } catch (err) {
        console.error('❌ [PARTNER AUTH] Error:', err);
        res.redirect('/portal-mitra/login?error=server_error');
    }
};

exports.logout = (req, res) => {
    req.session.destroy((err) => {
        if (err) console.error('Error destroying session:', err);
        res.redirect('/portal-mitra/login');
    });
};
