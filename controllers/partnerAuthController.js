const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // ✅ 1. HAPUS 'tenant_id' dari SELECT (karena tidak ada di tabel mitra_accounts)
    const query = `
      SELECT id, mitra_id, name, email, password_hash, status, last_login
      FROM mitra_accounts
      WHERE LOWER(email) = LOWER($1)
    `;
    const result = await pool.query(query, [email]);

    if (result.rows.length === 0) {
      return res.redirect('/portal-mitra/login?error=invalid_credentials');
    }

    const mitraAccount = result.rows[0];

    // 🔒 Izinkan login untuk status 'active' DAN 'pending_invite'
    if (mitraAccount.status !== 'active' && mitraAccount.status !== 'pending_invite') {
      return res.redirect('/portal-mitra/login?error=account_suspended');
    }

    const isMatch = await bcrypt.compare(password, mitraAccount.password_hash);
    if (!isMatch) {
      return res.redirect('/portal-mitra/login?error=invalid_credentials');
    }

    // ✅ 2. AMBIL SCOPE TENANT DARI TABEL JUNCTION (tenant_mitras)
    const scopeQuery = `
      SELECT DISTINCT tm.tenant_id, t.name AS tenant_name, t.slug
      FROM tenant_mitras tm
      JOIN tenants t ON t.id = tm.tenant_id
      WHERE tm.mitra_id = $1
        AND t.status = 'active'
      ORDER BY t.name ASC
    `;
    const scopeResult = await pool.query(scopeQuery, [mitraAccount.mitra_id]);
    const allowedTenants = scopeResult.rows;

    // 🚨 VALIDASI: Jika akun ada tapi tidak di-claim oleh kampus mana pun, tolak akses
    if (allowedTenants.length === 0) {
      return res.redirect('/portal-mitra/login?error=no_active_relationship');
    }

    // ✅ 3. SIMPAN KE SESSION DENGAN BENAR (Model M:N)
    req.session.mitraAccountId = mitraAccount.id;
    req.session.mitraId = mitraAccount.mitra_id;
    req.session.mitraName = mitraAccount.name;
    req.session.isMitra = true; 
    
    req.session.allowedTenants = allowedTenants.map(t => t.tenant_id); 
    req.session.activeTenantId = allowedTenants.length === 1 
      ? allowedTenants[0].tenant_id 
      : allowedTenants[0].tenant_id; 

    await pool.query(`UPDATE mitra_accounts SET last_login = CURRENT_TIMESTAMP WHERE id = $1`, [mitraAccount.id]);

    if (mitraAccount.status === 'pending_invite') {
      return res.redirect('/portal-mitra/first-login');
    }

    return res.redirect('/portal-mitra/dashboard');
  } catch (err) {
    console.error('❌ [PARTNER AUTH] Error:', err);
    res.redirect('/portal-mitra/login?error=server_error');
  }
};

// ... (pastikan fungsi exports.logout, firstLogin, dan changePassword juga ada di bawahnya)

exports.logout = (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('Error destroying session:', err);
    res.redirect('/portal-mitra/login');
  });
};

// 🆕 Handle first login password change
exports.firstLogin = async (req, res) => {
  // Pastikan user sudah login sebagai mitra
  if (!req.session.isMitra || !req.session.mitraAccountId) {
    return res.redirect('/portal-mitra/login');
  }

  res.render('portal-mitra/first-login', {
    mitraName: req.session.mitraName
  });
};

exports.changePassword = async (req, res) => {
  const client = await pool.connect();
  try {
    const mitraAccountId = req.session.mitraAccountId;
    const { new_password, confirm_password } = req.body;

    // Validasi password
    if (!new_password || new_password.length < 8) {
      return res.redirect('/portal-mitra/first-login?error=password_too_short');
    }

    if (new_password !== confirm_password) {
      return res.redirect('/portal-mitra/first-login?error=password_mismatch');
    }

    await client.query('BEGIN');

    // Hash password baru
    const passwordHash = await bcrypt.hash(new_password, 10);

    // Update password DAN ubah status jadi 'active'
    const result = await client.query(
      `UPDATE mitra_accounts 
       SET password_hash = $1, status = 'active'
       WHERE id = $2 AND status = 'pending_invite'
       RETURNING id`,
      [passwordHash, mitraAccountId]
    );

    if (result.rowCount === 0) {
      await client.query('ROLLBACK');
      return res.redirect('/portal-mitra/first-login?error=update_failed');
    }

    // Audit log (tenant_id NULL karena ini aksi global level akun, bukan level kampus spesifik)
    await client.query(
      `INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address)
       VALUES (NULL, NULL, 'MITRA_FIRST_LOGIN_ACTIVATION', 'mitra_accounts', $1, $2, $3)`,
      [mitraAccountId, JSON.stringify({ action: 'password_changed_and_activated' }), req.ip]
    );

    await client.query('COMMIT');

    return res.redirect('/portal-mitra/dashboard');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ [PARTNER AUTH] Error changing password:', err);
    res.redirect('/portal-mitra/first-login?error=server_error');
  } finally {
    client.release();
  }
};