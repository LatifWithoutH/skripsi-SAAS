const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // ✅ 1. TAMBAHKAN 'tenant_id' di SELECT query
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

    // 🔒 Izinkan login untuk status 'active' DAN 'pending_invite'
    if (mitraAccount.status !== 'active' && mitraAccount.status !== 'pending_invite') {
      return res.redirect('/portal-mitra/login?error=account_suspended');
    }

    const isMatch = await bcrypt.compare(password, mitraAccount.password_hash);
    if (!isMatch) {
      return res.redirect('/portal-mitra/login?error=invalid_credentials');
    }

    // ✅ 2. SIMPAN 'tenantId' KE SESSION (INI KUNCINYA)
    req.session.mitraAccountId = mitraAccount.id;
    req.session.tenantId = mitraAccount.tenant_id; // ← TAMBAHKAN BARIS INI
    req.session.mitraId = mitraAccount.mitra_id;
    req.session.mitraName = mitraAccount.name;

    // 🎯 FIRST LOGIN ACTIVATION: Jika status pending_invite, redirect ke halaman ganti password
    if (mitraAccount.status === 'pending_invite') {
      return res.redirect('/portal-mitra/first-login');
    }

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

// 🆕 BARU: Handle first login password change
exports.firstLogin = async (req, res) => {
  // Pastikan user sudah login (punya session mitra)
  if (!req.session.mitraAccountId) {
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

    // Audit log
    await client.query(
      `INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address)
       VALUES (NULL, NULL, 'MITRA_FIRST_LOGIN_ACTIVATION', 'mitra_accounts', $1, $2, $3)`,
      [mitraAccountId, JSON.stringify({ action: 'password_changed_and_activated' }), req.ip]
    );

    await client.query('COMMIT');

    // Redirect ke dashboard
    return res.redirect('/portal-mitra/dashboard');
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ [PARTNER AUTH] Error changing password:', err);
    res.redirect('/portal-mitra/first-login?error=server_error');
  } finally {
    client.release();
  }
};