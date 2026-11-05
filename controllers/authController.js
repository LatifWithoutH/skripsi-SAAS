const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');

// ==========================================
// ✅ HELPER: Pilih View Login yang Tepat
// ==========================================
function getLoginView(req) {
  return req.tenant ? 'tenant/login' : 'public/login';
}

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    const loginView = getLoginView(req);

    // 🛡️ SAFEGUARD 1: Blokir login tenant di domain utama
    if (req.isMainDomain) {
      return res.status(403).render('public/login', {
        error: 'Anda mengakses domain utama platform. Silakan gunakan URL subdomain institusi Anda (contoh: ums.saas.local) untuk login.',
        oldInput: { email },
        tenant: null
      });
    }

    // 🛡️ SAFEGUARD 2: Pastikan req.tenant ada
    if (!req.tenant || !req.tenant.id) {
      return res.status(400).render(loginView, {
        error: 'Konteks institusi tidak valid. Silakan gunakan URL subdomain yang benar.',
        oldInput: { email },
        tenant: req.tenant || null
      });
    }

    // 1. Cari user berdasarkan email DAN tenant_id (Defense in Depth)
    const userQuery = `
      SELECT u.id, u.name, u.email, u.password_hash, u.status,
             u.tenant_id, u.unit_id, r.name as role_name
      FROM users u
      JOIN roles r ON u.role_id = r.id
      WHERE u.email = $1 AND u.tenant_id = $2
    `;
    const result = await pool.query(userQuery, [email, req.tenant.id]);

    if (result.rows.length === 0) {
      return res.status(400).render(loginView, {
        error: 'Email atau password salah.',
        oldInput: { email },
        tenant: req.tenant
      });
    }

    const user = result.rows[0];

    // ✅ GATEKEEPER 1: Cek status user
    if (user.status === 'pending_approval') {
      return res.status(403).render(loginView, {
        error: 'Akun institusi Anda masih dalam proses verifikasi oleh admin platform.',
        oldInput: { email },
        tenant: req.tenant
      });
    }

    if (user.status === 'rejected') {
      return res.status(403).render(loginView, {
        error: 'Pendaftaran institusi Anda telah ditolak.',
        oldInput: { email },
        tenant: req.tenant
      });
    }

    if (user.status === 'pending_invite') {
      return res.status(403).render(loginView, {
        error: 'Akun Anda belum diaktifkan. Silakan hubungi admin institusi.',
        oldInput: { email },
        tenant: req.tenant
      });
    }

    // ✅ GATEKEEPER 2: Cek status tenant (Defense in Depth)
    if (req.tenant.status !== 'active') {
      return res.status(403).render(loginView, {
        error: 'Akun institusi ini sedang ditangguhkan atau tidak aktif.',
        oldInput: { email },
        tenant: req.tenant
      });
    }

    // 3. Verifikasi password (bcrypt)
    const isMatch = await bcrypt.compare(password, user.password_hash);
    if (!isMatch) {
      // 🛡️ OWASP A09 FIX: Catat percobaan login gagal
      const auditQuery = `
        INSERT INTO audit_logs (tenant_id, user_id, action, target_table, details, ip_address, user_agent)
        VALUES ($1, NULL, 'LOGIN_FAILED', 'users', $2, $3, $4)
      `;
      await pool.query(auditQuery, [
        req.tenant.id,
        JSON.stringify({ email: email, reason: 'wrong_password' }),
        req.ip || req.connection.remoteAddress,
        req.headers['user-agent'] || 'Unknown'
      ]);

      return res.status(401).render(loginView, {
        error: 'Email atau password salah.',
        oldInput: { email },
        tenant: req.tenant
      });
    }

    // 4. Jika sukses, simpan data penting ke Session
    req.session.userId = user.id;
    req.session.tenantId = user.tenant_id;
    req.session.role = user.role_name;
    req.session.userName = user.name;
    req.session.unitId = user.unit_id;
    req.session.tenantSlug = req.tenant.slug;

    if (user.unit_id) {
      const unitQuery = `SELECT name FROM units WHERE id = $1`;
      const unitResult = await pool.query(unitQuery, [user.unit_id]);
      if (unitResult.rows.length > 0) {
        req.session.unitName = unitResult.rows[0].name;
      }
    }

    // 5. ✅ PERBAIKAN: Audit log sukses login (6 placeholder untuk 6 elemen array)
    await pool.query(`
      INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address, user_agent)
      VALUES ($1, $2, 'LOGIN_SUCCESS', 'users', $3, $4, $5, $6)
    `, [
      req.tenant.id,                                          // $1
      user.id,                                                // $2
      user.id,                                                // $3 (target_id)
      JSON.stringify({ role: user.role_name }),               // $4 (details)
      req.ip || req.connection.remoteAddress,                 // $5 (ip_address)
      req.headers['user-agent'] || 'Unknown'                  // $6 (user_agent)
    ]);

    // 6. Redirect ke dashboard
    return res.redirect('/dashboard');

  } catch (err) {
    console.error('❌ [AUTH] Error saat login:', err);
    const loginView = getLoginView(req);
    res.status(500).render(loginView, {
      error: 'Terjadi kesalahan pada server.',
      tenant: req.tenant || null
    });
  }
};

exports.logout = (req, res) => {
  req.session.destroy((err) => {
    if (err) console.error('❌ [AUTH] Error saat logout:', err);
    
    // HAPUS logika if (req.tenant && req.tenant.slug) yang lama.
    // Cukup redirect ke '/login'. 
    // Middleware tenantResolver akan otomatis mendeteksi host (misal: uniba.saas.local) 
    // dan merender halaman login tenant yang benar.
    
    res.redirect('/login');
  });
};