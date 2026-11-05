// middleware/checkPermission.js
// ==========================================
// CENTRALIZED RBAC - SINGLE SOURCE OF TRUTH
// ==========================================
// Filosofi: Semua definisi permission ada di SATU tempat.
// Kalau ada role baru atau permission baru, cukup edit file ini.
// View dan controller akan otomatis konsisten.

const { pool } = require('../config/database');

// ==========================================
// 1. PERMISSION MAP (Definisi Hak Akses)
// ==========================================
// Format: 'action:resource'
//   - action: 'read' | 'write' | 'delete' | 'admin'
//   - resource: 'mitra' | 'kerjasama' | 'users' | 'audit_logs' | 'settings'
//
// Wildcard:
//   - '*'            = semua permission (superuser)
//   - 'read:*'       = semua operasi read
//   - 'write:*'      = semua operasi write
//
// Catatan khusus:
//   - 'write:kerjasama:own' = faculty_operator hanya bisa write kerjasama
//     di unit-nya sendiri. Validasi unit_id tetap dilakukan di controller.
//   - Permission ini adalah INDIKATOR, bukan enforcement unit.

const PERMISSION_MAP = {
  tenant_owner: ['*'], // Akses penuh ke semua

  it_admin: [
    'read:*',                  // Bisa baca semua
    'write:mitra',             // Bisa kelola mitra
    'write:kerjasama',         // Bisa kelola kerjasama
    'write:users',             // Bisa invite/activate/delete user
    'read:audit_logs'          // Bisa lihat log audit
    // ❌ TIDAK punya: write:settings, delete:tenant (khusus owner)
  ],

  faculty_operator: [
    'read:mitra',              // Bisa lihat mitra (scoped ke unit)
    'write:mitra',             // Bisa kelola mitra (scoped ke unit)
    'read:kerjasama',          // Bisa lihat kerjasama (scoped ke unit)
    'write:kerjasama:own',     // Bisa buat kerjasama HANYA di unit sendiri
    'read:audit_logs:own'      // Bisa lihat log audit unit sendiri
    // ❌ TIDAK punya: write:users, akses lintas unit
  ],

  auditor: [
    'read:mitra',              // Read-only
    'read:kerjasama',          // Read-only
    'read:users',              // Read-only (bisa lihat daftar user)
    'read:audit_logs'          // Read-only log audit
    // ❌ TIDAK punya: write/delete apapun
  ]
};

// ==========================================
// 2. HELPER FUNCTION (Internal Logic)
// ==========================================

/**
 * Cek apakah sebuah role memiliki permission tertentu
 * @param {string} role - Nama role (tenant_owner, it_admin, dll)
 * @param {string} permission - Permission yang dibutuhkan (misal: 'write:mitra')
 * @returns {boolean}
 */
function hasPermission(role, permission) {
  const perms = PERMISSION_MAP[role] || [];

  // 1. Wildcard penuh: owner bisa semua
  if (perms.includes('*')) return true;

  // 2. Exact match
  if (perms.includes(permission)) return true;

  // 3. Action wildcard: 'read:*' match 'read:mitra', 'read:kerjasama', dll
  const [action] = permission.split(':');
  if (perms.includes(`${action}:*`)) return true;

  return false;
}

/**
 * Helper untuk view (EJS) - diregister sebagai app.locals.can
 * Cara pakai di EJS: <% if (can(user.role, 'write:mitra')) { %>
 *
 * @param {string} userRole - Role user dari session
 * @param {string} permission - Permission yang dibutuhkan
 * @returns {boolean}
 */
function can(userRole, permission) {
  if (!userRole || !permission) return false;
  return hasPermission(userRole, permission);
}

// ==========================================
// 3. MIDDLEWARE FACTORY (Backend Enforcement)
// ==========================================

/**
 * Middleware factory untuk enforce permission di route
 * Cara pakai di app.js:
 *   app.post('/mitra/create', checkPermission('write:mitra'), mitraController.createMitra);
 *
 * @param {string} requiredPermission - Permission yang dibutuhkan untuk akses route ini
 * @returns {Function} Express middleware
 */
function checkPermission(requiredPermission) {
  return async (req, res, next) => {
    // 1. Cek apakah user sudah login
    if (!req.session || !req.session.userId) {
      return res.status(401).redirect('/login');
    }

    const userRole = req.session.role;
    const userId = req.session.userId;
    const tenantId = req.session.tenantId;

    // 2. Cek permission
    const hasAccess = hasPermission(userRole, requiredPermission);

    if (!hasAccess) {
      // 3. Log ke audit_logs (penting untuk skripsi - A09 Security Logging)
      try {
        await pool.query(
          `INSERT INTO audit_logs
            (tenant_id, user_id, action, target_table, details, ip_address, user_agent)
           VALUES ($1, $2, $3, $4, $5, $6, $7)`,
          [
            tenantId,
            userId,
            'UNAUTHORIZED_ACCESS',
            'permissions',
            JSON.stringify({
              attempted_permission: requiredPermission,
              user_role: userRole,
              path: req.path,
              method: req.method
            }),
            req.ip || req.connection?.remoteAddress || 'unknown',
            req.headers['user-agent'] || 'Unknown'
          ]
        );
      } catch (err) {
        // Jangan blokir response karena audit log gagal
        console.error('❌ [AUDIT LOG] Gagal mencatat unauthorized access:', err.message);
      }

      // 4. Log ke console untuk debugging
      console.warn(
        `🛡️ [RBAC DENIED] User ${userId} (role: ${userRole}) mencoba akses ` +
        `'${requiredPermission}' di ${req.method} ${req.path}`
      );

      // 5. Return 403 - beda perlakuan untuk AJAX vs HTML request
      if (req.xhr || req.headers.accept?.includes('application/json')) {
        return res.status(403).json({
          error: 'forbidden',
          message: 'Anda tidak memiliki izin untuk melakukan aksi ini.',
          required: requiredPermission,
          your_role: userRole
        });
      }

      // Untuk request HTML biasa, redirect ke dashboard dengan pesan error
      return res.redirect(`/dashboard?error=forbidden&required=${requiredPermission}`);
    }

    // 6. Permission OK, lanjut ke controller berikutnya
    next();
  };
}

// ==========================================
// 4. EXPORTS
// ==========================================

module.exports = {
  // Untuk dipakai di app.js sebagai middleware
  checkPermission,

  // Untuk diregister di app.locals agar bisa dipakai di EJS
  can,

  // Export PERMISSION_MAP untuk keperluan debugging/testing
  PERMISSION_MAP,

  // Export helper internal (untuk unit test)
  hasPermission
};