const { pool } = require('../config/database');

exports.getDashboard = async (req, res) => {
  try {
    const tenantId = req.session.tenantId;
    const userName = req.session.userName;
    const unitId = req.session.unitId;
    const roleName = req.session.role;

    if (!tenantId) return res.redirect('/login');

    const isFacultyOperator = (roleName === 'faculty_operator' && unitId);

    // ============================================
    // 1. TOTAL MITRA (DIPERBAIKI: JOIN ke tenant_mitras)
    // ============================================
    let mitraQuery = `
      SELECT COUNT(*) as total
      FROM mitras m
      JOIN tenant_mitras tm ON tm.mitra_id = m.id
      WHERE tm.tenant_id = $1
    `;
    const mitraResult = await pool.query(mitraQuery, [tenantId]);
    const totalMitra = parseInt(mitraResult.rows[0].total) || 0;

    // ============================================
    // 2. TOTAL USER AKTIF
    // ============================================
    let userQuery = `SELECT COUNT(*) as total FROM users WHERE tenant_id = $1 AND status = 'active'`;
    let userParams = [tenantId];
    if (isFacultyOperator) {
      userQuery += ` AND unit_id = $2`;
      userParams.push(unitId);
    }
    const userResult = await pool.query(userQuery, userParams);
    const totalUser = parseInt(userResult.rows[0].total) || 0;

    // ============================================
    // 3. TOTAL UNIT
    // ============================================
    let totalUnits = null;
    if (!isFacultyOperator) {
      const unitResult = await pool.query(`SELECT COUNT(*) as total FROM units WHERE tenant_id = $1 AND status = 'active'`, [tenantId]);
      totalUnits = parseInt(unitResult.rows[0].total) || 0;
    }

    // ============================================
    // 4. KERJASAMA AKTIF
    // ============================================
    let kerjasamaQuery = `
      SELECT COUNT(*) as total FROM kerjasama
      WHERE tenant_id = $1 AND status = 'active'
      AND (tanggal_berakhir IS NULL OR tanggal_berakhir >= CURRENT_DATE)
    `;
    let kerjasamaParams = [tenantId];
    if (isFacultyOperator) {
      kerjasamaQuery += ` AND unit_id = $2`;
      kerjasamaParams.push(unitId);
    }
    const kerjasamaResult = await pool.query(kerjasamaQuery, kerjasamaParams);
    const totalKerjasama = parseInt(kerjasamaResult.rows[0].total) || 0;

    // ============================================
    // 5. AUDIT LOGS TERBARU
    // ============================================
    let logQuery = `
      SELECT al.action, al.details, al.created_at, u.name as unit_name
      FROM audit_logs al
      LEFT JOIN units u ON al.unit_id = u.id
      WHERE al.tenant_id = $1
      ORDER BY al.created_at DESC LIMIT 3
    `;
    let logParams = [tenantId];
    if (isFacultyOperator) {
      logQuery += ` AND al.unit_id = $2`;
      logParams.push(unitId);
    }
    const logResult = await pool.query(logQuery, logParams);
    const recentLogs = logResult.rows;

    // ============================================
    // 6. ROLES & UNITS
    // ============================================
    let roles = [], units = [];
    if (!isFacultyOperator) {
      const rolesResult = await pool.query(`SELECT id, name, description FROM roles WHERE name != 'tenant_owner' ORDER BY name ASC`);
      roles = rolesResult.rows;
      const unitsResult = await pool.query(`SELECT id, name, code FROM units WHERE tenant_id = $1 AND status = 'active' ORDER BY name ASC`, [tenantId]);
      units = unitsResult.rows;
    }

    // ============================================
    // 7. RENDER VIEW
    // ============================================
    res.render('tenant/dashboard', {
      user: { name: userName, role: roleName },
      isFacultyOperator: isFacultyOperator,
      stats: {
        totalMitra, totalUser, totalUnits, totalKerjasama,
        systemStatus: 'Aman',
        lastAudit: recentLogs.length > 0 ? new Date(recentLogs[0].created_at).toLocaleString('id-ID') : 'Baru saja'
      },
      roles, units,
      recentLogs: recentLogs.length > 0 ? recentLogs : [{ action: 'SYSTEM_INIT', details: 'Dashboard dimuat', created_at: new Date(), unit_name: 'Sistem' }],
      success: req.query.success === 'true',
      error: req.query.error,
      temp_password: req.query.temp_password,
      email: req.query.email
    });
  } catch (err) {
    console.error('❌ [DASHBOARD] Error:', err);
    res.status(500).send('Terjadi kesalahan saat memuat dashboard.');
  }
};