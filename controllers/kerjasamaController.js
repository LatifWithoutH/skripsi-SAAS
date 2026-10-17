const { pool } = require('../config/database');

exports.getKerjasamaPage = async (req, res) => {
  try {
    const tenantId = req.session.tenantId;
    const unitId = req.session.unitId;
    const userRole = req.session.role;

    // --- QUERY UTAMA ---
    let query = `
      SELECT k.id, k.judul, k.jenis, k.tanggal_mulai, k.tanggal_berakhir,
             m.name as mitra_name, u.name as unit_name,
             CASE WHEN k.tanggal_berakhir < CURRENT_DATE THEN 'expired' ELSE k.status END as current_status
      FROM kerjasama k
      LEFT JOIN mitras m ON k.mitra_id = m.id
      LEFT JOIN units u ON k.unit_id = u.id
      WHERE k.tenant_id = $1
    `;
    const params = [tenantId];
    if (userRole === 'faculty_operator' && unitId) {
      query += ` AND (k.unit_id = $2 OR k.unit_id IS NULL)`;
      params.push(unitId);
    }
    query += ` ORDER BY k.tanggal_berakhir ASC`;
    const result = await pool.query(query, params);

    // --- QUERY STATISTIK ---
    let statsQuery = `
      SELECT COUNT(CASE WHEN tanggal_berakhir >= CURRENT_DATE AND status = 'active' THEN 1 END) as active_count,
             COUNT(CASE WHEN tanggal_berakhir < CURRENT_DATE OR status = 'expired' THEN 1 END) as expired_count
      FROM kerjasama WHERE tenant_id = $1
    `;
    let statsParams = [tenantId];
    if (userRole === 'faculty_operator' && unitId) {
      statsQuery += ` AND (unit_id = $2 OR unit_id IS NULL)`;
      statsParams.push(unitId);
    }
    const statsResult = await pool.query(statsQuery, statsParams);

    // --- QUERY DROPDOWN MITRA (DIPERBAIKI: JOIN ke tenant_mitras) ---
    const mitraQuery = `
      SELECT m.id, m.name
      FROM mitras m
      JOIN tenant_mitras tm ON tm.mitra_id = m.id
      WHERE tm.tenant_id = $1
      ORDER BY m.name ASC
    `;
    const mitraResult = await pool.query(mitraQuery, [tenantId]);

    // --- QUERY DROPDOWN UNIT ---
    let units = [];
    if (userRole !== 'faculty_operator') {
      const unitsResult = await pool.query(`SELECT id, name, code FROM units WHERE tenant_id = $1 AND status = 'active' ORDER BY name`, [tenantId]);
      units = unitsResult.rows;
    }

    res.render('tenant/kerjasama', {
      user: { name: req.session.userName, role: req.session.role, unitName: req.session.unitName },
      kerjasamaList: result.rows,
      stats: statsResult.rows[0],
      mitras: mitraResult.rows,
      units,
      success: req.query.success === 'true',
      error: req.query.error
    });
  } catch (err) {
    console.error('❌ [KERJASAMA] Error:', err);
    res.redirect('/dashboard?error=server_error');
  }
};

exports.createKerjasama = async (req, res) => {
  try {
    const { judul, jenis, tanggal_mulai, tanggal_berakhir, mitra_id, unit_id } = req.body;
    const tenantId = req.session.tenantId;
    const userId = req.session.userId;
    const userRole = req.session.role;
    const userUnitId = req.session.unitId;

    if (userRole === 'faculty_operator' && unit_id && unit_id !== userUnitId) {
      return res.redirect('/kerjasama?error=forbidden_unit');
    }

    const finalUnitId = (userRole === 'faculty_operator') ? userUnitId : (unit_id || null);
    const today = new Date().toISOString().split('T')[0];
    const initialStatus = tanggal_berakhir < today ? 'expired' : 'active';

    await pool.query(`
      INSERT INTO kerjasama (id, tenant_id, mitra_id, unit_id, created_by, judul, jenis, tanggal_mulai, tanggal_berakhir, status)
      VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, [tenantId, mitra_id || null, finalUnitId, userId, judul, jenis, tanggal_mulai, tanggal_berakhir, initialStatus]);

    await pool.query(`
      INSERT INTO audit_logs (tenant_id, user_id, action, target_table, details, ip_address)
      VALUES ($1, $2, 'CREATE_KERJASAMA', 'kerjasama', $3, $4)
    `, [tenantId, userId, JSON.stringify({ judul, mitra_id }), req.ip]);

    res.redirect('/kerjasama?success=true');
  } catch (err) {
    console.error('❌ [KERJASAMA] Error:', err);
    res.redirect('/kerjasama?error=true');
  }
};