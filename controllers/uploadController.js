const { pool } = require('../config/database');

exports.uploadDokumen = async (req, res) => {
  try {
    const { kerjasama_id } = req.body;
    const mitraId = req.session.mitraId;
    const tenantId = req.session.tenantId;

    // 1. Validasi jika file gagal diunggah (misal: tipe salah atau > 5MB)
    if (!req.file) {
      return res.redirect(`/portal-mitra/dashboard?error=upload_failed`);
    }

    // Path relatif untuk disimpan di database (misal: /uploads/dokumen-123.pdf)
    const filePath = `/uploads/${req.file.filename}`;

    // 2. Update tabel kerjasama (Pastikan user hanya update milik mereka sendiri)
    const updateQuery = `
      UPDATE kerjasama 
      SET file_path = $1, updated_at = CURRENT_TIMESTAMP
      WHERE id = $2 AND mitra_id = $3 AND tenant_id = $4
      RETURNING id, judul
    `;
    const result = await pool.query(updateQuery, [filePath, kerjasama_id, mitraId, tenantId]);

    if (result.rows.length === 0) {
      return res.redirect(`/portal-mitra/dashboard?error=unauthorized_update`);
    }

    // 3. 🛡️ AUDIT LOG (Nilai Plus Skripsi)
    await pool.query(`
      INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address)
      VALUES ($1, $2, 'UPLOAD_DOKUMEN', 'kerjasama', $3, $4, $5)
    `, [
      tenantId, 
      req.session.mitraAccountId, // ID user mitra
      kerjasama_id, 
      JSON.stringify({ filename: req.file.filename, judul: result.rows[0].judul }), 
      req.ip
    ]);

    res.redirect(`/portal-mitra/dashboard?success=upload_success`);
  } catch (err) {
    console.error('❌ [UPLOAD] Error:', err);
    res.redirect(`/portal-mitra/dashboard?error=server_error`);
  }
};