const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { sendMitraInviteEmail } = require('../utils/mitraEmailService');

// ==========================================
// 1. Menampilkan Halaman & Data Mitra (JOIN M:N)
// ==========================================
exports.getMitraPage = async (req, res) => {
    try {
        const tenantId = req.session.tenantId;
        
        // ✅ PERBAIKAN: Tambahkan LEFT JOIN ke mitra_accounts untuk mengambil status
        const query = `
            SELECT 
                m.id, m.name, m.industry, m.website, m.verified,
                tm.contact_name, tm.contact_email, tm.contact_phone, tm.notes,
                tm.created_at as claimed_at,
                ma.status as account_status
            FROM mitras m
            INNER JOIN tenant_mitras tm ON tm.mitra_id = m.id
            LEFT JOIN mitra_accounts ma ON ma.mitra_id = m.id AND LOWER(ma.email) = LOWER(tm.contact_email)
            WHERE tm.tenant_id = $1 
            ORDER BY tm.created_at DESC
        `;
        const result = await pool.query(query, [tenantId]);

        res.render('tenant/mitra', {
            user: { name: req.session.userName, role: req.session.role },
            mitras: result.rows,
            success: req.query.success,
            error: req.query.error,
            warning: req.query.warning
        });
    } catch (err) {
        console.error('❌ [MITRA] Error mengambil data:', err);
        res.redirect('/dashboard?error=fetch_failed');
    }
};

// ==========================================
// 2. Menyimpan Data Mitra Baru (M:N dengan Transaction)
// ==========================================
exports.createMitra = async (req, res) => {
  const client = await pool.connect();
  try {
    const tenantId = req.session.tenantId;
    const userId = req.session.userId;
    const { name, industry, website, contact_name, contact_email, contact_phone, notes } = req.body;

    if (!name || !name.trim()) {
      return res.redirect('/mitra?error=nama_kosong');
    }

    await client.query('BEGIN');

    // CEK ATAU BUAT PERUSAHAAN (GLOBAL)
    const existingMitra = await client.query(
      `SELECT id FROM mitras WHERE LOWER(name) = LOWER($1)`,
      [name.trim()]
    );

    let mitraId;
    let isExistingCompany = false;

    if (existingMitra.rows.length > 0) {
      mitraId = existingMitra.rows[0].id;
      isExistingCompany = true;
    } else {
      const insertMitra = await client.query(
        `INSERT INTO mitras (name, industry, website) 
         VALUES ($1, $2, $3) RETURNING id`,
        [name.trim(), industry || null, website || null]
      );
      mitraId = insertMitra.rows[0].id;
    }

    // BUAT/UPDATE RELASI TENANT (LOKAL)
    await client.query(
      `INSERT INTO tenant_mitras 
        (tenant_id, mitra_id, contact_name, contact_email, contact_phone, notes, created_by)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       ON CONFLICT (tenant_id, mitra_id) 
       DO UPDATE SET 
         contact_name = EXCLUDED.contact_name,
         contact_email = EXCLUDED.contact_email,
         contact_phone = EXCLUDED.contact_phone,
         notes = EXCLUDED.notes`,
      [tenantId, mitraId, contact_name || null, contact_email || null, contact_phone || null, notes || null, userId]
    );

    // CEK ATAU BUAT AKUN LOGIN PIC (GLOBAL)
    let emailAction = 'none';
    if (contact_email && contact_email.trim()) {
      const existingAccount = await client.query(
        `SELECT id, status FROM mitra_accounts WHERE email = LOWER($1)`,
        [contact_email.trim().toLowerCase()]
      );

      if (existingAccount.rows.length === 0) {
        const tempPassword = crypto.randomBytes(4).toString('hex');
        const passwordHash = await bcrypt.hash(tempPassword, 10);

        await client.query(
          `INSERT INTO mitra_accounts (mitra_id, name, email, password_hash, position, status)
           VALUES ($1, $2, $3, $4, $5, 'pending_invite')`,
          [mitraId, contact_name || 'PIC Mitra', contact_email.trim().toLowerCase(), passwordHash, 'Penanggung Jawab']
        );

        req.session.tempInvitePassword = tempPassword;
        emailAction = 'new_account';
      } else {
        emailAction = 'existing_account';
      }
    }

    // AUDIT LOG
    await client.query(
      `INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address)
       VALUES ($1, $2, $3, 'tenant_mitras', $4, $5, $6)`,
      [
        tenantId, 
        userId, 
        isExistingCompany ? 'CLAIM_EXISTING_MITRA' : 'CREATE_NEW_MITRA_RELATION',
        mitraId,
        JSON.stringify({ mitra_name: name, contact_email }), 
        req.ip
      ]
    );

    await client.query('COMMIT');

    // KIRIM EMAIL MITRA
    if (emailAction === 'new_account' && req.session.tempInvitePassword) {
      const tempPass = req.session.tempInvitePassword;
      delete req.session.tempInvitePassword; 
      
      const emailSent = await sendMitraInviteEmail(
        contact_email.trim().toLowerCase(), 
        name.trim(), 
        req.session.tenantName || 'Universitas Mitra', 
        tempPass
      );
      
      if (emailSent) {
          return res.redirect('/mitra?success=mitra_added_and_invited');
      } else {
          return res.redirect('/mitra?success=mitra_added&warning=email_failed');
      }
    } else if (emailAction === 'existing_account') {
      return res.redirect('/mitra?success=mitra_added_existing_pic');
    }

    return res.redirect('/mitra?success=mitra_added');

  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ [MITRA] Error menyimpan data:', err);
    res.redirect('/mitra?error=server_error');
  } finally {
    client.release();
  }
};

// ==========================================
// 3. Update Relasi Mitra (Edit PIC/Contact Info)
// ==========================================
exports.updateMitra = async (req, res) => {
    const client = await pool.connect();
    try {
        const tenantId = req.session.tenantId;
        const userId = req.session.userId;
        const { mitra_id } = req.params;
        const { contact_name, contact_email, contact_phone, notes } = req.body;

        await client.query('BEGIN');

        const result = await client.query(
            `UPDATE tenant_mitras 
             SET contact_name = $1, contact_email = $2, contact_phone = $3, notes = $4
             WHERE tenant_id = $5 AND mitra_id = $6`,
            [contact_name, contact_email, contact_phone, notes, tenantId, mitra_id]
        );

        if (result.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.redirect('/mitra?error=mitra_tidak_ditemukan');
        }

        await client.query(
            `INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address)
             VALUES ($1, $2, 'UPDATE_MITRA_RELATION', 'tenant_mitras', $3, $4, $5)`,
            [tenantId, userId, mitra_id, JSON.stringify({ contact_email }), req.ip]
        );

        await client.query('COMMIT');
        res.redirect('/mitra?success=mitra_updated');

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ [MITRA] Error update:', err);
        res.redirect('/mitra?error=update_failed');
    } finally {
        client.release();
    }
};

// ==========================================
// 4. Hapus Relasi Mitra (Unclaim - Data Global Tetap Ada)
// ==========================================
exports.deleteMitra = async (req, res) => {
    const client = await pool.connect();
    try {
        const tenantId = req.session.tenantId;
        const userId = req.session.userId;
        const { mitra_id } = req.params;

        await client.query('BEGIN');

        const result = await client.query(
            `DELETE FROM tenant_mitras 
             WHERE tenant_id = $1 AND mitra_id = $2`,
            [tenantId, mitra_id]
        );

        if (result.rowCount === 0) {
            await client.query('ROLLBACK');
            return res.redirect('/mitra?error=mitra_tidak_ditemukan');
        }

        await client.query(
            `INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address)
             VALUES ($1, $2, 'UNCLAIM_MITRA', 'tenant_mitras', $3, $4, $5)`,
            [tenantId, userId, mitra_id, JSON.stringify({ mitra_id }), req.ip]
        );

        await client.query('COMMIT');
        res.redirect('/mitra?success=mitra_removed');

    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ [MITRA] Error delete:', err);
        res.redirect('/mitra?error=delete_failed');
    } finally {
        client.release();
    }
};