const { pool } = require('../config/database');
const bcrypt = require('bcryptjs');
const { sendInviteEmail } = require('../utils/emailService');

exports.inviteUser = async (req, res) => {
    try {
        const { email, role_id, unit_id } = req.body;
        const tenantId = req.session.tenantId;
        const inviterId = req.session.userId;
        const inviterRole = req.session.role;

        // 1. Validasi Role Pengundang
        if (!['tenant_owner', 'it_admin'].includes(inviterRole)) {
            return res.redirect('/dashboard?error=forbidden');
        }

        // 2. Validasi Role yang diundang
        const roleCheck = await pool.query(`SELECT name FROM roles WHERE id = $1`, [role_id]);
        if (roleCheck.rows.length === 0 || roleCheck.rows[0].name === 'tenant_owner') {
            return res.redirect('/dashboard?error=invalid_role');
        }

        // 3. Validasi Unit (Jika diisi)
        if (unit_id) {
            const unitCheck = await pool.query(`SELECT id FROM units WHERE id = $1 AND tenant_id = $2`, [unit_id, tenantId]);
            if (unitCheck.rows.length === 0) {
                return res.redirect('/dashboard?error=invalid_unit');
            }
        }

        // 4. LOGIKA PINTAR: Cek email secara GLOBAL
        const existingUserGlobal = await pool.query(
            `SELECT id, status, tenant_id FROM users WHERE LOWER(email) = LOWER($1)`, 
            [email]
        );

        if (existingUserGlobal.rows.length > 0) {
            const user = existingUserGlobal.rows[0];

            if (user.tenant_id === tenantId) {
                if (user.status === 'active') {
                    return res.redirect(`/dashboard?error=user_active&email=${encodeURIComponent(email)}`);
                } 
                
                if (user.status === 'pending_invite') {
                    // RESEND INVITE
                    const newTempPassword = Math.random().toString(36).slice(-8);
                    const newHash = await bcrypt.hash(newTempPassword, 10);

                    await pool.query(`UPDATE users SET password_hash = $1, created_at = CURRENT_TIMESTAMP WHERE id = $2`, [newHash, user.id]);

                    const roleData = await pool.query('SELECT name FROM roles WHERE id = $1', [role_id]);
                    const roleName = roleData.rows[0].name;
                    let unitName = 'Seluruh Institusi';
                    if (unit_id) {
                        const unitData = await pool.query('SELECT name FROM units WHERE id = $1', [unit_id]);
                        if (unitData.rows.length > 0) unitName = unitData.rows[0].name;
                    }

                    await sendInviteEmail(email, newTempPassword, unitName, roleName);

                    await pool.query(`INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address) VALUES ($1, $2, 'RESEND_INVITE', 'users', $3, $4, $5)`, 
                        [tenantId, inviterId, user.id, JSON.stringify({ email }), req.ip]);

                    return res.redirect(`/dashboard?success=resent&email=${encodeURIComponent(email)}`);
                }
            } else {
                return res.redirect(`/dashboard?error=email_taken_global&email=${encodeURIComponent(email)}`);
            }
        }

        // 5. User benar-benar baru (Normal Flow)
        const tempPassword = Math.random().toString(36).slice(-8);
        const passwordHash = await bcrypt.hash(tempPassword, 10);
        const name = email.split('@')[0].replace(/[._-]/g, ' ');

        const insertQuery = `
            INSERT INTO users (tenant_id, unit_id, role_id, name, email, password_hash, status)
            VALUES ($1, $2, $3, $4, $5, $6, 'pending_invite')
            RETURNING id
        `;
        
        const result = await pool.query(insertQuery, [tenantId, unit_id || null, role_id, name, email, passwordHash]);
        const newUserId = result.rows[0].id;

        await pool.query(`INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address) VALUES ($1, $2, 'INVITE_USER', 'users', $3, $4, $5)`, 
            [tenantId, inviterId, newUserId, JSON.stringify({ email, role_id, unit_id }), req.ip]);

        const roleData = await pool.query('SELECT name FROM roles WHERE id = $1', [role_id]);
        const roleName = roleData.rows[0].name;
        let unitName = 'Seluruh Institusi';
        if (unit_id) {
            const unitData = await pool.query('SELECT name FROM units WHERE id = $1', [unit_id]);
            if (unitData.rows.length > 0) unitName = unitData.rows[0].name;
        }

        const emailSent = await sendInviteEmail(email, tempPassword, unitName, roleName);

        if (emailSent) {
            return res.redirect(`/dashboard?success=true&email=${encodeURIComponent(email)}`);
        } else {
            return res.redirect(`/dashboard?error=email_failed&email=${encodeURIComponent(email)}`);
        }

    } catch (err) {
        console.error('❌ [INVITE] Fatal Error:', err);
        
        if (err.code === '23505') {
            return res.redirect(`/dashboard?error=email_taken_global&email=${encodeURIComponent(req.body.email)}`);
        }
        
        return res.redirect('/dashboard?error=server_error');
    }
};