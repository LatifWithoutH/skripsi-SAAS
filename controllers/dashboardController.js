const { pool } = require('../config/database');

exports.getDashboard = async (req, res) => {
    try {
        const tenantId = req.session.tenantId;
        const userName = req.session.userName;
        const unitId = req.session.unitId;
        const roleName = req.session.role;

        if (!tenantId) {
            return res.redirect('/login');
        }

        // Flag untuk menentukan apakah user adalah Faculty Operator
        const isFacultyOperator = (roleName === 'faculty_operator' && unitId);

        // ============================================
        // 1. TOTAL MITRA (Difilter by unit jika faculty)
        // ============================================
        let mitraQuery = `SELECT COUNT(*) as total FROM mitras WHERE tenant_id = $1 AND status = 'active'`;
        let mitraParams = [tenantId];
        if (isFacultyOperator) {
            mitraQuery += ` AND unit_id = $2`;
            mitraParams.push(unitId);
        }
        const mitraResult = await pool.query(mitraQuery, mitraParams);
        const totalMitra = parseInt(mitraResult.rows[0].total) || 0;

        // ============================================
        // 2. TOTAL USER AKTIF (Difilter by unit jika faculty)
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
        // 3. TOTAL UNIT (Hanya untuk Owner, faculty = null)
        // ============================================
        let totalUnits = null;
        if (!isFacultyOperator) {
            const unitQuery = `SELECT COUNT(*) as total FROM units WHERE tenant_id = $1 AND status = 'active'`;
            const unitResult = await pool.query(unitQuery, [tenantId]);
            totalUnits = parseInt(unitResult.rows[0].total) || 0;
        }

        // ============================================
        // 4. 🔥 KERJASAMA AKTIF (Difilter by unit jika faculty)
        // ============================================
        let kerjasamaQuery = `
            SELECT COUNT(*) as total 
            FROM kerjasama 
            WHERE tenant_id = $1 
              AND status = 'active' 
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
        // 5. AUDIT LOGS TERBARU (DIPERBAIKI: Ada LEFT JOIN untuk ambil unit_name)
        // ============================================
        let logQuery = `
            SELECT al.action, al.details, al.created_at, u.name as unit_name 
            FROM audit_logs al
            LEFT JOIN units u ON al.unit_id = u.id
            WHERE al.tenant_id = $1
        `;
        let logParams = [tenantId];
        if (isFacultyOperator) {
            logQuery += ` AND al.unit_id = $2`;
            logParams.push(unitId);
        }
        logQuery += ` ORDER BY al.created_at DESC LIMIT 3`;
        const logResult = await pool.query(logQuery, logParams);
        const recentLogs = logResult.rows;

        // ============================================
        // 6. ROLES & UNITS (Hanya untuk Owner)
        // ============================================
        let roles = [];
        let units = [];
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
                totalMitra: totalMitra,
                totalUser: totalUser,
                totalUnits: totalUnits,
                totalKerjasama: totalKerjasama,
                systemStatus: 'Aman',
                lastAudit: recentLogs.length > 0 ? new Date(recentLogs[0].created_at).toLocaleString('id-ID') : 'Baru saja'
            },
            roles: roles,
            units: units,
            recentLogs: recentLogs.length > 0 ? recentLogs : [
                { action: 'SYSTEM_INIT', details: 'Dashboard dimuat', created_at: new Date(), unit_name: 'Sistem' }
            ],
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