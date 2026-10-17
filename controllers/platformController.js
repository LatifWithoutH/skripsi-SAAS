// controllers/platformController.js
const { pool } = require('../config/database');

exports.getDashboard = async (req, res) => {
    try {
        // A. Metrik Tenant
        const tenantStatsQuery = `
            SELECT 
                COUNT(*) FILTER (WHERE status = 'active') as active,
                COUNT(*) FILTER (WHERE status = 'pending_approval') as pending,
                COUNT(*) FILTER (WHERE status = 'rejected') as rejected,
                COUNT(*) as total
            FROM tenants
        `;
        const tenantStatsResult = await pool.query(tenantStatsQuery);
        const tenantStats = tenantStatsResult.rows[0];

        // B. Metrik Skala Sistem (DIPERTAHANKAN: menggunakan verified = true sesuai schema kamu)
        const globalStatsQuery = `
            SELECT 
                (SELECT COUNT(*) FROM users WHERE status = 'active') as total_active_users,
                (SELECT COUNT(*) FROM mitras WHERE verified = true) as total_active_mitra,
                (SELECT COUNT(*) FROM kerjasama WHERE status = 'active') as total_active_mou
        `;
        const globalStatsResult = await pool.query(globalStatsQuery);
        const globalStats = globalStatsResult.rows[0];

        // C. Antrian Approval
        const pendingQuery = `
            SELECT t.id, t.name, t.slug, t.subscription_plan, t.created_at, 
                   u.email as admin_email, u.name as admin_name
            FROM tenants t
            JOIN users u ON t.id = u.tenant_id AND u.role_id = 1
            WHERE t.status = 'pending_approval'
            ORDER BY t.created_at DESC
            LIMIT 10
        `;
        const pendingTenantsResult = await pool.query(pendingQuery);
        const pendingTenants = pendingTenantsResult.rows;

        // 🛡️ D. METRIK KEAMANAN (A09: Security Logging & Alerting)
        // ⚠️ PENTING: Pastikan kolom 'ip_address' sudah ada di tabel 'audit_logs' kamu.
        // Jika belum, jalankan dulu di database: ALTER TABLE audit_logs ADD COLUMN ip_address VARCHAR(45);
        
        // 1. Deteksi Brute Force (IP dengan >= 3 gagal login dalam 24 jam)
        const bruteForceQuery = `
            SELECT ip_address, COUNT(*) as failed_attempts, MAX(created_at) as last_attempt
            FROM audit_logs
            WHERE action = 'LOGIN_FAILED' 
              AND created_at > NOW() - INTERVAL '24 hours'
              AND ip_address IS NOT NULL
            GROUP BY ip_address
            HAVING COUNT(*) >= 3
            ORDER BY failed_attempts DESC
            LIMIT 5
        `;
        const bruteForceResult = await pool.query(bruteForceQuery);
        const suspiciousIPs = bruteForceResult.rows;

        // 2. Total Insiden Keamanan (24 jam terakhir)
        const securityIncidentsQuery = `
            SELECT COUNT(*) as total_incidents
            FROM audit_logs
            WHERE action IN ('LOGIN_FAILED', 'UNAUTHORIZED_ACCESS', 'REJECT_TENANT', 'DELETE_USER')
              AND created_at > NOW() - INTERVAL '24 hours'
        `;
        const incidentsResult = await pool.query(securityIncidentsQuery);
        const totalIncidents = parseInt(incidentsResult.rows[0].total_incidents) || 0;

        // 3. Feed Aktivitas Terbaru (DIPERTAHANKAN: Mengambil 10 log terakhir secara umum + info IP)
        // Kita tidak memfilter action-nya agar semua aktivitas (termasuk login sukses, dll) tetap terlihat di feed,
        // tapi kita tambahkan kolom ip_address agar UI bisa menampilkannya.
        const auditQuery = `
            SELECT al.action, al.details, al.created_at, al.ip_address, u.name as actor_name
            FROM audit_logs al
            LEFT JOIN users u ON al.user_id = u.id
            ORDER BY al.created_at DESC
            LIMIT 10
        `;
        const recentLogsResult = await pool.query(auditQuery);
        const recentLogs = recentLogsResult.rows;

        res.render('platform/dashboard', {
            user: { name: req.session.userName || 'Super Admin', role: 'Platform Owner' },
            tenantStats,
            globalStats,
            pendingTenants,
            recentLogs,
            // Data Keamanan Baru untuk di-render di UI EVA-01
            securityMetrics: {
                totalIncidents,
                suspiciousIPsCount: suspiciousIPs.length,
                suspiciousIPs
            },
            success: req.query.success,
            error: req.query.error
        });
    } catch (err) {
        console.error('❌ [PLATFORM] Error fatal:', err);
        res.status(500).send('Terjadi kesalahan pada server platform. Cek log terminal.');
    }
};

// 2. Aksi Approve Tenant (DIPERBAIKI: Menghindari FK Violation)
exports.approveTenant = async (req, res) => {
    const { tenantId } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        // 1. Update status tenant
        await client.query(`UPDATE tenants SET status = 'active' WHERE id = $1`, [tenantId]);
        
        // 2. Update status semua user di tenant tersebut
        await client.query(`UPDATE users SET status = 'active' WHERE tenant_id = $1`, [tenantId]);

        // 3. FIX: Jika yang approve adalah Platform Admin, user_id HARUS NULL 
        // agar tidak melanggar FK ke tabel 'users'
        const isPlatformAdmin = !!req.session.platformAdminId;
        const actorUserId = isPlatformAdmin ? null : (req.session.userId || null);
        const actorName = req.session.userName || 'Platform Admin';

        // 4. Insert Audit Log (Forensik)
        await client.query(`
            INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address, user_agent)
            VALUES ($1, $2, 'APPROVE_TENANT', 'tenants', $3, $4, $5, $6)
        `, [
            tenantId, 
            actorUserId, // NULL jika Platform Admin
            tenantId, 
            JSON.stringify({ 
                action_by: isPlatformAdmin ? 'Platform Admin' : 'Tenant User',
                admin_name: actorName 
            }), 
            req.ip || '127.0.0.1',
            req.get('user-agent') || 'Unknown'
        ]);

        await client.query('COMMIT');
        res.redirect('/platform/dashboard?success=approved');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ [PLATFORM] Approve Error:', err);
        res.redirect('/platform/dashboard?error=failed');
    } finally {
        client.release();
    }
};

// 3. Aksi Reject Tenant (DIPERBAIKI: Menghindari FK Violation)
exports.rejectTenant = async (req, res) => {
    const { tenantId } = req.params;
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        
        await client.query(`UPDATE tenants SET status = 'rejected' WHERE id = $1`, [tenantId]);
        await client.query(`UPDATE users SET status = 'rejected' WHERE tenant_id = $1`, [tenantId]);

        // FIX: Sama seperti approve, gunakan NULL untuk user_id jika Platform Admin
        const isPlatformAdmin = !!req.session.platformAdminId;
        const actorUserId = isPlatformAdmin ? null : (req.session.userId || null);
        const actorName = req.session.userName || 'Platform Admin';

        await client.query(`
            INSERT INTO audit_logs (tenant_id, user_id, action, target_table, target_id, details, ip_address, user_agent)
            VALUES ($1, $2, 'REJECT_TENANT', 'tenants', $3, $4, $5, $6)
        `, [
            tenantId, 
            actorUserId, // NULL jika Platform Admin
            tenantId, 
            JSON.stringify({ 
                action_by: isPlatformAdmin ? 'Platform Admin' : 'Tenant User',
                admin_name: actorName 
            }), 
            req.ip || '127.0.0.1',
            req.get('user-agent') || 'Unknown'
        ]);

        await client.query('COMMIT');
        res.redirect('/platform/dashboard?success=rejected');
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('❌ [PLATFORM] Reject Error:', err);
        res.redirect('/platform/dashboard?error=failed');
    } finally {
        client.release();
    }
};

module.exports = exports;