// controllers/partnerController.js
const { pool } = require('../config/database');

/**
 * Menampilkan dashboard portal mitra
 * Mengambil data kerjasama aktif dan statistik mitra
 */
exports.getDashboard = async (req, res) => {
    try {
        const mitraId = req.session.mitraId;
        
        // Validasi: pastikan mitraId ada di session
        if (!mitraId) {
            console.error('[PARTNER DASHBOARD] mitraId tidak ditemukan di session');
            return res.status(403).send('Akses ditolak: data mitra tidak valid.');
        }
        
        // Query 1: Ambil daftar kerjasama milik mitra ini
        const query = `
            SELECT 
                k.judul, 
                k.jenis, 
                k.tanggal_mulai, 
                k.tanggal_berakhir, 
                k.status,
                t.name as tenant_name,
                CASE 
                    WHEN k.tanggal_berakhir < CURRENT_DATE THEN 'expired' 
                    ELSE k.status 
                END as current_status 
            FROM kerjasama k
            JOIN tenants t ON t.id = k.tenant_id
            WHERE k.mitra_id = $1 
            ORDER BY k.tanggal_berakhir DESC
        `;
        const result = await pool.query(query, [mitraId]);
        
        // Query 2: Ambil statistik kerjasama aktif
        const statsQuery = `
            SELECT COUNT(*) as "activeCount" 
            FROM kerjasama 
            WHERE mitra_id = $1 
              AND tanggal_berakhir >= CURRENT_DATE 
              AND status = 'active'
        `;
        const statsResult = await pool.query(statsQuery, [mitraId]);

        // Render view dengan data yang sudah dipisah per tenant (aman dari IDOR)
        res.render('portal-mitra/dashboard', {
            mitraName: req.session.mitraName || 'Mitra',
            kerjasamaList: result.rows,
            stats: statsResult.rows[0]
        });
        
    } catch (err) {
        // Log error lengkap ke server (untuk debugging)
        console.error('❌ [PARTNER DASHBOARD] Error:', err);
        
        // Response ke user: generik, tidak bocorkan detail error
        res.status(500).send('Terjadi kesalahan pada portal mitra.');
    }
};