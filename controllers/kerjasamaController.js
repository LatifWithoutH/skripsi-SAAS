const { pool } = require('../config/database');

// 1. Menampilkan Halaman & Data Kerjasama
exports.getKerjasamaPage = async (req, res) => {
    try {
        const tenantId = req.session.tenantId;
        const unitId = req.session.unitId; // ✅ Ambil dari session, bukan dari parameter
        const userRole = req.session.role;

        // --- QUERY UTAMA (DAFTAR KERJASAMA) ---
        let query = `
            SELECT
                k.id, k.judul, k.jenis, k.tanggal_mulai, k.tanggal_berakhir,
                m.name as mitra_name,
                u.name as unit_name,
                CASE
                    WHEN k.tanggal_berakhir < CURRENT_DATE THEN 'expired'
                    ELSE k.status
                END as current_status
            FROM kerjasama k
            LEFT JOIN mitras m ON k.mitra_id = m.id
            LEFT JOIN units u ON k.unit_id = u.id
            WHERE k.tenant_id = $1
        `;
        
        const params = [tenantId];

        // ✅ Faculty operator hanya lihat punya unit mereka (atau yang tidak di-assign ke unit spesifik)
        if (userRole === 'faculty_operator' && unitId) {
            query += ` AND (k.unit_id = $2 OR k.unit_id IS NULL)`;
            params.push(unitId);
        }

        query += ` ORDER BY k.tanggal_berakhir ASC`;
        const result = await pool.query(query, params);

        // --- QUERY STATISTIK (DIPERBAIKI) ---
        let statsQuery = `
            SELECT
                COUNT(CASE WHEN tanggal_berakhir >= CURRENT_DATE AND status = 'active' THEN 1 END) as active_count,
                COUNT(CASE WHEN tanggal_berakhir < CURRENT_DATE OR status = 'expired' THEN 1 END) as expired_count
            FROM kerjasama
            WHERE tenant_id = $1
        `;
        let statsParams = [tenantId];

        // ✅ Faculty operator stats juga harus difilter by unit agar sinkron dengan tabel
        if (userRole === 'faculty_operator' && unitId) {
            statsQuery += ` AND (unit_id = $2 OR unit_id IS NULL)`;
            statsParams.push(unitId);
        }

        const statsResult = await pool.query(statsQuery, statsParams);

        // --- QUERY DROPDOWN MITRA ---
        const mitraQuery = `SELECT id, name FROM mitras WHERE tenant_id = $1 AND status = 'active' ORDER BY name`;
        const mitraResult = await pool.query(mitraQuery, [tenantId]);

        // --- QUERY DROPDOWN UNIT ---
        let units = [];
        // ✅ Hanya tenant_owner/it_admin yang boleh melihat semua unit untuk dipilih
        if (userRole !== 'faculty_operator') {
            const unitsQuery = `SELECT id, name, code FROM units WHERE tenant_id = $1 AND status = 'active' ORDER BY name`;
            const unitsResult = await pool.query(unitsQuery, [tenantId]);
            units = unitsResult.rows;
        }

        res.render('tenant/kerjasama', {
            user: { 
                name: req.session.userName, 
                role: req.session.role, 
                unitName: req.session.unitName 
            },
            kerjasamaList: result.rows,
            stats: statsResult.rows[0],
            mitras: mitraResult.rows,
            units: units, // ✅ Kirim units ke view
            success: req.query.success === 'true',
            error: req.query.error
        });
    } catch (err) {
        console.error('❌ [KERJASAMA] Error mengambil data:', err);
        res.redirect('/dashboard?error=server_error');
    }
};

// 2. Menyimpan Dokumen Kerjasama Baru
exports.createKerjasama = async (req, res) => {
    try {
        const { judul, jenis, tanggal_mulai, tanggal_berakhir, mitra_id, unit_id } = req.body;
        const tenantId = req.session.tenantId;
        const userId = req.session.userId;
        const userRole = req.session.role;
        const userUnitId = req.session.unitId;

        // ✅ VALIDASI: Faculty operator hanya bisa buat kerjasama untuk unit mereka sendiri
        if (userRole === 'faculty_operator' && unit_id && unit_id !== userUnitId) {
            return res.redirect('/kerjasama?error=forbidden_unit');
        }

        // ✅ Jika faculty_operator dan tidak pilih unit, paksa pakai unit mereka
        const finalUnitId = (userRole === 'faculty_operator') ? userUnitId : (unit_id || null);

        // Tentukan status awal berdasarkan tanggal berakhir
        const today = new Date().toISOString().split('T')[0];
        const initialStatus = tanggal_berakhir < today ? 'expired' : 'active';

        const insertQuery = `
            INSERT INTO kerjasama (
                id, tenant_id, mitra_id, unit_id, created_by, judul, jenis, 
                tanggal_mulai, tanggal_berakhir, status
            )
            VALUES (gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7, $8, $9)
            RETURNING id
        `;
        
        await pool.query(insertQuery, [
            tenantId,
            mitra_id || null,
            finalUnitId, // ✅ Gunakan finalUnitId yang sudah divalidasi
            userId,
            judul,
            jenis,
            tanggal_mulai,
            tanggal_berakhir,
            initialStatus
        ]);

        // TODO: Tambahkan Audit Log di sini jika diperlukan
        // await pool.query('INSERT INTO audit_logs ...', [...]);

        res.redirect('/kerjasama?success=true');
    } catch (err) {
        console.error('❌ [KERJASAMA] Error menyimpan data:', err);
        res.redirect('/kerjasama?error=true');
    }
};

// (Opsional) Tambahkan fungsi updateKerjasama dan deleteKerjasama di bawah ini 
// jika diperlukan untuk kelengkapan CRUD