const { pool } = require('../config/database');

// Daftar subdomain yang dicadangkan untuk sistem (bukan tenant)
const RESERVED_SUBDOMAINS = ['mitra', 'platform', 'www', 'api', 'admin', 'localhost', 'mail', 'ftp', 'cdn', 'status', 'billing', 'help', 'docs'];

const tenantResolver = async (req, res, next) => {
  try {
    // 1. Ambil host dan hapus port jika ada (misal: "ums.saas.local:3000" -> "ums.saas.local")
    const host = req.headers.host ? req.headers.host.split(':')[0].toLowerCase() : '';
    
    // 2. Jika domain utama atau localhost, lewati resolver (akan dihandle oleh route biasa di app.js)
    if (host === 'saas.local' || host === 'localhost' || host === '127.0.0.1') {
      req.isMainDomain = true;
      return next();
    }
    
    // 3. Jika ini adalah portal mitra, lewati (sudah dihandle oleh partnerMiddleware sebelumnya)
    if (req.isMitraPortal) {
      return next();
    }
    
    // 4. Extract slug dari subdomain (misal: "ums.saas.local" -> "ums")
    const parts = host.split('.');
    const slug = parts[0];
    
    // 5. Validasi apakah slug adalah subdomain khusus yang dicadangkan
    if (RESERVED_SUBDOMAINS.includes(slug)) {
      return res.status(404).render('errors/404', {
        message: 'Halaman tidak ditemukan.'
      });
    }
    
    // 6. ✅ PERBAIKAN KRITIS: Izinkan status 'active', 'pending_approval', dan 'rejected'
    // Agar user bisa melihat halaman login tenant dan mendapatkan pesan status yang sesuai
    const query = `
      SELECT id, name, slug, status, subscription_plan
      FROM tenants
      WHERE slug = $1 AND status IN ('active', 'pending_approval', 'rejected')
    `;
    const result = await pool.query(query, [slug]);
    
    // 7. Jika tenant benar-benar tidak ada di database
    if (result.rows.length === 0) {
      return res.status(404).render('errors/404', {
        message: 'Institusi tidak ditemukan.'
      });
    }
    
    // 8. Simpan data tenant ke object request agar bisa dipakai di controller/view
    req.tenant = result.rows[0];
    next(); // Lanjut ke route handler berikutnya (misal: app.get('/login'))
    
  } catch (error) {
    console.error('❌ [TENANT RESOLVER] Error:', error);
    res.status(500).render('errors/404', {
      message: 'Terjadi kesalahan pada server saat memuat institusi.'
    });
  }
};

module.exports = tenantResolver;