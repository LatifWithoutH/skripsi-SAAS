const { pool } = require('../config/database');

exports.findWorkspace = async (req, res) => {
  try {
    // 1. Sanitasi Input
    const identifier = req.body.identifier?.trim().toLowerCase();
    
    // 🆕 Cek apakah request berasal dari AJAX/Fetch (untuk mendukung Popup Modal)
    const isAjax = req.headers['x-requested-with'] === 'XMLHttpRequest';

    if (!identifier) {
      const errorMsg = 'Identifikasi tidak boleh kosong.';
      return isAjax 
        ? res.status(400).json({ success: false, error: errorMsg })
        : res.render('public/login', { error: errorMsg });
    }

    let slug = null;

    // 2. Jika input adalah Email (mengandung @)
    if (identifier.includes('@')) {
      // Cari tenant berdasarkan email user (Unik Global)
      const userQuery = `
        SELECT t.slug, t.status 
        FROM users u
        JOIN tenants t ON u.tenant_id = t.id
        WHERE LOWER(u.email) = $1
      `;
      const userResult = await pool.query(userQuery, [identifier]);
      
      if (userResult.rows.length > 0) {
        const tenant = userResult.rows[0];
        if (tenant.status !== 'active') {
          // 🛡️ Anti User Enumeration: Pesan tetap terdengar seperti "berhasil diproses"
          const msg = 'Jika email Anda terdaftar, Anda akan menerima instruksi login. Saat ini, akun institusi tersebut sedang tidak aktif.';
          return isAjax 
            ? res.json({ success: false, error: msg })
            : res.render('public/login', { success: msg });
        }
        slug = tenant.slug;
      } else {
        // 🛡️ Anti User Enumeration: Pesan SAMA PERSIS agar penyerang tidak bisa menebak email yang terdaftar
        const msg = 'Jika email Anda terdaftar di sistem, Anda akan diarahkan ke halaman login institusi Anda.';
        return isAjax 
          ? res.json({ success: false, error: msg })
          : res.render('public/login', { success: msg });
      }
    } 
    // 3. Jika input adalah Subdomain (Slug)
    else {
      // Validasi format slug (hanya huruf kecil, angka, strip, 3-30 karakter)
      const slugRegex = /^[a-z0-9-]{3,30}$/;
      if (!slugRegex.test(identifier)) {
        const errorMsg = 'Format subdomain tidak valid. Gunakan huruf kecil, angka, atau strip (-), minimal 3 karakter.';
        return isAjax 
          ? res.status(400).json({ success: false, error: errorMsg })
          : res.render('public/login', { error: errorMsg });
      }

      const tenantQuery = `SELECT slug, status FROM tenants WHERE slug = $1`;
      const tenantResult = await pool.query(tenantQuery, [identifier]);
      
      if (tenantResult.rows.length > 0) {
        const tenant = tenantResult.rows[0];
        if (tenant.status !== 'active') {
          const errorMsg = 'Institusi ini sedang dalam proses verifikasi atau telah ditangguhkan.';
          return isAjax 
            ? res.status(403).json({ success: false, error: errorMsg })
            : res.render('public/login', { error: errorMsg });
        }
        slug = tenant.slug;
      } else {
        const errorMsg = 'Institusi dengan subdomain tersebut tidak ditemukan.';
        return isAjax 
          ? res.status(404).json({ success: false, error: errorMsg })
          : res.render('public/login', { error: errorMsg });
      }
    }

    // 4. Redirect Aman (Mencegah Open Redirect karena slug divalidasi langsung dari DB)
    const domain = process.env.APP_DOMAIN || 'saas.local';
    
    // 🛠️ PERBAIKAN KRITIS: Deteksi protokol dari Nginx (X-Forwarded-Proto), fallback ke http/https
    // Ini menghilangkan kebutuhan hardcode port :3000, karena Nginx akan menangani routing port secara transparan.
    const protocol = req.headers['x-forwarded-proto'] || (process.env.NODE_ENV === 'production' ? 'https' : 'http');
    
    // URL bersih tanpa port eksplisit (serahkan ke Nginx)
    const redirectUrl = `${protocol}://${slug}.${domain}/login`;
    
    // Log untuk debugging (bisa dilihat di terminal Node.js)
    console.log(`✅ [FIND WORKSPACE] Redirecting to: ${redirectUrl}`);
    
    // 🆕 Jika AJAX, kirim URL sebagai JSON agar frontend bisa menampilkannya di Modal Popup
    if (isAjax) {
      return res.json({ 
        success: true, 
        url: redirectUrl,
        name: slug.toUpperCase() // Untuk ditampilkan di popup (misal: "UMS")
      });
    }

    // Fallback: Jika JavaScript dimatikan di browser, tetap redirect normal
    return res.redirect(redirectUrl);

  } catch (err) {
    console.error('❌ [FIND WORKSPACE] Error:', err);
    const errorMsg = 'Terjadi kesalahan pada server. Silakan coba lagi.';
    
    return isAjax
      ? res.status(500).json({ success: false, error: errorMsg })
      : res.render('public/login', { error: errorMsg });
  }
};