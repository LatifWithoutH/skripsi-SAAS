require('dotenv').config();
const morgan = require('morgan');
const helmet = require('helmet');
const express = require('express');
const path = require('path');
const session = require('express-session');

// ==========================================
// 1. IMPORT DATABASE & HELPERS
// ==========================================
const { testConnection, pool } = require('./config/database');
const timeHelper = require('./utils/timeHelper');

// ==========================================
// 2. IMPORT CONTROLLERS
// ==========================================
const registerController = require('./controllers/registerController');
const authController = require('./controllers/authController');
const dashboardController = require('./controllers/dashboardController');
const mitraController = require('./controllers/mitraController');
const inviteController = require('./controllers/inviteController');
const userController = require('./controllers/userController');
const kerjasamaController = require('./controllers/kerjasamaController');
const partnerAuthController = require('./controllers/partnerAuthController');
const uploadController = require('./controllers/uploadController');
const platformAuthController = require('./controllers/platformAuthController');
const platformController = require('./controllers/platformController');
const partnerController = require('./controllers/partnerController');
const workspaceController = require('./controllers/workspaceController');

// ==========================================
// 3. IMPORT MIDDLEWARE (Termasuk RBAC)
// ==========================================
const { ensureAuthenticated } = require('./middleware/tenantAuth');
const { checkPermission, can } = require('./middleware/checkPermission'); // ✅ RBAC Terpusat
const upload = require('./middleware/upload');
const { ensurePlatformAdmin } = require('./middleware/platformAuth');
const { checkMitraDomain, ensurePartnerAuthenticated } = require('./middleware/partnerMiddleware');
const { authLimiter, registerLimiter } = require('./middleware/rateLimiter');
const tenantResolver = require('./middleware/tenantResolver');

// ==========================================
// 4. INISIALISASI APP
// ==========================================
const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 5. KEAMANAN DASAR (OWASP A02)
// ==========================================
app.set('trust proxy', 1); // Wajib agar rate limiter & audit log dapat IP asli dari Nginx
app.disable('x-powered-by'); // Sembunyikan identitas Express

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      // ✅ HAPUS CDN, GANTI DENGAN 'self' SAJA
      scriptSrc: ["'self'"], 
      // ✅ HAPUS Google Fonts, gunakan 'unsafe-inline' untuk style dinamis EJS/Tailwind
      styleSrc: ["'self'", "'unsafe-inline'"], 
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'", "data:"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      formAction: ["'self'"],
    },
  },
  crossOriginEmbedderPolicy: false, // Wajib false untuk development lokal
  // Matikan HSTS di development agar tidak memaksa HTTPS jika cert belum siap
  strictTransportSecurity: process.env.NODE_ENV === 'production' ? { maxAge: 31536000, includeSubDomains: true } : false,
}));

// ==========================================
// 6. KONFIGURASI DASAR & LOGGING
// ==========================================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Morgan untuk logging HTTP request
app.use(morgan(':method :url :status :response-time ms - :res[content-length] bytes'));

// Debugging session (Hanya di development)
app.use((req, res, next) => {
    if (process.env.NODE_ENV !== 'production') {
        const sessionInfo = req.session ? {
            userId: req.session.userId || 'None',
            role: req.session.role || req.session.platformRole || 'Guest',
            tenantId: req.session.tenantId || 'None',
            mitraId: req.session.mitraId || 'None'
        } : 'No Session';
        console.log(`👤 [SESSION] ${req.method} ${req.url} |`, sessionInfo);
    }
    next();
});

// Session Configuration
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // Hanya HTTPS di production
        httpOnly: true, // Mencegah akses via JavaScript (Anti-XSS)
        sameSite: 'lax', // Melindungi dari CSRF lintas subdomain
        maxAge: 1000 * 60 * 60 * 24 // 24 jam
    }
}));

// ==========================================
// 7. VIEW ENGINE & GLOBAL HELPERS
// ==========================================
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('view cache', false);

app.locals.toWIB = timeHelper.toWIB;
app.locals.timeAgo = timeHelper.timeAgo;

// ✅ HELPER RBAC UNTUK VIEW (EJS)
// Memungkinkan penggunaan: <% if (can(user.role, 'write:mitra')) { %> di file .ejs
app.locals.can = can; 

// ==========================================
// 8. DOMAIN ISOLATION & TENANT RESOLUTION
// ==========================================
// Urutan PENTING: Cek mitra dulu, baru resolve tenant umum
app.use(checkMitraDomain);
app.use(tenantResolver);

// ==========================================
// 9. ROUTING PUBLIK & KAMPUS (TENANT)
// ==========================================
app.get('/', (req, res) => {
    if (req.isMitraPortal) return res.redirect('/portal-mitra/login');
    if (req.isMainDomain) return res.render('public/index');
    if (req.tenant) {
        if (req.session.userId) return res.redirect('/dashboard');
        return res.redirect('/login');
    }
    res.render('public/index');
});

app.get('/login', (req, res) => {
    if (req.tenant) {
        return res.render('tenant/login', { error: req.query.error, tenant: req.tenant });
    }
    res.render('public/login', { error: req.query.error, success: req.query.success });
});

app.get('/register', (req, res) => res.render('public/register', { error: req.query.error }));
app.get('/register-success', (req, res) => res.render('public/register-success', { slug: req.query.slug || null }));

// API Cek Slug Real-time
app.get('/api/check-slug', async (req, res) => {
    try {
        const { slug } = req.query;
        if (!slug) return res.status(400).json({ available: false, message: 'Slug diperlukan' });
        
        const slugRegex = /^[a-z0-9-]{3,30}$/;
        if (!slugRegex.test(slug)) {
            return res.json({ available: false, message: 'Hanya huruf kecil, angka, dan strip (-), min. 3 karakter.' });
        }

        const RESERVED = ['mitra', 'platform', 'www', 'api', 'admin', 'localhost', 'mail', 'ftp', 'cdn', 'status', 'billing', 'help', 'docs'];
        if (RESERVED.includes(slug)) {
            return res.json({ available: false, message: 'Slug ini dicadangkan oleh sistem.' });
        }

        const result = await pool.query('SELECT id FROM tenants WHERE slug = $1', [slug]);
        if (result.rows.length > 0) {
            return res.json({ available: false, message: 'Slug ini sudah digunakan institusi lain.' });
        }

        res.json({ available: true, message: 'Slug tersedia!' });
    } catch (err) {
        console.error('❌ [CHECK SLUG] Error:', err);
        res.status(500).json({ available: false, message: 'Terjadi kesalahan server' });
    }
});

app.post('/register', registerLimiter, registerController.registerTenant);
app.post('/find-workspace', authLimiter, workspaceController.findWorkspace);
app.post('/login', authLimiter, authController.login);
app.post('/logout', authController.logout);

// ==========================================
// 10. ROUTING TENANT (DENGAN RBAC ENFORCEMENT)
// ==========================================
// MITRA
app.get('/mitra', ensureAuthenticated, checkPermission('read:mitra'), mitraController.getMitraPage);
app.post('/mitra/create', ensureAuthenticated, checkPermission('write:mitra'), mitraController.createMitra);
app.post('/mitra/update/:mitra_id', ensureAuthenticated, checkPermission('write:mitra'), mitraController.updateMitra);
app.post('/mitra/delete/:mitra_id', ensureAuthenticated, checkPermission('write:mitra'), mitraController.deleteMitra);

// KERJASAMA
app.get('/kerjasama', ensureAuthenticated, checkPermission('read:kerjasama'), kerjasamaController.getKerjasamaPage);
app.post('/kerjasama', ensureAuthenticated, checkPermission('write:kerjasama'), kerjasamaController.createKerjasama);

// USERS & TIM
app.get('/users', ensureAuthenticated, checkPermission('read:users'), userController.getUsersPage);
app.post('/users/:id/activate', ensureAuthenticated, checkPermission('write:users'), userController.activateUser);
app.post('/users/:id/delete', ensureAuthenticated, checkPermission('write:users'), userController.deleteUser);
app.post('/team/invite', ensureAuthenticated, checkPermission('write:users'), inviteController.inviteUser);

// DASHBOARD
app.get('/dashboard', ensureAuthenticated, dashboardController.getDashboard);

// ==========================================
// 11. ROUTING PORTAL PLATFORM (SUPERADMIN)
// ==========================================
app.get('/platform/login', platformAuthController.showLogin);
app.post('/platform/login', authLimiter, platformAuthController.handleLogin);
app.post('/platform/logout', platformAuthController.logout);

app.get('/platform/dashboard', ensurePlatformAdmin, platformController.getDashboard);
app.post('/platform/tenants/:tenantId/approve', ensurePlatformAdmin, platformController.approveTenant);
app.post('/platform/tenants/:tenantId/reject', ensurePlatformAdmin, platformController.rejectTenant);

// ==========================================
// 12. ROUTING PORTAL MITRA
// ==========================================
app.get('/portal-mitra/first-login', partnerAuthController.firstLogin);
app.post('/portal-mitra/change-password', partnerAuthController.changePassword);

app.get('/portal-mitra/login', (req, res) => {
    if (req.session.mitraAccountId) return res.redirect('/portal-mitra/dashboard');
    res.render('portal-mitra/login', { error: req.query.error });
});
app.post('/portal-mitra/login', authLimiter, partnerAuthController.login);
app.post('/portal-mitra/logout', partnerAuthController.logout);

app.get('/portal-mitra/dashboard', ensurePartnerAuthenticated, partnerController.getDashboard);
app.post('/portal-mitra/upload-dokumen', ensurePartnerAuthenticated, upload.single('dokumen'), uploadController.uploadDokumen);

// ==========================================
// 13. HANDLER 404 GLOBAL
// ==========================================
app.use((req, res) => {
    console.log(`⚠️ [404] Route tidak ditemukan: ${req.method} ${req.url}`);
    res.status(404).render('errors/404', { message: 'Halaman yang Anda cari tidak ditemukan.' });
});

// ==========================================
// 14. GLOBAL ERROR HANDLER (OWASP A10)
// ==========================================
// WAJIB ada di paling bawah, setelah semua route dan 404 handler
app.use((err, req, res, next) => {
    console.error('💥 [GLOBAL ERROR HANDLER]:', err.message);
    
    // Jangan pernah kirim err.stack ke client di production!
    res.status(500).json({ 
        error: 'Terjadi kesalahan internal pada server.',
        // stack: process.env.NODE_ENV === 'development' ? err.stack : undefined 
    });
});

// ==========================================
// 15. MENJALANKAN SERVER
// ==========================================
testConnection().then(() => {
    app.listen(PORT, () => {
        console.log('=======================================================');
        console.log('🚀 Server SIMITRADUDIKA berhasil dijalankan!');
        console.log(`🌍 Environment : ${process.env.NODE_ENV || 'development'}`);
        console.log(`🔗 Akses Publik   : http://localhost:${PORT}`);
        console.log(`🔗 Akses Tenant   : http://[slug].saas.local:${PORT} (misal: ums.saas.local)`);
        console.log(`🔗 Akses Platform : http://localhost:${PORT}/platform/login`);
        console.log(`🔗 Akses Mitra    : http://mitra.saas.local:${PORT}/portal-mitra/login`);
        console.log(`🛡️ Rate Limiting  : ACTIVE`);
        console.log(`🛡️ RBAC Enforcer  : ACTIVE`);
        console.log('=======================================================');
    });
}).catch(err => {
    console.error('💥 Gagal memulai server karena masalah database.');
    console.error(err);
});

module.exports = app;