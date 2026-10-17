require('dotenv').config();
const morgan = require('morgan');
const helmet = require('helmet'); // ✅ TAMBAHAN: Security Headers

const { testConnection, pool } = require('./config/database');
const express = require('express');
const path = require('path');
const session = require('express-session');
const rateLimit = require('express-rate-limit');



console.log('🔍 [VERBOSE] Memulai inisialisasi aplikasi...');

// ==========================================
// 1. IMPORT CONTROLLERS
// ==========================================
console.log('📂 [VERBOSE] Memuat Controllers...');
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
console.log('✅ [VERBOSE] Semua Controllers berhasil dimuat.');

// ==========================================
// 2. IMPORT MIDDLEWARE
// ==========================================
console.log('🛡️ [VERBOSE] Memuat Middlewares...');
const { ensureAuthenticated } = require('./middleware/tenantAuth');
const upload = require('./middleware/upload');
const { ensurePlatformAdmin } = require('./middleware/platformAuth');
console.log('✅ [VERBOSE] Semua Middlewares berhasil dimuat.');

const app = express();
const PORT = process.env.PORT || 3000;


const timeHelper = require('./utils/timeHelper');

// ==========================================
// ✅ PERBAIKAN KEAMANAN (A02 & A09)
// ==========================================
// 1. Trust Proxy: Wajib agar req.ip membaca IP asli (bukan IP internal Docker/Nginx)
app.set('trust proxy', 1);

// 2. Hide X-Powered-By: Mencegah kebocoran info stack teknologi
app.disable('x-powered-by');

// 3. Helmet: Menambahkan header keamanan standar (CSP dimatikan sementara agar tidak bentrok dengan inline script EJS)
app.use(helmet({
    contentSecurityPolicy: false,
    crossOriginEmbedderPolicy: false
}));

// ==========================================
// 3. KONFIGURASI DASAR & MIDDLEWARE LOGGING
// ==========================================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(morgan(':method :url :status :response-time ms - :res[content-length] bytes'));

app.use((req, res, next) => {
    if (process.env.NODE_ENV !== 'production') {
        const sessionInfo = req.session ? {
            userId: req.session.userId || 'None',
            platformAdminId: req.session.platformAdminId || 'None',
            role: req.session.role || req.session.platformRole || 'Guest',
            tenantId: req.session.tenantId || 'None',
            mitraId: req.session.mitraId || 'None'
        } : 'No Session';
        
        console.log(`👤 [VERBOSE SESSION] ${req.method} ${req.url} | User:`, sessionInfo);
    }
    next();
});

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production',
        httpOnly: true,
        sameSite: 'lax',
        maxAge: 1000 * 60 * 60 * 24
    }
}));

// Tambahkan sebelum app.set('view engine', 'ejs');
app.locals.toWIB = timeHelper.toWIB;
app.locals.timeAgo = timeHelper.timeAgo;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('view cache', false); 

// ==========================================
// 4. RATE LIMITING
// ==========================================
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { error: 'Terlalu banyak percobaan login. Silakan coba lagi dalam 15 menit.' },
  standardHeaders: true,
  legacyHeaders: false,
});

const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 3,
  message: { error: 'Terlalu banyak percobaan registrasi. Silakan coba lagi dalam 15 menit.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// ==========================================
// 5. DOMAIN ISOLATION & AUTH MIDDLEWARE
// ==========================================
app.use((req, res, next) => {
    const host = req.headers.host;
    
    // Portal mitra HANYA aktif di domain mitra.saas.local atau mitra.saas.com
    // localhost:3000 adalah default untuk tenant/kampus
    req.isMitraPortal = (host === 'mitra.saas.local' || host === 'mitra.saas.com');
    
    next();
});

const ensurePartnerAuthenticated = (req, res, next) => {
    if (!req.session.mitraAccountId) {
        console.log(' [VERBOSE AUTH] Akses portal mitra ditolak: Tidak ada session mitraAccountId');
        return res.redirect('/portal-mitra/login');
    }
    next();
};

// ==========================================
// 6. ROUTING PUBLIK & KAMPUS (TENANT)
// ==========================================
app.get('/', (req, res) => {
    if (req.isMitraPortal) return res.redirect('/portal-mitra/login');
    res.render('public/index');
});

app.get('/login', (req, res) => res.render('public/login', { error: req.query.error }));
app.get('/register', (req, res) => res.render('public/register', { error: req.query.error }));

app.post('/register', registerLimiter, registerController.registerTenant);
app.post('/login', authLimiter, authController.login);
app.post('/logout', authController.logout);

app.post('/team/invite', ensureAuthenticated, inviteController.inviteUser);

app.get('/mitra', ensureAuthenticated, mitraController.getMitraPage);
app.post('/mitra/create', ensureAuthenticated, mitraController.createMitra);
app.post('/mitra/update/:mitra_id', ensureAuthenticated, mitraController.updateMitra);
app.post('/mitra/delete/:mitra_id', ensureAuthenticated, mitraController.deleteMitra);

app.get('/dashboard', ensureAuthenticated, dashboardController.getDashboard);
app.get('/users', ensureAuthenticated, userController.getUsersPage);
app.post('/users/:id/activate', ensureAuthenticated, userController.activateUser);
app.post('/users/:id/delete', ensureAuthenticated, userController.deleteUser);

app.get('/kerjasama', ensureAuthenticated, kerjasamaController.getKerjasamaPage);
app.post('/kerjasama', ensureAuthenticated, kerjasamaController.createKerjasama);

// ==========================================
// 7. ROUTING PORTAL PLATFORM (SUPERADMIN)
// ==========================================
app.get('/platform/login', platformAuthController.showLogin);
app.post('/platform/login', authLimiter, platformAuthController.handleLogin);
app.post('/platform/logout', platformAuthController.logout);

app.get('/platform/dashboard', ensurePlatformAdmin, platformController.getDashboard);
app.post('/platform/tenants/:tenantId/approve', ensurePlatformAdmin, platformController.approveTenant);
app.post('/platform/tenants/:tenantId/reject', ensurePlatformAdmin, platformController.rejectTenant);

// ==========================================
// 8. ROUTING PORTAL MITRA
// ==========================================
app.get('/portal-mitra/first-login', partnerAuthController.firstLogin);
app.post('/portal-mitra/change-password', partnerAuthController.changePassword);

app.get('/portal-mitra/login', (req, res) => {
    if (req.session.mitraAccountId) return res.redirect('/portal-mitra/dashboard');
    res.render('portal-mitra/login', { error: req.query.error });
});

app.post('/portal-mitra/login', authLimiter, partnerAuthController.login);
app.post('/portal-mitra/logout', partnerAuthController.logout);

app.get('/portal-mitra/dashboard', ensurePartnerAuthenticated, async (req, res) => {
    try {
        const mitraId = req.session.mitraId;
        
        const query = `
            SELECT 
                k.judul, k.jenis, k.tanggal_mulai, k.tanggal_berakhir, k.status,
                t.name as tenant_name,
                CASE WHEN k.tanggal_berakhir < CURRENT_DATE THEN 'expired' ELSE k.status END as current_status 
            FROM kerjasama k
            JOIN tenants t ON t.id = k.tenant_id
            WHERE k.mitra_id = $1 
            ORDER BY k.tanggal_berakhir DESC
        `;
        const result = await pool.query(query, [mitraId]);
        
        const statsQuery = `
            SELECT COUNT(*) as "activeCount" 
            FROM kerjasama 
            WHERE mitra_id = $1 AND tanggal_berakhir >= CURRENT_DATE AND status = 'active'
        `;
        const statsResult = await pool.query(statsQuery, [mitraId]);

        res.render('portal-mitra/dashboard', {
            mitraName: req.session.mitraName || 'Mitra',
            kerjasamaList: result.rows,
            stats: statsResult.rows[0]
        });
    } catch (err) {
        console.error('❌ [PARTNER DASHBOARD] Error:', err);
        res.status(500).send('Terjadi kesalahan pada portal mitra.');
    }
});

app.post('/portal-mitra/upload-dokumen', ensurePartnerAuthenticated, upload.single('dokumen'), uploadController.uploadDokumen);

// ==========================================
// 9. HANDLER 404 GLOBAL
// ==========================================
app.use((req, res) => {
    console.log(`⚠️ [VERBOSE 404] Route tidak ditemukan: ${req.method} ${req.url}`);
    res.status(404).send(`
        <div class="flex items-center justify-center min-h-screen bg-gray-50 font-sans">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-800 mb-4">404</h1>
                <p class="text-xl text-gray-600 mb-6">Halaman tidak ditemukan.</p>
                <a href="/" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition">Kembali ke Beranda</a>
            </div>
        </div>
    `);
});

// ==========================================
// 10. MENJALANKAN SERVER
// ==========================================
testConnection().then(() => {
    app.listen(PORT, () => {
        console.log('=======================================================');
        console.log('🚀 [VERBOSE] Server SIMITRADUDIKA berhasil dijalankan!');
        console.log(`🌍 Environment : ${process.env.NODE_ENV || 'development'}`);
        console.log(`🔗 Akses Kampus   : http://localhost:${PORT}`);
        console.log(`🔗 Akses Platform : http://localhost:${PORT}/platform/login`);
        console.log(`🔗 Akses Mitra    : http://localhost:${PORT}/portal-mitra/login`);
        console.log(`🛡️ Rate Limiting  : ACTIVE`);
        console.log(`📝 Logging Mode   : VERBOSE (Morgan + Custom)`);
        console.log('=======================================================');
    });
}).catch(err => {
    console.error('💥 [VERBOSE] Gagal memulai server karena masalah database.');
    console.error(err);
});

module.exports = app;