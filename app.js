require('dotenv').config();
const morgan = require('morgan');
const helmet = require('helmet');

const { testConnection } = require('./config/database'); 
const express = require('express');
const path = require('path');
const session = require('express-session');

// ==========================================
// 1. IMPORT CONTROLLERS
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
const partnerController = require('./controllers/partnerController'); // ✅ Logika SQL sudah dipindah ke sini

// ==========================================
// 2. IMPORT MIDDLEWARE
// ==========================================
const { ensureAuthenticated } = require('./middleware/tenantAuth');
const upload = require('./middleware/upload');
const { ensurePlatformAdmin } = require('./middleware/platformAuth');
const { checkMitraDomain, ensurePartnerAuthenticated } = require('./middleware/partnerMiddleware');
const { authLimiter, registerLimiter } = require('./middleware/rateLimiter'); // ✅ BARU: Rate limiter dipisah

const app = express();
const PORT = process.env.PORT || 3000;
const timeHelper = require('./utils/timeHelper');

// ==========================================
// ✅ PERBAIKAN KEAMANAN (A02 & A09)
// ==========================================
app.set('trust proxy', 1);
app.disable('x-powered-by');
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

// Logging session hanya untuk development
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

app.locals.toWIB = timeHelper.toWIB;
app.locals.timeAgo = timeHelper.timeAgo;

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.set('view cache', false); 

// ==========================================
// 4. DOMAIN ISOLATION
// ==========================================
app.use(checkMitraDomain);

// ==========================================
// 5. ROUTING PUBLIK & KAMPUS (TENANT)
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
// 6. ROUTING PORTAL PLATFORM (SUPERADMIN)
// ==========================================
app.get('/platform/login', platformAuthController.showLogin);
app.post('/platform/login', authLimiter, platformAuthController.handleLogin);
app.post('/platform/logout', platformAuthController.logout);

app.get('/platform/dashboard', ensurePlatformAdmin, platformController.getDashboard);
app.post('/platform/tenants/:tenantId/approve', ensurePlatformAdmin, platformController.approveTenant);
app.post('/platform/tenants/:tenantId/reject', ensurePlatformAdmin, platformController.rejectTenant);

// ==========================================
// 7. ROUTING PORTAL MITRA
// ==========================================
app.get('/portal-mitra/first-login', partnerAuthController.firstLogin);
app.post('/portal-mitra/change-password', partnerAuthController.changePassword);

app.get('/portal-mitra/login', (req, res) => {
    if (req.session.mitraAccountId) return res.redirect('/portal-mitra/dashboard');
    res.render('portal-mitra/login', { error: req.query.error });
});

app.post('/portal-mitra/login', authLimiter, partnerAuthController.login);
app.post('/portal-mitra/logout', partnerAuthController.logout);

// ✅ BERSIH: Routing sekarang hanya 1 baris, logika SQL ada di partnerController
app.get('/portal-mitra/dashboard', ensurePartnerAuthenticated, partnerController.getDashboard);
app.post('/portal-mitra/upload-dokumen', ensurePartnerAuthenticated, upload.single('dokumen'), uploadController.uploadDokumen);

// ==========================================
// 8. HANDLER 404 GLOBAL
// ==========================================
app.use((req, res) => {
    console.log(`⚠️ [404] Route tidak ditemukan: ${req.method} ${req.url}`);
    // ✅ Render file EJS, bukan HTML inline
    res.status(404).render('errors/404'); 
});

// ==========================================
// 9. MENJALANKAN SERVER
// ==========================================
testConnection().then(() => {
    app.listen(PORT, () => {
        console.log('=======================================================');
        console.log('🚀 Server SIMITRADUDIKA berhasil dijalankan!');
        console.log(`🌍 Environment : ${process.env.NODE_ENV || 'development'}`);
        console.log(`🔗 Akses Kampus   : http://localhost:${PORT}`);
        console.log(`🔗 Akses Platform : http://localhost:${PORT}/platform/login`);
        console.log(`🔗 Akses Mitra    : http://localhost:${PORT}/portal-mitra/login`);
        console.log(`🛡️ Rate Limiting  : ACTIVE (via middleware/rateLimiter.js)`);
        console.log('=======================================================');
    });
}).catch(err => {
    console.error('💥 Gagal memulai server karena masalah database.');
    console.error(err);
});

module.exports = app;