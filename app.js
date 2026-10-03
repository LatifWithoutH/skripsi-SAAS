require('dotenv').config();

// ✅ PERBAIKAN 1: Import pool dan testConnection dari database config
const { testConnection, pool } = require('./config/database');
const express = require('express');
const path = require('path');
const session = require('express-session');
// Pastikan ini ada di bagian atas file app.js
const registerController = require('./controllers/registerController');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// IMPORT CONTROLLER & MIDDLEWARE
// ==========================================
const authController = require('./controllers/authController');
const dashboardController = require('./controllers/dashboardController');
const { ensureAuthenticated } = require('./middleware/tenantAuth');
const mitraController = require('./controllers/mitraController');
const inviteController = require('./controllers/inviteController');
const userController = require('./controllers/userController');
const kerjasamaController = require('./controllers/kerjasamaController');
const partnerAuthController = require('./controllers/partnerAuthController');

// ==========================================
// 1. KONFIGURASI DASAR & MIDDLEWARE
// ==========================================
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: process.env.NODE_ENV === 'production', // True hanya jika HTTPS
        maxAge: 1000 * 60 * 60 * 24 // 24 jam
    }
}));

app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// ==========================================
// 2. MIDDLEWARE PENDETEKSI DOMAIN (WAJIB ADA)
// ==========================================
app.use((req, res, next) => {
    const host = req.headers.host;
    // Deteksi apakah request datang dari subdomain mitra
    req.isMitraPortal = host === 'mitra.saas.local';
    next();
});

// ==========================================
// 3. MIDDLEWARE STRICT ISOLATION (BARU DITAMBAHKAN)
// ==========================================
// Menjaga agar route /portal-mitra TIDAK BISA diakses dari saas.local
const ensureMitraDomain = (req, res, next) => {
    if (!req.isMitraPortal) {
        return res.status(404).send(`
            <div style="text-align:center; margin-top:50px; font-family:sans-serif; color: #333;">
                <h1 style="font-size: 4rem; margin-bottom: 10px;">404</h1>
                <h2 style="font-size: 1.5rem; margin-bottom: 20px;">Halaman Tidak Ditemukan</h2>
                <p style="margin-bottom: 30px;">Anda mencoba mengakses portal yang tidak terdaftar di domain ini.</p>
                <a href="/" style="padding: 10px 20px; background-color: #4f46e5; color: white; text-decoration: none; border-radius: 6px;">
                    Kembali ke Halaman Utama Kampus
                </a>
            </div>
        `);
    }
    next(); // Jika dari mitra.saas.local, izinkan masuk
};

// ==========================================
// 4. ROUTING KAMPUS (saas.local / localhost)
// ==========================================
app.get('/', (req, res) => {
    if (req.isMitraPortal) {
        return res.redirect('/portal-mitra/login');
    }
    res.render('public/index');
});

app.get('/login', (req, res) => res.render('public/login', { error: req.query.error }));

// ... (kode lainnya) ...

app.get('/register', (req, res) => res.render('public/register', { error: req.query.error }));
app.post('/register', registerController.registerTenant); // <-- TAMBAHKAN BARIS INI

app.post('/login', authController.login);
app.post('/logout', authController.logout);

// Route Kampus (Dilindungi ensureAuthenticated)
app.post('/team/invite', ensureAuthenticated, inviteController.inviteUser);
app.get('/mitra', ensureAuthenticated, mitraController.getMitraPage);
app.post('/mitra', ensureAuthenticated, mitraController.createMitra);
app.get('/dashboard', ensureAuthenticated, dashboardController.getDashboard);
app.get('/users', ensureAuthenticated, userController.getUsersPage);
app.post('/users/:id/activate', ensureAuthenticated, userController.activateUser);
app.post('/users/:id/delete', ensureAuthenticated, userController.deleteUser);
app.get('/kerjasama', ensureAuthenticated, kerjasamaController.getKerjasamaPage);
app.post('/kerjasama', ensureAuthenticated, kerjasamaController.createKerjasama);

app.get('/platform/dashboard', (req, res) => {
    const dummyUser = { name: 'Super Admin', role: 'Platform Owner' };
    res.render('platform/dashboard', { user: dummyUser });
});

// ==========================================
// 5. ROUTING PORTAL MITRA (mitra.saas.local)
// ==========================================
const ensurePartnerAuthenticated = (req, res, next) => {
    if (!req.session.mitraAccountId) {
        return res.redirect('/portal-mitra/login');
    }
    next();
};

// ✅ PERHATIAN: Semua route di bawah ini kini dilindungi oleh ensureMitraDomain
app.get('/portal-mitra/login', ensureMitraDomain, (req, res) => {
    if (req.session.mitraAccountId) return res.redirect('/portal-mitra/dashboard');
    res.render('tenant/portal-mitra-login', { error: req.query.error });
});

app.post('/portal-mitra/login', ensureMitraDomain, partnerAuthController.login);
app.post('/portal-mitra/logout', ensureMitraDomain, partnerAuthController.logout);

app.get('/portal-mitra/dashboard', ensureMitraDomain, ensurePartnerAuthenticated, async (req, res) => {
    try {
        const mitraId = req.session.mitraId;
        
        const query = `
            SELECT judul, jenis, tanggal_mulai, tanggal_berakhir, status,
            CASE 
                WHEN tanggal_berakhir < CURRENT_DATE THEN 'expired'
                ELSE status 
            END as current_status
            FROM kerjasama 
            WHERE mitra_id = $1 
            ORDER BY tanggal_berakhir DESC
        `;
        const result = await pool.query(query, [mitraId]);

        const statsQuery = `
            SELECT COUNT(*) as "activeCount" 
            FROM kerjasama 
            WHERE mitra_id = $1 AND tanggal_berakhir >= CURRENT_DATE AND status = 'active'
        `;
        const statsResult = await pool.query(statsQuery, [mitraId]);

        res.render('tenant/portal-mitra-dashboard', {
            mitraName: req.session.mitraName || 'Mitra',
            kerjasamaList: result.rows,
            stats: statsResult.rows[0]
        });
    } catch (err) {
        console.error('❌ [PARTNER DASHBOARD] Error:', err);
        res.status(500).send('Terjadi kesalahan pada portal mitra.');
    }
});

// ==========================================
// 6. HANDLER 404 GLOBAL
// ==========================================
app.use((req, res) => {
    res.status(404).send(`
        <div class="flex items-center justify-center min-h-screen bg-gray-50 font-sans">
            <div class="text-center">
                <h1 class="text-6xl font-bold text-gray-800 mb-4">404</h1>
                <p class="text-xl text-gray-600 mb-6">Halaman yang Anda cari tidak ditemukan.</p>
                <a href="/" class="px-6 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors">
                    Kembali ke Beranda
                </a>
            </div>
        </div>
    `);
});

// ==========================================
// 7. MENJALANKAN SERVER
// ==========================================
testConnection().then(() => {
    app.listen(PORT, () => {
        console.log('---------------------------------------------------');
        console.log(`🚀 Server berhasil dijalankan!`);
        console.log(`🌍 Environment : ${process.env.NODE_ENV || 'development'}`);
        console.log(`🔗 Akses Kampus : http://localhost:${PORT} (atau https://saas.local)`);
        console.log(`🔗 Akses Mitra  : https://mitra.saas.local`);
        console.log('---------------------------------------------------');
    });
}).catch(err => {
    console.error('💥 Gagal memulai server karena masalah database.');
    console.error(err);
});