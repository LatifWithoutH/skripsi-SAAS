// middleware/partnerMiddleware.js

// 1. Middleware untuk mendeteksi domain mitra
const checkMitraDomain = (req, res, next) => {
    const host = req.headers.host;
    // Portal mitra HANYA aktif di domain mitra.saas.local atau mitra.saas.com
    req.isMitraPortal = (host === 'mitra.saas.local' || host === 'mitra.saas.com');
    next();
};

// 2. Middleware untuk memastikan partner sudah login
const ensurePartnerAuthenticated = (req, res, next) => {
    if (!req.session.mitraAccountId) {
        console.log('[VERBOSE AUTH] Akses portal mitra ditolak: Tidak ada session mitraAccountId');
        return res.redirect('/portal-mitra/login');
    }
    next();
};

module.exports = {
    checkMitraDomain,
    ensurePartnerAuthenticated
};