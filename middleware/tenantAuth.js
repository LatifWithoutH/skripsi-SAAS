// Middleware untuk memastikan user sudah login
exports.ensureAuthenticated = (req, res, next) => {
    if (req.session && req.session.userId) {
        // User sudah login, lanjutkan ke route berikutnya
        next();
    } else {
        // User belum login, lempar kembali ke halaman login
        res.redirect('/login');
    }
};

// Middleware untuk memastikan user memiliki role tertentu (Opsional, untuk pengembangan)
exports.ensureRole = (allowedRoles) => {
    return (req, res, next) => {
        if (req.session && allowedRoles.includes(req.session.role)) {
            next();
        } else {
            res.status(403).send('Akses Ditolak: Anda tidak memiliki izin untuk mengakses halaman ini.');
        }
    };
};