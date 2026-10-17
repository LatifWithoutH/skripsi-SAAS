// middleware/platformAuth.js
exports.ensurePlatformAdmin = (req, res, next) => {
    // Cek apakah session platformAdminId ada (bukan userId atau role biasa)
    if (req.session && req.session.platformAdminId) {
        return next();
    }
    
    // Jika bukan, tendang kembali ke login platform
    return res.redirect('/platform/login?error=Akses ditolak. Silakan login sebagai Super Admin Platform.');
};