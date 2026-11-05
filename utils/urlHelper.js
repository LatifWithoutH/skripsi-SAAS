// utils/urlHelper.js

/**
 * Membuat URL dinamis berdasarkan subdomain tenant
 * @param {string} slug - Slug tenant (misal: 'ums')
 * @param {string} path - Path tujuan (misal: '/login')
 * @returns {string} URL lengkap
 */
exports.getTenantUrl = (slug, path = '/') => {
    // Fallback untuk development jika diakses via localhost tanpa subdomain
    if (process.env.NODE_ENV !== 'production' && !slug) {
        return `http://localhost:3000${path.startsWith('/') ? path : '/' + path}`;
    }

    const domain = process.env.APP_DOMAIN || 'saas.local';
    const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
    const safePath = path.startsWith('/') ? path : `/${path}`;
    
    return `${protocol}://${slug}.${domain}${safePath}`;
};

/**
 * Membuat URL untuk Portal Mitra (fixed subdomain)
 * @param {string} path - Path tujuan
 * @returns {string} URL lengkap
 */
exports.getMitraUrl = (path = '/') => {
    const domain = process.env.APP_DOMAIN || 'saas.local';
    const protocol = process.env.NODE_ENV === 'production' ? 'https' : 'http';
    const safePath = path.startsWith('/') ? path : `/${path}`;
    
    return `${protocol}://mitra.${domain}${safePath}`;
};