// utils/timeHelper.js
/**
 * Konversi timestamp UTC ke WIB (Asia/Jakarta)
 * @param {Date|string} utcTime - Timestamp dalam UTC
 * @param {object} options - Opsi format (opsional)
 * @returns {string} - Waktu dalam format WIB
 */
exports.toWIB = (utcTime, options = {}) => {
    if (!utcTime) return '-';
    
    const date = new Date(utcTime);
    
    // Default format: "17 Okt 2026, 06:19 WIB"
    const defaultOptions = {
        timeZone: 'Asia/Jakarta',
        day: 'numeric',
        month: 'short',
        year: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
        hour12: false,
        ...options
    };
    
    return date.toLocaleString('id-ID', defaultOptions) + ' WIB';
};

/**
 * Format relatif (misal: "5 menit lalu")
 */
exports.timeAgo = (utcTime) => {
    if (!utcTime) return '-';
    
    const date = new Date(utcTime);
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    if (seconds < 60) return 'Baru saja';
    if (seconds < 3600) return `${Math.floor(seconds / 60)} menit lalu`;
    if (seconds < 86400) return `${Math.floor(seconds / 3600)} jam lalu`;
    if (seconds < 604800) return `${Math.floor(seconds / 86400)} hari lalu`;
    
    return exports.toWIB(utcTime, { 
        day: 'numeric', 
        month: 'short',
        hour: '2-digit',
        minute: '2-digit'
    });
};