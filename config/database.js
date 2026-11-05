const { Pool } = require('pg');
require('dotenv').config();

// 1. Inisialisasi Connection Pool
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    max: 20, // Maksimal 20 koneksi sekaligus
    idleTimeoutMillis: 30000, // Tutup koneksi yang menganggur > 30 detik
    connectionTimeoutMillis: 2000, // Timeout jika DB tidak merespons > 2 detik
});

// ✅ 2. TAMBAHKAN INI: Error Handler untuk Mencegah Crash Node.js
// Ini akan menangkap error jika koneksi terputus tiba-tiba (misal: DB restart saat init)
pool.on('error', (err, client) => {
    console.error('⚠️ [DATABASE] Koneksi terputus secara tidak terduga:', err.message);
    console.error('⚠️ [DATABASE] Pool akan mencoba menghubungkan kembali secara otomatis...');
    // PENTING: JANGAN gunakan process.exit() di sini. 
    // Biarkan library 'pg' menangani proses reconnect secara otomatis di latar belakang.
});

// 3. Fungsi testConnection yang dipanggil oleh app.js saat server menyala
const testConnection = async () => {
    try {
        const client = await pool.connect();
        console.log('✅ [DATABASE] Koneksi ke PostgreSQL berhasil!');
        console.log(`📦 [DATABASE] PostgreSQL Version: PostgreSQL ${client.serverVersion}`);
        
        // ✅ PENTING: Selalu release client kembali ke pool setelah selesai dipakai
        client.release(); 
    } catch (err) {
        console.error('❌ [DATABASE] Gagal terhubung ke PostgreSQL:', err.message);
        throw err; // Lempar error agar app.js tahu kalau koneksi gagal total
    }
};

// 4. Export agar bisa dipakai di app.js
module.exports = {
    pool,
    testConnection
};