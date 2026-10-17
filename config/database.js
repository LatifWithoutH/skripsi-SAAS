const { Pool } = require('pg');
require('dotenv').config();

// 1. Inisialisasi Connection Pool
const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_NAME,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
    max: 20,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 2000,
});

// 2. Tes Koneksi Saat Server Menyala
pool.connect((err, client, release) => {
    if (err) {
        console.error('❌ [DATABASE] Gagal terhubung ke PostgreSQL:', err.message);
    } else {
        console.log('✅ [DATABASE] Koneksi ke PostgreSQL berhasil!');
        console.log(`📦 [DATABASE] PostgreSQL Version: PostgreSQL ${client.serverVersion}`);
        release(); // Kembalikan koneksi ke pool agar tidak bocor
    }
});

// 2. Buat fungsi testConnection yang mengembalikan Promise
const testConnection = async () => {
    try {
        const client = await pool.connect();
        console.log('✅ [DATABASE] Koneksi ke PostgreSQL berhasil!');
        console.log(`📦 [DATABASE] PostgreSQL Version: PostgreSQL ${client.serverVersion}`);
        
    } catch (err) {
        console.error('❌ [DATABASE] Gagal terhubung ke PostgreSQL:', err.message);
        throw err; // Lempar error agar app.js tahu kalau koneksi gagal
    }
};

// 3. Export pool dan testConnection
module.exports = {
    pool,
    testConnection
};