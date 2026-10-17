const multer = require('multer');
const path = require('path');

// 1. Konfigurasi penyimpanan file
const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    // File akan disimpan di folder public/uploads
    cb(null, 'public/uploads/'); 
  },
  filename: function (req, file, cb) {
    // Buat nama file unik agar tidak tertimpa: timestamp + angka acak + ekstensi asli
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'dokumen-' + uniqueSuffix + path.extname(file.originalname));
  }
});

// 2. Filter Keamanan (Mencegah upload file berbahaya seperti .php, .sh, .exe)
const fileFilter = (req, file, cb) => {
  const allowedTypes = ['application/pdf', 'image/jpeg', 'image/png'];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true); // File aman, lanjutkan
  } else {
    cb(new Error('Tipe file tidak diizinkan. Hanya PDF, JPG, atau PNG.'), false); // Tolak file
  }
};

// 3. Inisialisasi Multer dengan batasan keamanan
const upload = multer({ 
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // Batas maksimal 5 MB (Mencegah DoS)
});

// 4. Ekspor agar bisa dipakai di app.js
module.exports = upload;