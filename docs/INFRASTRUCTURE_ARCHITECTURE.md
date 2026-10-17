# 🏗️ Arsitektur Infrastruktur & Domain Routing: SI-MITRA-DUDIKA

Dokumen ini menjelaskan implementasi infrastruktur jaringan, routing domain, dan strategi keamanan yang digunakan dalam pengembangan sistem **SI-MITRA-DUDIKA**. Sistem ini menerapkan pola arsitektur **"Single Codebase, Multiple Faces"** untuk memisahkan antarmuka Administrasi Kampus dan Portal Mitra Industri.

---

## 📑 Daftar Isi
1. [Konsep Arsitektur](#1-konsep-arsitektur)
2. [Implementasi Lingkungan Lokal (Development)](#2-implementasi-lingkungan-lokal-development)
   - 2.1. Local DNS Spoofing (`/etc/hosts`)
   - 2.2. Reverse Proxy & Enkripsi (Nginx + mkcert)
   - 2.3. Host Header Detection (Node.js)
3. [Strategi & Alasan Penggunaan untuk Demo Skripsi](#3-strategi-&-alasan-penggunaan-untuk-demo-skripsi)
4. [Peta Jalan Produksi (Rencana VPS)](#4-peta-jalan-produksi-rencana-vps)

---

## 1. Konsep Arsitektur

Alih-alih membangun dua aplikasi terpisah (satu untuk Admin Kampus, satu untuk Portal Mitra), SI-MITRA-DUDIKA menggunakan **satu instance aplikasi Node.js** yang berjalan di balik **Nginx Reverse Proxy**. 

Nginx bertindak sebagai "pintu depan" yang mendengarkan permintaan berdasarkan nama domain (`saas.local` vs `mitra.saas.local`), lalu meneruskannya ke aplikasi Node.js. Aplikasi Node.js kemudian membaca *Host Header* untuk menentukan antarmuka (UI) dan logika keamanan mana yang harus disajikan.

**Keuntungan Pola Ini:**
- **Efisiensi Pemeliharaan:** Hanya satu *codebase* yang perlu di-*update*.
- **Konsistensi Data:** Berbagi skema database dan logika bisnis yang sama.
- **Isolasi Keamanan:** Pemisahan antarmuka dan *scoping* data yang ketat di level aplikasi.

---

## 2. Implementasi Lingkungan Lokal (Development)

Untuk mensimulasikan lingkungan produksi di mesin lokal (localhost), kami mengimplementasikan 3 lapisan konfigurasi:

### 2.1. Local DNS Spoofing (`/etc/hosts`)
Karena domain `.local` tidak terdaftar di DNS publik, kami memetakan domain secara manual di sistem operasi (Linux/Ubuntu) agar mengarah ke *loopback address* (127.0.0.1).

```text
# /etc/hosts
127.0.0.1    saas.local
127.0.0.1    mitra.saas.local
```

### 2.2. Reverse Proxy & Enkripsi (Nginx + mkcert)
Kami menggunakan **Nginx** sebagai Reverse Proxy dan **mkcert** untuk membuat sertifikat SSL lokal yang dipercaya oleh browser (menghilangkan peringatan "Not Secure").

**Konfigurasi Nginx (`/etc/nginx/sites-available/saas-skripsi`):**
```nginx
# Redirect HTTP ke HTTPS
server {
    listen 80;
    server_name saas.local mitra.saas.local;
    return 301 https://$host$request_uri;
}

# Server Kampus (Admin)
server {
    listen 443 ssl;
    server_name saas.local;
    ssl_certificate /path/to/saas.local+1.pem;
    ssl_certificate_key /path/to/saas.local+1-key.pem;

    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host; # KUNCI: Meneruskan nama domain ke Node.js
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}

# Server Portal Mitra
server {
    listen 443 ssl;
    server_name mitra.saas.local;
    # ... (konfigurasi SSL sama) ...
    location / {
        proxy_pass http://127.0.0.1:3000;
        proxy_set_header Host $host; 
        # ...
    }
}
```

### 2.3. Host Header Detection (Node.js/Express)
Di sisi aplikasi, middleware Express membaca `req.headers.host` yang diteruskan oleh Nginx untuk melakukan *Bifurcated UI Routing*.

```javascript
// Middleware Pendeteksi Domain
app.use((req, res, next) => {
    if (req.headers.host === 'mitra.saas.local') {
        req.isMitraPortal = true;
    } else {
        req.isMitraPortal = false;
    }
    next();
});

// Routing Dinamis
app.get('/', (req, res) => {
    if (req.isMitraPortal) {
        return res.redirect('/portal-mitra/login');
    }
    res.render('public/index'); // Landing page kampus
});
```

---

## 3. Strategi & Alasan Penggunaan untuk Demo Skripsi

Pemilihan arsitektur subdomain lokal ini bukan sekadar preferensi teknis, melainkan strategi yang disengaja untuk mendukung fokus skripsi pada **Keamanan Sistem Informasi**:

1. **Simulasi Standar Enterprise (Vendor Portal):** 
   Sistem SaaS kelas enterprise (seperti SAP Ariba atau Slack) memisahkan portal eksternal dari dashboard internal menggunakan subdomain. Implementasi ini membuktikan bahwa SI-MITRA-DUDIKA dirancang dengan standar industri, bukan sekadar CRUD biasa.
2. **Psikologi Keamanan & Kepercayaan (Trust):** 
   Penggunaan `mkcert` untuk mengaktifkan HTTPS lokal memastikan browser menampilkan ikon "Gembok Aman" (Secure). Dalam konteks demo skripsi keamanan, ini menghilangkan distraksi peringatan browser dan menunjukkan komitmen terhadap enkripsi *in-transit*.
3. **Demonstrasi Zero-Trust Data Scoping:** 
   Dengan memisahkan URL, kami dapat mendemonstrasikan bahwa meskipun berjalan di *codebase* yang sama, akun `mitra_pic` yang login via `mitra.saas.local` secara fisik tidak dapat mengakses rute internal kampus (seperti `/users` atau `/dashboard`) karena validasi *Host Header* dan *Session Scoping* di backend.
4. **Efisiensi Resource:** 
   Membuktikan bahwa isolasi psikologis dan keamanan dapat dicapai tanpa perlu menyewa dua server atau VPS yang berbeda, sangat relevan untuk studi kelayakan sistem bagi institusi pendidikan dengan anggaran terbatas.

---

## 4. Peta Jalan Produksi (Rencana VPS)

Dokumen ini mencakup rencana migrasi dari lingkungan lokal ke server produksi (VPS) setelah disetujui oleh Dosen Pembimbing. Arsitektur inti akan tetap sama, namun komponen lokal akan diganti dengan standar produksi:

| Komponen | Lingkungan Lokal (Saat Ini) | Lingkungan Produksi (Rencana VPS) |
| :--- | :--- | :--- |
| **DNS** | `/etc/hosts` (Manual) | **DNS A-Records** (Cloudflare/Namecheap) |
| **Domain** | `saas.local`, `mitra.saas.local` | `simitra.id`, `partner.simitra.id` |
| **Sertifikat SSL** | `mkcert` (Local CA) | **Let's Encrypt** (via Certbot) |
| **Containerization** | Node.js Native | **Docker & Docker Compose** |
| **Firewall** | Default Ubuntu | **UFW** (Hanya buka port 80, 443, 22) |
| **Process Manager** | `node app.js` / `nodemon` | **PM2** (Auto-restart & Clustering) |

**Langkah Eksekusi Produksi:**
1. Membeli domain dan mengatur A-Records ke IP Publik VPS.
2. Mengonfigurasi UFW dan menginstal Docker.
3. Menjalankan `docker-compose up -d` yang mencakup layanan Nginx, Node.js, dan PostgreSQL.
4. Menjalankan Certbot untuk menerbitkan sertifikat SSL otomatis untuk kedua subdomain.

---
*Dokumen ini disusun sebagai bagian dari dokumentasi teknis Skripsi S1 Sistem Informasi.*
