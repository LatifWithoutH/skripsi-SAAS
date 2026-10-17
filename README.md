# 📋 PROJECT CONTEXT - SI-MITRA-DUDIKA SaaS Multi-Tenant

**Terakhir Diperbarui:** 2026-01-28 
**Status:** Dalam Pengembangan (Fase Arsitektur & Perancangan)  
**Penyusun:** Abdul Latif Multi Utomo  
**Dosen Pembimbing:** Gunawan Ariyanto, S.T., M.Comp.Sc., Ph.D.

---

## 🎯 Ringkasan Eksekutif

### Judul Skripsi (ACC)
**"Evaluasi Keamanan dan Pembenahan Kode (Hardening) pada Aplikasi SI-MITRA-DUDIKA Versi SaaS Menggunakan Metode Gray-Box Penetration Testing Berbasis OWASP WSTG v4.2 dan OWASP Top 10:2025"**

### Tujuan Utama
Mentransformasi aplikasi SI-MITRA-DUDIKA dari arsitektur monolith (single-tenant) menjadi arsitektur SaaS multi-tenant hierarkis, kemudian mengevaluasi keamanannya melalui penetration testing dan melakukan hardening untuk menutup celah yang ditemukan.

### Fokus Skripsi
- **BUKAN** tentang UI/UX atau desain frontend
- **BUKAN** tentang kelayakan bisnis/komersial
- **ADALAH** tentang keamanan arsitektur, isolasi data, dan hardening sistem
- **ADALAH** tentang pembuktian empiris melalui penetration testing

---

## 🏗️ Evolusi Arsitektur

### Fase 1: Monolith (Sudah Selesai - UNIBA)
**Lokasi:** `/home/acer/Documents/wirchtinformatik/`

**Karakteristik:**
- Single-tenant (hanya untuk UNIBA)
- Database: Supabase (cloud)
- File storage: Google Drive via GAS
- Email: GAS Web App
- Role: Hardcoded (`humas`, `admin_fakultas`, `guest`)
- Isolasi: Berdasarkan `fakultas_id`

**Status:** ✅ Berhasil diimplementasi dan digunakan di UNIBA  
**Dokumentasi:** Terseal (tidak dibahas lagi kecuali diminta)

---

### Fase 2: SaaS Multi-Tenant (Sedang Dikembangkan)
**Lokasi:** `/home/acer/skripsi-saas/`

**Karakteristik:**
- Multi-tenant (bisa melayani banyak universitas)
- Database: PostgreSQL lokal (migrasi dari Supabase)
- File storage: Akan migrasi ke MinIO atau local storage
- Email: Nodemailer + Email Queue (migrasi dari GAS)
- Role: Hybrid RBAC (System Role + Custom Role per tenant)
- Isolasi: Berdasarkan `tenant_id` dengan hierarki parent-child

**Status:** 🚧 Dalam pengembangan (fondasi sudah terbangun)

---

## 🧠 Keputusan Arsitektural Utama

### 1. Model Multi-Tenancy: Shared Database, Shared Schema ✅
**Keputusan:** Semua tenant berbagi satu database PostgreSQL dengan kolom `tenant_id` untuk isolasi.

**Alternatif yang Dipertimbangkan:**
- ❌ Separate Database per tenant → Overkill, mahal, sulit maintenance
- ❌ Separate Schema per tenant → Rumit, perlu switch schema
- ✅ Shared Database + `tenant_id` → Hemat, scalable, mudah di-maintain

**Justifikasi:**
- Cocok untuk skripsi S1 (tidak over-engineering)
- Mirip dengan cara kerja Gmail, Slack, Canva
- Memudahkan demonstrasi isolasi data di Bab 4 (pentesting)

---

### 2. Hierarki Tenant: Parent-Child Relationship ✅
**Keputusan:** Tenant memiliki struktur hierarki menggunakan `parent_id`.

**Struktur:**
Universitas (Root Tenant, parent_id = NULL)
├── Fakultas (Child Tenant, parent_id = UUID Universitas)
│ ├── Prodi (Grandchild Tenant, parent_id = UUID Fakultas)
│ └── Prodi
└── Fakultas
└── Prodi


**Implementasi:**
- Recursive CTE untuk menelusuri hierarki
- Middleware `ensureTenant` + utility `getAccessibleTenantIds`
- Superadmin universitas bisa lihat semua data di bawahnya
- Dekan fakultas hanya bisa lihat data fakultasnya + prodi di bawahnya

**Justifikasi:**
- Sesuai dengan struktur organisasi kampus nyata
- Memudahkan agregasi data (rekursif ke bawah)
- Built-in isolation berdasarkan hierarki

---

### 3. Fleksibilitas Tenant: Universitas ATAU Fakultas Bisa Jadi Root ✅
**Keputusan:** Sistem mendukung dua model bisnis:

**Model A: Top-Down (Universitas sebagai Root)**
- Rektorat/LPPM berlangganan SaaS
- Fakultas/Prodi otomatis menjadi child tenant
- Rektorat bisa lihat semua data

**Model B: Bottom-Up (Fakultas sebagai Root)**
- Fakultas berlangganan mandiri (punya anggaran sendiri)
- Fakultas menjadi root tenant (parent_id = NULL)
- Rektorat TIDAK bisa lihat data fakultas ini (isolasi penuh)

**Justifikasi:**
- Realistis: banyak fakultas punya otonomi anggaran
- Tidak perlu ubah kode, cukup ubah `parent_id` saat registrasi
- Menunjukkan kematangan arsitektur

---

### 4. RBAC: Hybrid System Role + Custom Role ✅
**Keputusan:** Kombinasi role bawaan (tidak bisa diubah) dan role custom (bisa dibuat tenant).

**System Roles (Bawaan Platform):**
- `platform_superadmin` → Pemilik SaaS (kamu)
- `tenant_superadmin` → Admin universitas (Humas/LPPM)
- `tenant_admin` → Admin fakultas (Dekan/Kaprodi)
- `tenant_guest` → Guest/auditor

**Custom Roles (Dibuat Tenant):**
- Tenant bisa buat role sendiri (misal: "Reviewer MoU", "Liaison Officer")
- Permission granular (misal: `create_mitra`, `upload_mou`, `approve_mou`)
- Tenant admin bisa assign permission ke custom role

**Justifikasi:**
- Fleksibel untuk berbagai struktur organisasi kampus
- Tidak perlu 3000 permissions seperti GCP (overkill untuk skripsi)
- 30-50 permissions sudah cukup untuk SI-MITRA
- Mirip dengan Slack, Notion, Salesforce

---

### 5. Alur Dokumen: Mitra yang Upload (Bukan Kampus) ✅
**Keputusan:** Pergeseran tanggung jawab upload dokumen dari kampus ke mitra.

**Alur Lama (Monolith):**
1. Humas kampus input data mitra
2. Humas kampus upload dokumen MoU/MoA (beban kerja besar)
3. Dokumen tersimpan di Google Drive

**Alur Baru (SaaS):**
1. Kampus buat "rekam jejak" mitra (nama, kontak, email)
2. Sistem kirim email undangan ke mitra
3. Mitra login ke portal khusus
4. Mitra upload dokumen sendiri (MoU, MoA, IA, PKS)
5. Kampus review & approve

**Justifikasi:**
- Mengurangi beban kerja administratif kampus ~40%
- Menjamin keaslian dokumen (dari sumber langsung)
- Lebih profesional (mirip portal vendor di perusahaan besar)
- Nilai plus untuk Bab Pembahasan (Business Process Improvement)

---

### 6. Routing Dokumen: Delegated Approval Workflow ✅
**Keputusan:** Dokumen bisa langsung ditargetkan ke fakultas/prodi, tidak harus lewat rektorat.

**Skenario A: Kerjasama Tingkat Universitas**
- PT Telkom (pusat) → Rektorat/LPPM
- Review oleh Superadmin Tenant

**Skenario B: Kerjasama Tingkat Fakultas**
- Startup lokal → Dekan FT / Kaprodi TI
- Review oleh Admin Fakultas/Prodi
- Rektorat tidak perlu tahu detail (bypass birokrasi)

**Implementasi:**
- Kolom `fakultas_id` di tabel `mitras` (boleh null jika level universitas)
- Middleware otomatis route dokumen ke penanggung jawab yang tepat
- Tetap menjaga isolasi data (fakultas lain tidak bisa akses)

**Justifikasi:**
- Mendesentralisasi beban kerja
- Mempercepat proses kerjasama rutin
- Realistis dengan birokrasi kampus nyata

---

## 🔐 Strategi Keamanan & Penetration Testing

### Lapisan Keamanan yang Sudah Diimplementasi

1. **Isolasi Database**
   - Setiap query WAJIB punya `WHERE tenant_id = ANY($1)`
   - Recursive CTE untuk hierarki
   - Parameterized query (mencegah SQL Injection)

2. **Middleware Penjaga Pintu**
   - `ensureTenant` → Blokir user tanpa tenant_id
   - `ensurePlatformAdmin` → Blokir user yang bukan platform superadmin
   - Validasi session di setiap request

3. **Password Security**
   - Bcrypt hashing (salt rounds = 10)
   - Rate limiting untuk login (5 percobaan / 15 menit)
   - Forgot password dengan token (expire 30 menit)

4. **Audit Trail**
   - Log semua aksi penting (CREATE, UPDATE, DELETE, LOGIN, UPLOAD)
   - Simpan old_data dan new_data untuk tracking perubahan
   - IP address dan user agent dicatat

### Skenario Penetration Testing (Bab 4)

**Akan Diuji:**
1. **IDOR (Insecure Direct Object Reference)**
   - Login sebagai tenant A, coba akses data tenant B via manipulasi ID
   - Expected: 403 Forbidden

2. **Cross-Tenant Data Leakage**
   - Login sebagai Fakultas A, coba lihat data Fakultas B
   - Expected: Data tidak muncul (filtered by tenant_id)

3. **Privilege Escalation**
   - User dengan role "guest" coba akses fitur "admin"
   - Expected: 403 Forbidden

4. **SQL Injection**
   - Inject SQL di form login/search
   - Expected: Ditolak oleh parameterized query

5. **Session Hijacking**
   - Manipulasi cookie untuk jadi tenant lain
   - Expected: Middleware menolak

6. **File Upload Vulnerability**
   - Upload file .exe atau .php (bukan PDF)
   - Expected: Ditolak oleh file filter

---

## 📊 Status Saat Ini

### ✅ Yang Sudah Selesai

**Arsitektur & Database:**
- [x] Schema database PostgreSQL (tenants, users, mitras)
- [x] Recursive CTE untuk hierarki tenant
- [x] Middleware `ensureTenant` untuk isolasi
- [x] Utility `getAccessibleTenantIds` untuk filtering

**Fitur Dasar:**
- [x] Landing page (`/`)
- [x] Registrasi tenant baru (`/register`)
- [x] Login dengan bcrypt (`/login`)
- [x] Dashboard terisolasi per tenant (`/dashboard`)
- [x] Platform dashboard untuk superadmin (`/platform/dashboard`)

**Testing:**
- [x] Pembuktian isolasi data (3 universitas berbeda, data tidak bocor)
- [x] Atomic transaction untuk registrasi (BEGIN/COMMIT/ROLLBACK)

### 🚧 Yang Sedang Dikembangkan

- [ ] CRUD Mitra (Create, Read, Update, Delete)
- [ ] Upload dokumen (migrasi dari GAS ke MinIO/local)
- [ ] Email queue dengan Nodemailer
- [ ] Portal mitra untuk upload dokumen sendiri
- [ ] Custom RBAC UI (tenant bisa buat role sendiri)

### ⏳ Yang Belum Dimulai

- [ ] Deploy ke VPS (Ubuntu Server)
- [ ] Server hardening (UFW, Nginx, Fail2Ban, SSL)
- [ ] Penetration testing dengan OWASP ZAP
- [ ] Dokumentasi SKPL (Spesifikasi Kebutuhan Perangkat Lunak)
- [ ] Penulisan Bab 1-5

---

## 🗺️ Roadmap 3 Bulan Menuju Sidang

### Bulan 1: Fondasi & SKPL
**Fokus:** Selesaikan fitur inti + dokumentasi SKPL

**Target:**
- [ ] CRUD Mitra lengkap
- [ ] Upload dokumen (MinIO/local)
- [ ] Email queue (Nodemailer)
- [ ] Portal mitra
- [ ] SKPL (fokus pada Security Requirements)

**Deliverable:**
- Aplikasi SaaS fungsional (bisa dipakai demo)
- Dokumen SKPL (bab 3.1)

---

### Bulan 2: Deploy & Hardening
**Fokus:** Deploy ke VPS + server hardening

**Target:**
- [ ] Beli VPS (Ubuntu Server, 2GB RAM)
- [ ] Install Node.js + PostgreSQL + Nginx
- [ ] Setup SSL (Let's Encrypt)
- [ ] Konfigurasi UFW (firewall)
- [ ] Setup Fail2Ban (anti brute-force)
- [ ] Hardening PostgreSQL (pg_hba.conf)

**Deliverable:**
- Aplikasi live di VPS
- Dokumentasi hardening (bab 3.2)

---

### Bulan 3: Penetration Testing & Penulisan
**Fokus:** Serang sistem sendiri + tulis skripsi

**Target:**
- [ ] Gray-box pentesting (OWASP WSTG v4.2)
- [ ] Vulnerability scanning (OWASP ZAP)
- [ ] Temukan celah → perbaiki → re-test
- [ ] Tulis Bab 4 (Hasil & Pembahasan)
- [ ] Tulis Bab 1, 2, 5
- [ ] Revisi final

**Deliverable:**
- Laporan pentesting (bab 4)
- Skripsi lengkap (draft final)

---

## 📝 Catatan Penting untuk AI Lain

### Jika Kamu Adalah AI yang Membantu Proyek Ini:

1. **Pahami Konteks Dulu**
   - Baca file ini sampai selesai sebelum memberi saran
   - Jangan ulangi penjelasan yang sudah ada di sini
   - Fokus pada hal yang belum dibahas

2. **Jangan Bahas Hal yang Sudah "Seal"**
   - Kode monolith lama (`wirchtinformatik`) hanya dibahas jika diminta eksplisit
   - Jangan terus-menerus mengingatkan tentang kode lama
   - Fokus pada versi SaaS baru

3. **Fokus pada Keamanan, Bukan UI**
   - Jangan sarankan perubahan desain frontend
   - Jangan bahas warna tombol, animasi, dll
   - Fokus pada arsitektur, isolasi data, hardening

4. **Jangan Paksa Narasi Bisnis**
   - Jangan tanya "apakah kampus lain mau beli?"
   - Jangan bahas kelayakan komersial
   - Fokus pada aspek teknis dan keamanan

5. **Gunakan Bahasa Indonesia**
   - User lebih nyaman dengan Bahasa Indonesia
   - Istilah teknis bisa pakai English, tapi penjelasan pakai Indonesia
   - Jangan campur-campur bahasa tanpa perlu

6. **Sabar dengan Kebingungan User**
   - User kadang merasa "bingung" atau "terjebak"
   - Itu wajar karena konsepnya kompleks
   - Jangan langsung kasih kode, tanya dulu apa yang tidak paham
   - Gunakan analogi sederhana (apartemen, mall, dll)

7. **Jangan Generate Kode Kecuali Diminta**
   - User lebih suka ngobrol konsep dulu
   - Jangan langsung kasih kode panjang
   - Tanya: "Mau saya buatkan kodenya?" sebelum generate

---

## 🔒 Sealed Memory (Tidak Dibahas Kecuali Diminta)

Berikut adalah hal-hal yang sudah "dikunci" dan tidak akan dibahas lagi kecuali user meminta secara eksplisit:

1. **Kode Monolith Lama** (`/home/acer/Documents/wirchtinformatik/`)
   - Semua file di folder ini
   - Implementasi Supabase, GAS, dll
   - Hanya dibahas jika user minta eksplisit

2. **Detail Implementasi yang Sudah Selesai**
   - Recursive CTE (sudah dijelaskan berkali-kali)
   - Middleware `ensureTenant` (sudah final)
   - Struktur database dasar (sudah fix)

3. **Narasi Bisnis yang Sudah Ditolak**
   - "Kenapa kampus mau beli SaaS ini?"
   - "Apakah ini laku dijual?"
   - Sudah disepakati: fokus teknis, bukan bisnis

---

## 📚 Referensi & Standar

### OWASP (Open Web Application Security Project)
- **OWASP Top 10:2025** → Daftar 10 risiko keamanan web teratas
- **OWASP WSTG v4.2** → Panduan langkah demi langkah untuk penetration testing

### Istilah Teknis
- **Multi-Tenant:** Satu aplikasi melayani banyak "penyewa" (tenant)
- **Tenant Isolation:** Mekanisme memastikan data tenant A tidak bocor ke tenant B
- **Hierarchical RBAC:** Role-Based Access Control dengan struktur hierarki
- **Gray-Box Pentesting:** Penetration testing dengan pengetahuan sebagian tentang sistem
- **Hardening:** Proses memperkuat keamanan sistem (konfigurasi server, patching, dll)

---

## 🤝 Cara Menggunakan File Ini

### Untuk Dosen Pembimbing:
- Gunakan sebagai ringkasan progres
- Lihat bagian "Status Saat Ini" untuk update
- Lihat "Roadmap" untuk timeline

### Untuk AI Lain:
- Baca file ini DULU sebelum membantu
- Jangan ulangi penjelasan yang sudah ada
- Fokus pada bagian yang belum selesai

### Untuk Dirimu Sendiri (3 Bulan Lagi):
- Baca saat mulai lupa konteks
- Lihat "Keputusan Arsitektural" untuk mengingat mengapa memilih pendekatan tertentu
- Lihat "Sealed Memory" untuk tahu apa yang tidak perlu dibahas lagi

---

## 📞 Kontak & Kolaborasi

**Dibuat oleh:** [AI Assistant]  
**Untuk:** [Nama Kamu]  
**Tanggal Mulai:** 2026-01-XX  
**Versi Dokumen:** 1.0

---

**Catatan Akhir:**  
File ini adalah "living document". Akan terus diupdate seiring perkembangan proyek. Jika ada keputusan baru yang diambil, tambahkan ke bagian yang relevan. Jika ada hal yang sudah tidak relevan, beri tanda ~~dicoret~~ atau pindahkan ke arsip.

**Semangat mengerjakan skripsi! Kamu sudah di jalur yang tepat.** 🚀
