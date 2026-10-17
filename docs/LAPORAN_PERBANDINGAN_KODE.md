# 📊 Laporan Perbandingan Keamanan Kode Sumber

**Skripsi S1 - Gray-Box Penetration Testing**  
**Tanggal Scan**: 12 October 2026, 14:49  
**Metode**: Static Code Analysis (Pattern Matching)  

## 1. Objek Perbandingan

| Versi | Direktori | Deskripsi |
|-------|-----------|----------|
| **Lama** | `skripsi-saas (copy)` | Sebelum hardening |
| **Baru** | `skripsi-saas` | Sesudah hardening |

## 2. Statistik Global

| Metrik | Versi Lama | Versi Baru | Delta |
|--------|------------|------------|-------|
| Files Scanned | 19 | 42 | - |
| Lines Scanned | 1208 | 3010 | - |
| **Total Findings** | **0** | **0** | **=** |

## 3. Perbandingan per Kategori OWASP Top 10:2025

| Kategori OWASP | Sebelum | Sesudah | Perubahan |
|----------------|---------|---------|----------|

## 4. Detail Temuan di Versi Baru (Jika Ada)

**✅ Tidak ada temuan kerentanan di versi baru.**  
Semua pattern kerentanan yang terdeteksi di versi lama telah berhasil dimitigasi melalui code-level hardening.


## 5. Kesimpulan

Berdasarkan hasil static code analysis, proses hardening berhasil mengurangi **0** potensi kerentanan menjadi **0** (penurunan **0.0%**).

