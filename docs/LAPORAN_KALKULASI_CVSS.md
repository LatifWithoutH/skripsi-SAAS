# 📊 Laporan Kalkulasi Risiko CVSS v3.1

**Skripsi S1 - Gray-Box Penetration Testing**  
**Tanggal**: 12 October 2026, 14:58  

## 1. Ringkasan Eksekutif Risiko

| Metrik Risiko | Versi Lama (Baseline) | Versi Baru (Hardened) | Delta |
|---------------|-----------------------|-----------------------|-------|
| **Total Skor Risiko** | **27.9** | **12.6** | **↓ 15.3** |
| **Rata-rata CVSS** | **6.97** | **6.30** | - |
| **Skor Maksimum** | **8.8** | **6.5** | - |

## 2. Detail Kalkulasi Per Kontrol

| Kontrol Keamanan | OWASP | Base Score | Skor Lama | Skor Baru | Status |
|------------------|-------|------------|-----------|-----------|--------|
| Password Hashing (Bcrypt) | A07:2025 - Auth Failures | 9.1 | 0.0 | 0.0 | ➖ MAINTAINED (Sudah ada) |
| State Validation (Zero Trust Login) | A01:2025 - Broken Access Control | 8.8 | 8.8 | 0.0 | ✅ HARDENED (Ditambahkan) |
| Multi-Tenant Isolation (Row-Level Security) | A01:2025 - Broken Access Control | 8.8 | 0.0 | 0.0 | ➖ MAINTAINED (Sudah ada) |
| Parameterized Queries (Anti-SQLi) | A03:2025 - Injection | 9.8 | 0.0 | 0.0 | ➖ MAINTAINED (Sudah ada) |
| Secure Session Cookies | A02:2025 - Cryptographic Failures | 6.5 | 0.0 | 0.0 | ➖ MAINTAINED (Sudah ada) |
| API Rate Limiting | A05:2025 - Security Misconfiguration | 7.5 | 0.0 | 0.0 | ➖ MAINTAINED (Sudah ada) |
| Security Headers (Helmet) | A05:2025 - Security Misconfiguration | 6.1 | 6.1 | 6.1 | ❌ MISSING (Belum diimplementasi) |
| Comprehensive Audit Logging | A08:2025 - Software/Data Integrity Failures | 4.9 | 0.0 | 0.0 | ➖ MAINTAINED (Sudah ada) |
| Secure Email Delivery (Managed API) | A05:2025 - Security Misconfiguration | 6.5 | 6.5 | 0.0 | ✅ HARDENED (Ditambahkan) |
| Strict CORS Configuration | A10:2025 - SSRF / Misconfiguration | 6.5 | 6.5 | 6.5 | ❌ MISSING (Belum diimplementasi) |

## 3. Analisis Naratif

Berdasarkan kalkulasi CVSS v3.1, proses hardening berhasil menurunkan total skor risiko dari **27.9** menjadi **12.6**. Penurunan ini didorong oleh mitigasi celah pada *State Validation* dan *Secure Email Delivery*.

Namun, skor risiko residual sebesar **12.6** masih ada dikarenakan belum diimplementasikannya *Security Headers (Helmet)* dan *Strict CORS Configuration*, yang direkomendasikan untuk fase hardening selanjutnya.
