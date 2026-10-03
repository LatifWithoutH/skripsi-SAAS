-- ==========================================
-- SKRIPSI SAAS MULTI-TENANT: DATABASE SCHEMA
-- Engine: PostgreSQL
-- ==========================================

-- 1. TABEL TENANTS (Data Institusi/Kampus)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(), -- UUID untuk keamanan (mencegah ID Enumeration)
    name VARCHAR(255) NOT NULL,                    -- Nama Kampus (misal: Universitas Nusantara)
    slug VARCHAR(100) UNIQUE NOT NULL,             -- URL friendly (misal: uniba) -> uniba.saas.com
    status VARCHAR(50) DEFAULT 'active',           -- active, suspended, trial
    subscription_plan VARCHAR(50) DEFAULT 'basic', -- basic, premium, enterprise
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. TABEL ROLES (Definisi Hak Akses / RBAC)
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,              -- tenant_owner, it_admin, faculty_operator, auditor
    description TEXT,
    permissions JSONB                              -- Fleksibel untuk menyimpan array izin (misal: ["read:mitra", "write:mitra"])
);

-- 3. TABEL USERS (Pengguna Sistem)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, -- 🔒 KUNCI MULTI-TENANT: User terikat ke Tenant
    role_id INT NOT NULL REFERENCES roles(id),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,           -- Disimpan dalam bentuk hash (bcrypt), JANGAN plain text!
    status VARCHAR(50) DEFAULT 'active',           -- active, pending_invite, suspended
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    
    -- Pastikan email unik di seluruh sistem (atau bisa diubah jadi unik per tenant jika perlu)
    CONSTRAINT unique_email UNIQUE (email) 
);

-- Tambahkan setelah tabel users

-- 4. TABEL UNITS (Fakultas/Prodi)
CREATE TABLE units (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_units_tenant ON units(tenant_id);

-- 5. TABEL KERJASAMA
CREATE TABLE kerjasama (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    mitra_id UUID REFERENCES mitras(id) ON DELETE SET NULL,
    unit_id UUID REFERENCES units(id) ON DELETE SET NULL,
    created_by UUID REFERENCES users(id),
    judul VARCHAR(255) NOT NULL,
    jenis VARCHAR(50) NOT NULL, -- MoU, MoA, IA
    tanggal_mulai DATE NOT NULL,
    tanggal_berakhir DATE NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    file_path TEXT,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_kerjasama_tenant ON kerjasama(tenant_id);
CREATE INDEX idx_kerjasama_unit ON kerjasama(unit_id);
CREATE INDEX idx_kerjasama_mitra ON kerjasama(mitra_id);

-- 4. TABEL MITRAS (Data Bisnis Utama)
CREATE TABLE mitras (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE, -- 🔒 KUNCI MULTI-TENANT: Data Mitra terisolasi per Tenant
    created_by UUID REFERENCES users(id),          -- Siapa yang menginput data ini (Audit trail)
    name VARCHAR(255) NOT NULL,
    industry VARCHAR(100),
    contact_email VARCHAR(255),
    status VARCHAR(50) DEFAULT 'active',
    contract_start DATE,
    contract_end DATE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 5. TABEL AUDIT LOGS (Jejak Keamanan / Accountability)
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,                      -- Bigserial karena log akan sangat banyak
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL, -- Tetap simpan log meski tenant dihapus
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(100) NOT NULL,                  -- misal: 'LOGIN_FAILED', 'CREATE_MITRA', 'DELETE_USER'
    target_table VARCHAR(100),                     -- Tabel apa yang dipengaruhi
    target_id UUID,                                -- ID baris yang dipengaruhi
    ip_address INET,                               -- Tipe data khusus IP address di Postgres
    user_agent TEXT,
    details JSONB,                                 -- Data tambahan (misal: payload yang diubah)
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- INDEXING (Sangat Penting untuk Performa!)
-- ==========================================
-- Index mempercepat query WHERE tenant_id = 'xxx'
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_mitras_tenant ON mitras(tenant_id);
CREATE INDEX idx_audit_logs_tenant ON audit_logs(tenant_id);
CREATE INDEX idx_audit_logs_created ON audit_logs(created_at DESC);

-- ==========================================
-- DATA AWAL (SEEDING)
-- ==========================================
-- Insert Roles dasar
INSERT INTO roles (name, description, permissions) VALUES
('tenant_owner', 'Pemilik utama tenant, akses penuh', '["*"]'::jsonb),
('it_admin', 'Admin IT, mengelola konfigurasi teknis dan user', '["read:*", "write:users", "write:settings"]'::jsonb),
('faculty_operator', 'Operator fakultas, hanya mengelola data di fakultasnya', '["read:mitra", "write:mitra"]'::jsonb),
('auditor', 'Hanya bisa melihat data dan log audit', '["read:*"]'::jsonb);

-- Insert Tenant Dummy (Kampus A)
INSERT INTO tenants (id, name, slug, status) VALUES
('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 'Universitas Nusantara', 'uniba', 'active');

-- Insert User Dummy (Owner untuk Kampus A)
-- Password: 'password123' (Ini adalah hash bcrypt, JANGAN pakai plain text di produksi!)
INSERT INTO users (tenant_id, role_id, name, email, password_hash, status) VALUES
('a1b2c3d4-e5f6-7890-abcd-ef1234567890', 1, 'Pengelola Utama', 'owner@uniba.ac.id', '$2a$10$XQ5rbGZ9J0kQ5vQ5vQ5vOeXQ5rbGZ9J0kQ5vQ5vQ5vOe', 'active');

-- ==========================================
-- GRANT PERMISSIONS (Wajib untuk skripsi_user)
-- ==========================================
GRANT USAGE ON SCHEMA public TO skripsi_user;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO skripsi_user;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO skripsi_user;

-- Agar tabel/sequence baru di masa depan juga otomatis ter-grant
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO skripsi_user;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO skripsi_user;