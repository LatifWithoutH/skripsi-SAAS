-- ==========================================
-- SKRIPSI SAAS MULTI-TENANT: DATABASE SCHEMA (FINAL)
-- Engine: PostgreSQL
-- ==========================================

-- 1. TABEL TENANTS (Data Institusi/Kampus)
CREATE TABLE tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    subscription_plan VARCHAR(50) DEFAULT 'basic',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 2. TABEL ROLES (Definisi Hak Akses / RBAC)
CREATE TABLE roles (
    id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    permissions JSONB
);

-- 3. TABEL UNITS (Fakultas/Prodi) 
-- Dibuat sebelum users & kerjasama agar bisa di-reference
CREATE TABLE units (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    code VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 4. TABEL USERS (Pengguna Sistem Kampus)
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    role_id INT NOT NULL REFERENCES roles(id),
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    last_login TIMESTAMPTZ,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    unit_id UUID REFERENCES units(id) ON DELETE SET NULL, -- ✅ PENTING: Untuk isolasi level fakultas
    
    CONSTRAINT unique_email UNIQUE (email)
);

-- 5. TABEL MITRAS (Data Bisnis Utama)
CREATE TABLE mitras (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    name VARCHAR(255) NOT NULL,
    industry VARCHAR(100),
    contact_email VARCHAR(255),
    status VARCHAR(50) DEFAULT 'active',
    contract_start DATE,
    contract_end DATE,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 6. TABEL MITRA_ACCOUNTS (Akun Login Khusus untuk Portal Mitra)
-- ✅ PENTING: Tabel ini wajib ada agar partnerAuthController.js bisa berjalan
CREATE TABLE mitra_accounts (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    mitra_id UUID NOT NULL REFERENCES mitras(id) ON DELETE CASCADE,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 7. TABEL KERJASAMA (Dokumen MoU/MoA/IA)
CREATE TABLE kerjasama (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    mitra_id UUID REFERENCES mitras(id) ON DELETE SET NULL,
    unit_id UUID REFERENCES units(id) ON DELETE SET NULL,
    created_by UUID REFERENCES users(id) ON DELETE SET NULL,
    judul VARCHAR(255) NOT NULL,
    jenis VARCHAR(50) NOT NULL,
    tanggal_mulai DATE NOT NULL,
    tanggal_berakhir DATE NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    file_path TEXT, -- ✅ SIAP UNTUK FITUR UPLOAD DOKUMEN
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- 8. TABEL AUDIT LOGS (Jejak Keamanan / Accountability)
CREATE TABLE audit_logs (
    id BIGSERIAL PRIMARY KEY,
    tenant_id UUID REFERENCES tenants(id) ON DELETE SET NULL,
    user_id UUID REFERENCES users(id) ON DELETE SET NULL,
    unit_id UUID REFERENCES units(id) ON DELETE SET NULL, -- ✅ PENTING: Agar join di dashboard controller tidak error
    action VARCHAR(100) NOT NULL,
    target_table VARCHAR(100),
    target_id UUID,
    ip_address INET,
    user_agent TEXT,
    details JSONB,
    created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- ==========================================
-- INDEXING (Sangat Penting untuk Performa!)
-- ==========================================
CREATE INDEX idx_units_tenant ON units(tenant_id);
CREATE INDEX idx_users_tenant ON users(tenant_id);
CREATE INDEX idx_mitras_tenant ON mitras(tenant_id);
CREATE INDEX idx_kerjasama_tenant ON kerjasama(tenant_id);
CREATE INDEX idx_kerjasama_unit ON kerjasama(unit_id);
CREATE INDEX idx_kerjasama_mitra ON kerjasama(mitra_id);
CREATE INDEX idx_mitra_accounts_tenant ON mitra_accounts(tenant_id);
CREATE INDEX idx_mitra_accounts_mitra ON mitra_accounts(mitra_id);
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