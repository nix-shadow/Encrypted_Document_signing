-- Initialize database for Encrypted Document Signing Platform

-- Create ENUM types for user roles and approval status
CREATE TYPE user_role AS ENUM ('admin', 'user');
CREATE TYPE approval_status AS ENUM ('pending', 'approved', 'rejected');

-- Users table: stores user credentials and RSA keys
CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    public_key_pem TEXT NOT NULL,
    private_key_encrypted BYTEA NOT NULL,
    role user_role DEFAULT 'user' NOT NULL,
    is_approved BOOLEAN DEFAULT false NOT NULL,
    approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Documents table: stores encrypted document content and signatures
CREATE TABLE IF NOT EXISTS documents (
    id SERIAL PRIMARY KEY,
    owner_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    filename VARCHAR(255) NOT NULL,
    content_type VARCHAR(128) NOT NULL,
    encrypted_content BYTEA NOT NULL,
    nonce BYTEA NOT NULL,
    tag BYTEA NOT NULL,
    doc_hash BYTEA NOT NULL,
    signature BYTEA NOT NULL,
    aes_key_encrypted_owner BYTEA NOT NULL,
    pdf_password_encrypted BYTEA,
    has_pdf_password BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Document shares table: manages document sharing with re-encrypted keys
CREATE TABLE IF NOT EXISTS document_shares (
    id SERIAL PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    recipient_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_aes_key BYTEA NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE(document_id, recipient_id)
);

-- Audit log table: tracks security-relevant events
CREATE TABLE IF NOT EXISTS audit_log (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
    action VARCHAR(128) NOT NULL,
    entity_type VARCHAR(128) NOT NULL,
    entity_id INTEGER,
    detail TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_documents_owner ON documents(owner_id);
CREATE INDEX IF NOT EXISTS idx_shares_document ON document_shares(document_id);
CREATE INDEX IF NOT EXISTS idx_shares_recipient ON document_shares(recipient_id);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at DESC);

-- Trusted devices table: track authorized devices per user for security
CREATE TABLE IF NOT EXISTS trusted_devices (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    user_agent TEXT,
    ip_address VARCHAR(45),
    is_trusted BOOLEAN DEFAULT false,
    is_active BOOLEAN DEFAULT true,
    last_used_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    UNIQUE(user_id, device_fingerprint)
);

-- MFA secrets table: store TOTP secrets for two-factor authentication
CREATE TABLE IF NOT EXISTS mfa_secrets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER UNIQUE NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    secret VARCHAR(32) NOT NULL,
    is_enabled BOOLEAN DEFAULT false,
    backup_codes TEXT[],
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Pending device authorizations: temporary tokens for new device approval
CREATE TABLE IF NOT EXISTS pending_device_auth (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    user_agent TEXT,
    ip_address VARCHAR(45),
    auth_token VARCHAR(64) UNIQUE NOT NULL,
    status approval_status DEFAULT 'pending' NOT NULL,
    approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Pending logins: track login attempts pending admin approval
CREATE TABLE IF NOT EXISTS pending_logins (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    ip_address VARCHAR(45),
    user_agent TEXT,
    status approval_status DEFAULT 'pending' NOT NULL,
    approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    approved_at TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL
);

-- Viewing sessions: track active document viewing sessions
CREATE TABLE IF NOT EXISTS viewing_sessions (
    id SERIAL PRIMARY KEY,
    document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_fingerprint VARCHAR(255) NOT NULL,
    device_name VARCHAR(255),
    ip_address VARCHAR(45),
    status approval_status DEFAULT 'pending' NOT NULL,
    approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    started_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    last_active_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
    ended_at TIMESTAMP
);

-- Additional indexes for device security
CREATE INDEX IF NOT EXISTS idx_trusted_devices_user ON trusted_devices(user_id);
CREATE INDEX IF NOT EXISTS idx_trusted_devices_fingerprint ON trusted_devices(device_fingerprint);
CREATE INDEX IF NOT EXISTS idx_pending_auth_token ON pending_device_auth(auth_token);
CREATE INDEX IF NOT EXISTS idx_pending_auth_expires ON pending_device_auth(expires_at);
CREATE INDEX IF NOT EXISTS idx_pending_logins_user ON pending_logins(user_id);
CREATE INDEX IF NOT EXISTS idx_pending_logins_status ON pending_logins(status);
CREATE INDEX IF NOT EXISTS idx_viewing_sessions_document ON viewing_sessions(document_id);
CREATE INDEX IF NOT EXISTS idx_viewing_sessions_user ON viewing_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_viewing_sessions_status ON viewing_sessions(status);
