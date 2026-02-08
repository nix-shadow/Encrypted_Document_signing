-- Migration script to upgrade existing database to admin-controlled security model
-- Run this script if you have an existing database with data

-- WARNING: This will modify your database structure
-- BACKUP YOUR DATABASE BEFORE RUNNING THIS SCRIPT!

BEGIN;

-- 1. Create new ENUM types
DO $$ BEGIN
    CREATE TYPE user_role AS ENUM ('admin', 'user');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

DO $$ BEGIN
    CREATE TYPE approval_status AS ENUM ('pending', 'approved', 'rejected');
EXCEPTION
    WHEN duplicate_object THEN null;
END $$;

-- 2. Add new columns to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS role user_role DEFAULT 'user' NOT NULL,
ADD COLUMN IF NOT EXISTS is_approved BOOLEAN DEFAULT false NOT NULL,
ADD COLUMN IF NOT EXISTS approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
ADD COLUMN IF NOT EXISTS approved_at TIMESTAMP;

-- 3. Auto-approve all existing users (they were created before this change)
UPDATE users SET is_approved = true, approved_at = CURRENT_TIMESTAMP WHERE is_approved = false;

-- 4. Update pending_device_auth table
ALTER TABLE pending_device_auth
ADD COLUMN IF NOT EXISTS status approval_status DEFAULT 'pending' NOT NULL,
ADD COLUMN IF NOT EXISTS approved_by INTEGER REFERENCES users(id) ON DELETE SET NULL;

-- 5. Create pending_logins table
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

-- 6. Create viewing_sessions table
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

-- 7. Create indexes for new tables
CREATE INDEX IF NOT EXISTS idx_pending_logins_user ON pending_logins(user_id);
CREATE INDEX IF NOT EXISTS idx_pending_logins_status ON pending_logins(status);
CREATE INDEX IF NOT EXISTS idx_viewing_sessions_document ON viewing_sessions(document_id);
CREATE INDEX IF NOT EXISTS idx_viewing_sessions_user ON viewing_sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_viewing_sessions_status ON viewing_sessions(status);

-- 8. Create audit log entries for migration
INSERT INTO audit_log (user_id, action, entity_type, entity_id, detail, created_at)
VALUES (NULL, 'system.migration', 'database', NULL, 'Upgraded to admin-controlled security model', CURRENT_TIMESTAMP);

COMMIT;

-- Print summary
DO $$ 
DECLARE 
    user_count INTEGER;
    admin_count INTEGER;
BEGIN
    SELECT COUNT(*) INTO user_count FROM users;
    SELECT COUNT(*) INTO admin_count FROM users WHERE role = 'admin';
    
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Migration completed successfully!';
    RAISE NOTICE '============================================';
    RAISE NOTICE 'Total users: %', user_count;
    RAISE NOTICE 'Admin users: %', admin_count;
    RAISE NOTICE 'All existing users auto-approved: YES';
    RAISE NOTICE '';
    RAISE NOTICE 'Next steps:';
    RAISE NOTICE '1. If no admin exists, run: python create_admin.py';
    RAISE NOTICE '2. Restart the application';
    RAISE NOTICE '3. New users will require admin approval';
    RAISE NOTICE '============================================';
END $$;
