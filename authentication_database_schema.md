# Ariba WAF Authentication Database Schema

## 1. Database Schema Overview

This document provides the comprehensive database schema design for the Ariba WAF authentication system. The schema includes all tables, indexes, constraints, and relationships required for secure user management, session tracking, and audit logging.

## 2. Core Tables

### 2.1 Users Table

**Purpose**: Stores user account information and credentials

```sql
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'viewer',
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    is_active BOOLEAN DEFAULT TRUE,
    is_locked BOOLEAN DEFAULT FALSE,
    failed_login_attempts INTEGER DEFAULT 0,
    last_login TIMESTAMP WITH TIME ZONE,
    last_password_change TIMESTAMP WITH TIME ZONE,
    password_reset_required BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    updated_by INTEGER REFERENCES users(id),
    CONSTRAINT valid_role CHECK (role IN ('super_admin', 'admin', 'viewer')),
    CONSTRAINT valid_email CHECK (email ~* '^[A-Za-z0-9._%-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,4}$')
);

CREATE INDEX idx_users_username ON users(username);
CREATE INDEX idx_users_email ON users(email);
CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_is_active ON users(is_active);
CREATE INDEX idx_users_is_locked ON users(is_locked);
```

**Table Structure:**

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| id | SERIAL | Primary key | PRIMARY KEY |
| username | VARCHAR(50) | Unique username | UNIQUE, NOT NULL |
| email | VARCHAR(255) | User email address | UNIQUE, NOT NULL, email format |
| password_hash | VARCHAR(255) | Bcrypt password hash | NOT NULL |
| role | VARCHAR(20) | User role | DEFAULT 'viewer', enum constraint |
| first_name | VARCHAR(100) | User's first name | - |
| last_name | VARCHAR(100) | User's last name | - |
| is_active | BOOLEAN | Account activation status | DEFAULT TRUE |
| is_locked | BOOLEAN | Account lockout status | DEFAULT FALSE |
| failed_login_attempts | INTEGER | Failed login counter | DEFAULT 0 |
| last_login | TIMESTAMP | Last successful login | - |
| last_password_change | TIMESTAMP | Last password change | - |
| password_reset_required | BOOLEAN | Force password reset flag | DEFAULT FALSE |
| created_at | TIMESTAMP | Record creation time | DEFAULT CURRENT_TIMESTAMP |
| updated_at | TIMESTAMP | Last update time | DEFAULT CURRENT_TIMESTAMP |
| created_by | INTEGER | User who created record | REFERENCES users(id) |
| updated_by | INTEGER | User who last updated | REFERENCES users(id) |

### 2.2 Sessions Table

**Purpose**: Tracks active user sessions and authentication tokens

```sql
CREATE TABLE sessions (
    session_id UUID PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    access_token_hash VARCHAR(255) NOT NULL,
    refresh_token_hash VARCHAR(255) NOT NULL,
    access_token_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    refresh_token_expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_info TEXT,
    location_country VARCHAR(2),
    location_city VARCHAR(50),
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE,
    revoked_at TIMESTAMP WITH TIME ZONE,
    revoked_by INTEGER REFERENCES users(id),
    revocation_reason TEXT,
    CONSTRAINT valid_token_expiry CHECK (
        access_token_expires_at > CURRENT_TIMESTAMP AND
        refresh_token_expires_at > access_token_expires_at
    )
);

CREATE INDEX idx_sessions_user_id ON sessions(user_id);
CREATE INDEX idx_sessions_access_token_expires ON sessions(access_token_expires_at);
CREATE INDEX idx_sessions_refresh_token_expires ON sessions(refresh_token_expires_at);
CREATE INDEX idx_sessions_is_active ON sessions(is_active);
CREATE INDEX idx_sessions_ip_address ON sessions(ip_address);
CREATE INDEX idx_sessions_last_used_at ON sessions(last_used_at);
```

**Table Structure:**

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| session_id | UUID | Unique session identifier | PRIMARY KEY |
| user_id | INTEGER | User who owns session | REFERENCES users(id), ON DELETE CASCADE |
| access_token_hash | VARCHAR(255) | SHA-256 hash of access token | NOT NULL |
| refresh_token_hash | VARCHAR(255) | SHA-256 hash of refresh token | NOT NULL |
| access_token_expires_at | TIMESTAMP | Access token expiration | NOT NULL, > current time |
| refresh_token_expires_at | TIMESTAMP | Refresh token expiration | NOT NULL, > access token expiry |
| ip_address | VARCHAR(45) | Client IP address | - |
| user_agent | TEXT | Client user agent string | - |
| device_info | TEXT | Device information | - |
| location_country | VARCHAR(2) | Country code | - |
| location_city | VARCHAR(50) | City name | - |
| is_active | BOOLEAN | Session active status | DEFAULT TRUE |
| created_at | TIMESTAMP | Session creation time | DEFAULT CURRENT_TIMESTAMP |
| last_used_at | TIMESTAMP | Last token usage time | - |
| revoked_at | TIMESTAMP | Session revocation time | - |
| revoked_by | INTEGER | User who revoked session | REFERENCES users(id) |
| revocation_reason | TEXT | Reason for revocation | - |

### 2.3 Authentication Logs Table

**Purpose**: Comprehensive audit trail of all authentication events

```sql
CREATE TABLE authentication_logs (
    log_id BIGSERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    username VARCHAR(50),
    event_type VARCHAR(50) NOT NULL,
    event_timestamp TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_fingerprint VARCHAR(64),
    success BOOLEAN NOT NULL,
    details JSONB,
    metadata JSONB,
    severity VARCHAR(20) DEFAULT 'info',
    CONSTRAINT valid_event_type CHECK (event_type IN (
        'login_success', 'login_failure', 'logout',
        'password_change', 'password_reset_request', 'password_reset_success',
        'session_created', 'session_revoked', 'token_refresh',
        'account_locked', 'account_unlocked', 'account_created',
        'account_deleted', 'role_change', 'permission_change'
    )),
    CONSTRAINT valid_severity CHECK (severity IN (
        'debug', 'info', 'warning', 'error', 'critical'
    ))
);

CREATE INDEX idx_auth_logs_user_id ON authentication_logs(user_id);
CREATE INDEX idx_auth_logs_username ON authentication_logs(username);
CREATE INDEX idx_auth_logs_event_type ON authentication_logs(event_type);
CREATE INDEX idx_auth_logs_event_timestamp ON authentication_logs(event_timestamp);
CREATE INDEX idx_auth_logs_ip_address ON authentication_logs(ip_address);
CREATE INDEX idx_auth_logs_success ON authentication_logs(success);
CREATE INDEX idx_auth_logs_severity ON authentication_logs(severity);
```

**Table Structure:**

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| log_id | BIGSERIAL | Primary key | PRIMARY KEY |
| user_id | INTEGER | User associated with event | REFERENCES users(id) |
| username | VARCHAR(50) | Username for non-user events | - |
| event_type | VARCHAR(50) | Type of authentication event | ENUM constraint |
| event_timestamp | TIMESTAMP | Event timestamp | DEFAULT CURRENT_TIMESTAMP |
| ip_address | VARCHAR(45) | Client IP address | - |
| user_agent | TEXT | Client user agent | - |
| device_fingerprint | VARCHAR(64) | Device fingerprint hash | - |
| success | BOOLEAN | Event success status | NOT NULL |
| details | JSONB | Event-specific details | - |
| metadata | JSONB | Additional metadata | - |
| severity | VARCHAR(20) | Log severity level | ENUM constraint, DEFAULT 'info' |

### 2.4 Password Reset Tokens Table

**Purpose**: Secure storage of password reset tokens with expiration

```sql
CREATE TABLE password_reset_tokens (
    token_id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    ip_address VARCHAR(45),
    user_agent TEXT,
    CONSTRAINT valid_expiry CHECK (expires_at > CURRENT_TIMESTAMP)
);

CREATE INDEX idx_password_reset_tokens_user_id ON password_reset_tokens(user_id);
CREATE INDEX idx_password_reset_tokens_token_hash ON password_reset_tokens(token_hash);
CREATE INDEX idx_password_reset_tokens_expires_at ON password_reset_tokens(expires_at);
CREATE INDEX idx_password_reset_tokens_used ON password_reset_tokens(used);
CREATE INDEX idx_password_reset_tokens_created_at ON password_reset_tokens(created_at);
```

**Table Structure:**

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| token_id | SERIAL | Primary key | PRIMARY KEY |
| user_id | INTEGER | User who requested reset | REFERENCES users(id), ON DELETE CASCADE |
| token_hash | VARCHAR(255) | SHA-256 hash of reset token | NOT NULL |
| expires_at | TIMESTAMP | Token expiration time | NOT NULL, > current time |
| used | BOOLEAN | Token usage status | DEFAULT FALSE |
| used_at | TIMESTAMP | When token was used | - |
| created_at | TIMESTAMP | Token creation time | DEFAULT CURRENT_TIMESTAMP |
| created_by | INTEGER | User who created token | REFERENCES users(id) |
| ip_address | VARCHAR(45) | Request IP address | - |
| user_agent | TEXT | Request user agent | - |

## 3. Role-Based Access Control Tables

### 3.1 Roles Table

**Purpose**: Define user roles and their properties

```sql
CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    role_name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    is_system_role BOOLEAN DEFAULT FALSE,
    is_default_role BOOLEAN DEFAULT FALSE,
    priority INTEGER DEFAULT 100,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    updated_by INTEGER REFERENCES users(id),
    CONSTRAINT valid_role_name CHECK (role_name ~ '^[a-z_]+$')
);

CREATE INDEX idx_roles_role_name ON roles(role_name);
CREATE INDEX idx_roles_is_system_role ON roles(is_system_role);
CREATE INDEX idx_roles_priority ON roles(priority);
```

**Table Structure:**

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| role_id | SERIAL | Primary key | PRIMARY KEY |
| role_name | VARCHAR(50) | Unique role identifier | UNIQUE, NOT NULL, lowercase alphanumeric |
| description | TEXT | Role description | - |
| is_system_role | BOOLEAN | System-defined role flag | DEFAULT FALSE |
| is_default_role | BOOLEAN | Default role for new users | DEFAULT FALSE |
| priority | INTEGER | Role priority (lower = higher) | DEFAULT 100 |
| created_at | TIMESTAMP | Creation timestamp | DEFAULT CURRENT_TIMESTAMP |
| updated_at | TIMESTAMP | Last update timestamp | DEFAULT CURRENT_TIMESTAMP |
| created_by | INTEGER | User who created role | REFERENCES users(id) |
| updated_by | INTEGER | User who last updated | REFERENCES users(id) |

### 3.2 Permissions Table

**Purpose**: Define individual permissions that can be assigned to roles

```sql
CREATE TABLE permissions (
    permission_id SERIAL PRIMARY KEY,
    permission_name VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    category VARCHAR(50) NOT NULL,
    is_system_permission BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    updated_by INTEGER REFERENCES users(id),
    CONSTRAINT valid_permission_name CHECK (permission_name ~ '^[a-z_:]+$'),
    CONSTRAINT valid_category CHECK (category IN (
        'dashboard', 'rules', 'ip_management', 'rate_limiting',
        'user_management', 'system', 'logging', 'api'
    ))
);

CREATE INDEX idx_permissions_permission_name ON permissions(permission_name);
CREATE INDEX idx_permissions_category ON permissions(category);
CREATE INDEX idx_permissions_is_system ON permissions(is_system_permission);
```

**Table Structure:**

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| permission_id | SERIAL | Primary key | PRIMARY KEY |
| permission_name | VARCHAR(100) | Unique permission identifier | UNIQUE, NOT NULL, specific format |
| description | TEXT | Permission description | - |
| category | VARCHAR(50) | Permission category | ENUM constraint |
| is_system_permission | BOOLEAN | System-defined permission | DEFAULT FALSE |
| created_at | TIMESTAMP | Creation timestamp | DEFAULT CURRENT_TIMESTAMP |
| updated_at | TIMESTAMP | Last update timestamp | DEFAULT CURRENT_TIMESTAMP |
| created_by | INTEGER | User who created permission | REFERENCES users(id) |
| updated_by | INTEGER | User who last updated | REFERENCES users(id) |

### 3.3 Role Permissions Table

**Purpose**: Many-to-many relationship between roles and permissions

```sql
CREATE TABLE role_permissions (
    role_id INTEGER NOT NULL REFERENCES roles(role_id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES permissions(permission_id) ON DELETE CASCADE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    created_by INTEGER REFERENCES users(id),
    PRIMARY KEY (role_id, permission_id)
);

CREATE INDEX idx_role_permissions_role_id ON role_permissions(role_id);
CREATE INDEX idx_role_permissions_permission_id ON role_permissions(permission_id);
CREATE INDEX idx_role_permissions_created_at ON role_permissions(created_at);
```

**Table Structure:**

| Column | Type | Description | Constraints |
|--------|------|-------------|-------------|
| role_id | INTEGER | Role identifier | REFERENCES roles(role_id), ON DELETE CASCADE |
| permission_id | INTEGER | Permission identifier | REFERENCES permissions(permission_id), ON DELETE CASCADE |
| created_at | TIMESTAMP | Assignment timestamp | DEFAULT CURRENT_TIMESTAMP |
| created_by | INTEGER | User who made assignment | REFERENCES users(id) |

## 4. Database Functions and Triggers

### 4.1 User Management Functions

```sql
CREATE OR REPLACE FUNCTION create_user(
    p_username VARCHAR(50),
    p_email VARCHAR(255),
    p_password_hash VARCHAR(255),
    p_role VARCHAR(20) DEFAULT 'viewer',
    p_first_name VARCHAR(100) DEFAULT NULL,
    p_last_name VARCHAR(100) DEFAULT NULL,
    p_created_by INTEGER DEFAULT NULL
) RETURNS INTEGER AS $$
DECLARE
    v_user_id INTEGER;
    v_current_user INTEGER;
BEGIN
    -- Set current user if not provided
    IF p_created_by IS NULL THEN
        v_current_user := current_setting('app.current_user_id')::INTEGER;
    ELSE
        v_current_user := p_created_by;
    END IF;

    -- Insert new user
    INSERT INTO users (
        username, email, password_hash, role,
        first_name, last_name, created_by, updated_by
    ) VALUES (
        p_username, p_email, p_password_hash, p_role,
        p_first_name, p_last_name, v_current_user, v_current_user
    ) RETURNING id INTO v_user_id;

    -- Log user creation
    INSERT INTO authentication_logs (
        user_id, username, event_type, success,
        details, created_by
    ) VALUES (
        v_user_id, p_username, 'account_created', TRUE,
        jsonb_build_object(
            'email', p_email,
            'role', p_role,
            'created_by', v_current_user
        ),
        v_current_user
    );

    RETURN v_user_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

### 4.2 Session Management Functions

```sql
CREATE OR REPLACE FUNCTION create_session(
    p_user_id INTEGER,
    p_access_token_hash VARCHAR(255),
    p_refresh_token_hash VARCHAR(255),
    p_access_token_expires TIMESTAMP WITH TIME ZONE,
    p_refresh_token_expires TIMESTAMP WITH TIME ZONE,
    p_ip_address VARCHAR(45),
    p_user_agent TEXT,
    p_device_info TEXT
) RETURNS UUID AS $$
DECLARE
    v_session_id UUID;
BEGIN
    v_session_id := gen_random_uuid();

    INSERT INTO sessions (
        session_id, user_id, access_token_hash, refresh_token_hash,
        access_token_expires_at, refresh_token_expires_at,
        ip_address, user_agent, device_info, created_at
    ) VALUES (
        v_session_id, p_user_id, p_access_token_hash, p_refresh_token_hash,
        p_access_token_expires, p_refresh_token_expires,
        p_ip_address, p_user_agent, p_device_info, CURRENT_TIMESTAMP
    );

    RETURN v_session_id;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;
```

### 4.3 Authentication Logging Triggers

```sql
CREATE OR REPLACE FUNCTION log_user_login()
RETURNS TRIGGER AS $$
BEGIN
    IF TG_OP = 'INSERT' AND NEW.last_login IS NOT NULL THEN
        INSERT INTO authentication_logs (
            user_id, username, event_type, success,
            ip_address, user_agent, details
        ) VALUES (
            NEW.id, NEW.username, 'login_success', TRUE,
            current_setting('app.client_ip'),
            current_setting('app.user_agent'),
            jsonb_build_object(
                'last_login', NEW.last_login,
                'failed_attempts', NEW.failed_login_attempts
            )
        );
    END IF;

    RETURN NEW;
END;
$$ LANGUAGE plpgsql SECURITY DEFINER;

CREATE TRIGGER trg_user_login_log
AFTER UPDATE OF last_login ON users
FOR EACH ROW
EXECUTE FUNCTION log_user_login();
```

## 5. Database Views

### 5.1 Active Sessions View

```sql
CREATE OR REPLACE VIEW vw_active_sessions AS
SELECT
    s.session_id,
    s.user_id,
    u.username,
    u.email,
    u.role,
    s.ip_address,
    s.user_agent,
    s.device_info,
    s.created_at,
    s.last_used_at,
    s.access_token_expires_at,
    s.refresh_token_expires_at,
    EXTRACT(EPOCH FROM (s.access_token_expires_at - CURRENT_TIMESTAMP)) AS access_token_remaining_seconds,
    EXTRACT(EPOCH FROM (s.refresh_token_expires_at - CURRENT_TIMESTAMP)) AS refresh_token_remaining_seconds,
    CASE
        WHEN s.access_token_expires_at < CURRENT_TIMESTAMP THEN 'expired'
        WHEN s.revoked_at IS NOT NULL THEN 'revoked'
        WHEN s.is_active = FALSE THEN 'inactive'
        ELSE 'active'
    END AS session_status
FROM sessions s
JOIN users u ON s.user_id = u.id
WHERE s.is_active = TRUE
AND s.revoked_at IS NULL
AND s.access_token_expires_at > CURRENT_TIMESTAMP;
```

### 5.2 User Permissions View

```sql
CREATE OR REPLACE VIEW vw_user_permissions AS
SELECT
    u.id AS user_id,
    u.username,
    u.email,
    u.role,
    r.role_name,
    p.permission_id,
    p.permission_name,
    p.description AS permission_description,
    p.category AS permission_category
FROM users u
JOIN roles r ON u.role = r.role_name
JOIN role_permissions rp ON r.role_id = rp.role_id
JOIN permissions p ON rp.permission_id = p.permission_id
WHERE u.is_active = TRUE;
```

## 6. Database Indexes and Optimization

### 6.1 Recommended Indexes

```sql
-- Additional performance indexes
CREATE INDEX idx_users_last_login ON users(last_login);
CREATE INDEX idx_users_created_at ON users(created_at);
CREATE INDEX idx_sessions_created_at ON sessions(created_at);
CREATE INDEX idx_auth_logs_created_at ON authentication_logs(event_timestamp);
CREATE INDEX idx_password_reset_tokens_created_at ON password_reset_tokens(created_at);

-- Composite indexes for common queries
CREATE INDEX idx_users_role_active ON users(role, is_active);
CREATE INDEX idx_sessions_user_active ON sessions(user_id, is_active);
CREATE INDEX idx_auth_logs_user_event ON authentication_logs(user_id, event_type);
```

### 6.2 Partitioning Strategy

```sql
-- Partition authentication logs by time for large datasets
CREATE TABLE authentication_logs (
    -- ... existing columns ...
) PARTITION BY RANGE (event_timestamp);

-- Create monthly partitions
CREATE TABLE authentication_logs_y2025m01 PARTITION OF authentication_logs
    FOR VALUES FROM ('2025-01-01') TO ('2025-02-01');

CREATE TABLE authentication_logs_y2025m02 PARTITION OF authentication_logs
    FOR VALUES FROM ('2025-02-01') TO ('2025-03-01');

-- Add more partitions as needed
```

## 7. Database Security

### 7.1 Role-Based Database Access

```sql
-- Create database roles
CREATE ROLE waf_auth_admin WITH
    LOGIN
    PASSWORD 'secure_password_here'
    NOSUPERUSER
    INHERIT
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION;

CREATE ROLE waf_auth_app WITH
    LOGIN
    PASSWORD 'secure_password_here'
    NOSUPERUSER
    INHERIT
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION;

CREATE ROLE waf_auth_readonly WITH
    LOGIN
    PASSWORD 'secure_password_here'
    NOSUPERUSER
    INHERIT
    NOCREATEDB
    NOCREATEROLE
    NOREPLICATION;

-- Grant permissions
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO waf_auth_admin;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO waf_auth_admin;
GRANT ALL PRIVILEGES ON ALL FUNCTIONS IN SCHEMA public TO waf_auth_admin;

GRANT SELECT, INSERT, UPDATE ON ALL TABLES IN SCHEMA public TO waf_auth_app;
GRANT SELECT, UPDATE ON ALL SEQUENCES IN SCHEMA public TO waf_auth_app;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO waf_auth_app;

GRANT SELECT ON ALL TABLES IN SCHEMA public TO waf_auth_readonly;
GRANT SELECT ON ALL SEQUENCES IN SCHEMA public TO waf_auth_readonly;
```

### 7.2 Row-Level Security Policies

```sql
-- Enable row-level security
ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- Policy: Users can only see their own data
CREATE POLICY user_self_access_policy ON users
    USING (id = current_setting('app.current_user_id')::INTEGER);

-- Policy: Admins can see all users
CREATE POLICY admin_user_access_policy ON users
    USING (current_setting('app.current_user_role') = 'admin');

-- Policy: Users can only update their own data
CREATE POLICY user_self_update_policy ON users
    FOR UPDATE
    USING (id = current_setting('app.current_user_id')::INTEGER)
    WITH CHECK (id = current_setting('app.current_user_id')::INTEGER);
```

## 8. Database Maintenance

### 8.1 Session Cleanup Procedure

```sql
CREATE OR REPLACE PROCEDURE cleanup_expired_sessions()
LANGUAGE plpgsql
AS $$
BEGIN
    -- Delete expired sessions
    DELETE FROM sessions
    WHERE access_token_expires_at < CURRENT_TIMESTAMP
    AND refresh_token_expires_at < CURRENT_TIMESTAMP;

    -- Log cleanup operation
    INSERT INTO authentication_logs (
        event_type, success, details, severity
    ) VALUES (
        'session_cleanup',
        TRUE,
        jsonb_build_object(
            'deleted_count', (SELECT COUNT(*) FROM sessions WHERE access_token_expires_at < CURRENT_TIMESTAMP)
        ),
        'info'
    );
END;
$$;

-- Schedule daily cleanup
SELECT cron.schedule(
    'session-cleanup-daily',
    '0 3 * * *',  -- Daily at 3 AM
    $$CALL cleanup_expired_sessions()$$
);
```

### 8.2 Password Reset Token Cleanup

```sql
CREATE OR REPLACE PROCEDURE cleanup_expired_reset_tokens()
LANGUAGE plpgsql
AS $$
BEGIN
    -- Delete expired and used tokens
    DELETE FROM password_reset_tokens
    WHERE (expires_at < CURRENT_TIMESTAMP) OR (used = TRUE);

    -- Log cleanup operation
    INSERT INTO authentication_logs (
        event_type, success, details, severity
    ) VALUES (
        'token_cleanup',
        TRUE,
        jsonb_build_object(
            'deleted_count', (SELECT COUNT(*) FROM password_reset_tokens WHERE expires_at < CURRENT_TIMESTAMP OR used = TRUE)
        ),
        'info'
    );
END;
$$;

-- Schedule hourly cleanup
SELECT cron.schedule(
    'token-cleanup-hourly',
    '0 * * * *',  -- Hourly
    $$CALL cleanup_expired_reset_tokens()$$
);
```

## 9. Database Migration Scripts

### 9.1 Initial Migration Script

```sql
-- 001_initial_auth_schema.sql
BEGIN;

-- Create schema if not exists
CREATE SCHEMA IF NOT EXISTS auth;

-- Set search path
SET search_path TO auth, public;

-- Create all tables
CREATE TABLE IF NOT EXISTS users (...);
CREATE TABLE IF NOT EXISTS sessions (...);
CREATE TABLE IF NOT EXISTS authentication_logs (...);
CREATE TABLE IF NOT EXISTS password_reset_tokens (...);
CREATE TABLE IF NOT EXISTS roles (...);
CREATE TABLE IF NOT EXISTS permissions (...);
CREATE TABLE IF NOT EXISTS role_permissions (...);

-- Create indexes
CREATE INDEX IF NOT EXISTS idx_users_username ON users(username);
-- ... all other indexes ...

-- Create functions and triggers
CREATE OR REPLACE FUNCTION create_user(...) ...;
-- ... all other functions ...

-- Create views
CREATE OR REPLACE VIEW vw_active_sessions AS ...;
-- ... all other views ...

-- Insert default roles and permissions
INSERT INTO roles (role_name, description, is_system_role, priority)
VALUES
    ('super_admin', 'Full system access', TRUE, 10),
    ('admin', 'Administrative access', TRUE, 50),
    ('viewer', 'Read-only access', TRUE, 100);

-- Insert default permissions
INSERT INTO permissions (permission_name, description, category, is_system_permission)
VALUES
    ('dashboard:view', 'View dashboard', 'dashboard', TRUE),
    ('dashboard:edit', 'Edit dashboard settings', 'dashboard', TRUE),
    -- ... all other permissions ...

-- Assign permissions to roles
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.role_id, p.permission_id
FROM roles r, permissions p
WHERE r.role_name = 'super_admin';

-- ... other role assignments ...

COMMIT;
```

### 9.2 Sample Data Migration

```sql
-- 002_sample_data.sql
BEGIN;

-- Create sample users
INSERT INTO users (username, email, password_hash, role, first_name, last_name)
VALUES
    ('admin', 'admin@ariba-waf.com', '$2b$12$...', 'super_admin', 'System', 'Administrator'),
    ('analyst', 'analyst@ariba-waf.com', '$2b$12$...', 'admin', 'Security', 'Analyst'),
    ('viewer', 'viewer@ariba-waf.com', '$2b$12$...', 'viewer', 'Dashboard', 'Viewer');

-- Log user creations
INSERT INTO authentication_logs (user_id, username, event_type, success, details)
SELECT id, username, 'account_created', TRUE,
    jsonb_build_object('migration', TRUE)
FROM users;

COMMIT;
```

## 10. Database Backup and Recovery

### 10.1 Backup Strategy

```bash
# Daily full backup
pg_dump -U waf_auth_admin -d ariba_waf_auth -F c -f /backups/auth_db_$(date +%Y%m%d).dump

# Hourly incremental backup (using WAL archiving)
# Configure in postgresql.conf:
# wal_level = replica
# archive_mode = on
# archive_command = 'test ! -f /backups/wal_archive/%f && cp %p /backups/wal_archive/%f'

# Backup retention policy
find /backups -name "auth_db_*.dump" -mtime +30 -exec rm {} \;
find /backups/wal_archive -name "*.wal" -mtime +7 -exec rm {} \;
```

### 10.2 Recovery Procedures

```bash
# Full database recovery
createdb -U postgres ariba_waf_auth_recovery
pg_restore -U waf_auth_admin -d ariba_waf_auth_recovery /backups/auth_db_latest.dump

# Point-in-time recovery
# 1. Restore base backup
pg_restore -U waf_auth_admin -d ariba_waf_auth_recovery /backups/auth_db_20250101.dump

# 2. Apply WAL files up to desired point
# (Using pg_rewind and recovery.conf as needed)
```

This comprehensive database schema provides a secure, scalable foundation for the Ariba WAF authentication system with proper indexing, constraints, functions, and security measures.