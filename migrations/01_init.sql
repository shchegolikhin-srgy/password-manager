CREATE TABLE users(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(30) NOT NULL UNIQUE,
    email VARCHAR(40),
    password_hash TEXT NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE encrypted_passwords (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    service VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    url VARCHAR(255),
    encrypted_password TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);

CREATE TABLE trusted_devices(
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    browser_version VARCHAR(30),
    browser_name VARCHAR(20),
    device_type VARCHAR(20),
    device_name VARCHAR(60),
    os_name VARCHAR(20),
    os_version VARCHAR(20),
    is_active BOOLEAN NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP
);

CREATE TABLE device_history(
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    browser_version VARCHAR(30),
    browser_name VARCHAR(20),
    device_type VARCHAR(20),
    device_name VARCHAR(60),
    os_name VARCHAR(20),
    os_version VARCHAR(20),
    is_active BOOLEAN NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    last_seen_at TIMESTAMP
);

CREATE TABLE favorite_passwords (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    password_id INTEGER NOT NULL REFERENCES encrypted_passwords(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id, password_id)
);

CREATE TABLE password_hints (
    id SERIAL PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hint VARCHAR(100) NOT NULL
);

CREATE INDEX idx_favorite_passwords_user_id ON favorite_passwords (user_id);
CREATE INDEX idx_favorite_passwords_password_id ON favorite_passwords (password_id);
CREATE INDEX idx_passwords_user_id ON encrypted_passwords (user_id);
CREATE INDEX idx_device_history_user_id ON device_history (user_id);