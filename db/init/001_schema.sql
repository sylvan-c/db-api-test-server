CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id BIGSERIAL PRIMARY KEY
 ,public_id TEXT NOT NULL UNIQUE DEFAULT (
    -- random url safe base64 string
    regexp_replace(
        translate(encode(gen_random_bytes(12), 'base64'), '+/', '-_'),
        '=+$',
        ''
    )
  )
 ,email TEXT NOT NULL UNIQUE
 ,password_hash TEXT NOT NULL
 ,created_date TIMESTAMP DEFAULT now()
 ,tst TIMESTAMP DEFAULT now()
);

CREATE INDEX idx_users_public_id ON users(public_id);

CREATE TABLE user_details (
  id BIGSERIAL PRIMARY KEY
 ,user_id INT NOT NULL UNIQUE REFERENCES users(id)
 ,first_name TEXT NOT NULL
 ,last_name TEXT NOT NULL
 ,tst TIMESTAMP DEFAULT now()
);

CREATE TABLE refresh_tokens (
  id BIGSERIAL PRIMARY KEY
 ,user_id INT NOT NULL REFERENCES users(id)
 ,device_uuid UUID NOT NULL
 ,token TEXT NOT NULL UNIQUE
 ,expiry_tst TIMESTAMP NOT NULL
 ,revoked BOOLEAN DEFAULT FALSE
 ,tst TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
