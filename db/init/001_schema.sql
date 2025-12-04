CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
  id UUID PRIMARY KEY
 ,email TEXT NOT NULL UNIQUE
 ,password_hash TEXT NOT NULL
 ,created_date TIMESTAMP DEFAULT now()
 ,tst TIMESTAMP DEFAULT now()
);

CREATE TABLE user_details (
  id UUID PRIMARY KEY
 ,user_id UUID NOT NULL UNIQUE REFERENCES users(id)
 ,first_name TEXT NOT NULL DEFAULT ''
 ,last_name TEXT NOT NULL DEFAULT ''
 ,tst TIMESTAMP DEFAULT now()
);

CREATE TABLE refresh_tokens (
  id UUID PRIMARY KEY
 ,user_id UUID NOT NULL REFERENCES users(id)
 ,device_uuid UUID NOT NULL
 ,token TEXT NOT NULL UNIQUE
 ,expiry_tst TIMESTAMP NOT NULL
 ,revoked BOOLEAN DEFAULT FALSE
 ,tst TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
