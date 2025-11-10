CREATE TABLE users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  password_hash TEXT NOT NULL,
  created_date TIMESTAMP DEFAULT now(),
  tst TIMESTAMP DEFAULT now()
);

CREATE TABLE user_details (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id),
  email TEXT NOT NULL,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  tst TIMESTAMP DEFAULT now()
);

CREATE TABLE refresh_tokens (
  id SERIAL PRIMARY KEY,
  user_id INT NOT NULL REFERENCES users(id),
  token TEXT NOT NULL UNIQUE,
  expiry_tst TIMESTAMP NOT NULL,
  revoked BOOLEAN DEFAULT FALSE,
  tst TIMESTAMP NOT NULL DEFAULT now()
);

CREATE INDEX idx_refresh_tokens_token ON refresh_tokens(token);
