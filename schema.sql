CREATE TABLE IF NOT EXISTS photo (
  id INTEGER PRIMARY KEY CHECK (id = 1),
  mime TEXT NOT NULL,
  bytes BLOB NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS links (
  id TEXT PRIMARY KEY,
  token_hash TEXT NOT NULL UNIQUE,
  otp_salt TEXT NOT NULL,
  otp_hash TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL,
  used_at INTEGER,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  locked_until INTEGER
);
CREATE INDEX IF NOT EXISTS links_expiry ON links(expires_at);
