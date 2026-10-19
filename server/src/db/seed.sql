

CREATE TABLE users (
  id          SERIAL PRIMARY KEY,
  username    TEXT UNIQUE NOT NULL,
  sign_pub    BYTEA NOT NULL,   -- Ed25519, 32 bytes
  x25519_pub  BYTEA NOT NULL,   -- X25519, 32 bytes
  kem_pub     BYTEA NOT NULL,   -- ML-KEM-768, 1184 bytes
  bundle_sig  BYTEA NOT NULL,   -- Ed25519 signature, 64 bytes
  created_at  TIMESTAMPTZ DEFAULT now()
);

CREATE TABLE auth_challenges (
  nonce       BYTEA PRIMARY KEY,
  user_id     INT REFERENCES users(id),
  expires_at  TIMESTAMPTZ NOT NULL,
  used        BOOLEAN DEFAULT FALSE
);

CREATE TABLE messages (
  id           BIGSERIAL PRIMARY KEY,
  sender_id    INT REFERENCES users(id),
  receiver_id  INT REFERENCES users(id),
  session_id   UUID NOT NULL,
  epoch        INT NOT NULL,
  counter      INT NOT NULL,
  header       BYTEA NOT NULL,
  nonce        BYTEA NOT NULL,
  ciphertext   BYTEA NOT NULL,
  created_at   TIMESTAMPTZ DEFAULT now(),
  UNIQUE (session_id, sender_id, epoch, counter)
);