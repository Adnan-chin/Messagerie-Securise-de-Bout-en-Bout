// server.mjs
import express from 'express';
import session from 'express-session';
import crypto from 'node:crypto';
import { ed25519 } from '@noble/curves/ed25519.js';
import pool  from '../db/db.js';

const app = express();

// ---------- Global middleware (registered once, before routes) ----------
app.use(express.json({ limit: '16kb' }));
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: process.env.SESSION_SECRET ?? crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    sameSite: 'strict',
    secure: process.env.NODE_ENV === 'production', // requires HTTPS in prod
  },
}));

// ---------- Config ----------
const NONCE_TTL_MS = 5 * 60 * 1000;           // 5 minutes
const KEM_PUB_LEN = 1184;                      // ML-KEM-768 — adjust to your KEM
const AUTH_CONTEXT = Buffer.from('auth-v1:');  // domain separation for login signatures

// ---------- Helpers ----------
function decodeB64(value, expectedLen, name) {
  if (typeof value !== 'string' || value.length === 0) {
    throw new Error(`${name} is missing`);
  }
  const bytes = new Uint8Array(Buffer.from(value, 'base64'));
  if (expectedLen && bytes.length !== expectedLen) {
    throw new Error(`${name} must be ${expectedLen} bytes`);
  }
  return bytes;
}

function isValidUsername(u) {
  return typeof u === 'string' && /^[a-zA-Z0-9_.-]{3,32}$/.test(u);
}

// ---------- POST /register : validate, verify bundle_sig, INSERT, 201 ----------
app.post('/register', async (req, res) => {
  const { username, sign_pub, x25519_pub, kem_pub, bundle_sig } = req.body ?? {};

  // 1. Validate and decode inputs
  let signPub, xPub, kemPub, bundleSig;
  try {
    if (!isValidUsername(username)) throw new Error('invalid username');
    signPub   = decodeB64(sign_pub,   32,          'sign_pub');
    xPub      = decodeB64(x25519_pub, 32,          'x25519_pub');
    kemPub    = decodeB64(kem_pub,    KEM_PUB_LEN, 'kem_pub');
    bundleSig = decodeB64(bundle_sig, 64,          'bundle_sig');
  } catch (err) {
    return res.status(400).json({ error: 'invalid_input', message: err.message });
  }

  // 2. Verify the signature BEFORE touching the database
  //    Must be byte-for-byte the same message the client signed
  const message = Buffer.concat([xPub, kemPub]);
  let ok = false;
  try {
    ok = ed25519.verify(bundleSig, message, signPub);
  } catch {
    ok = false;
  }
  if (!ok) {
    return res.status(400).json({ error: 'invalid_input', message: 'bundle_sig invalid' });
  }

  // 3. Insert into Postgres
  try {
    const result = await pool.query(
      `INSERT INTO users (username, sign_pub, x25519_pub, kem_pub)
       VALUES ($1, $2, $3, $4)
       ON CONFLICT (username) DO NOTHING
       RETURNING id`,
      [username, Buffer.from(signPub), Buffer.from(xPub), Buffer.from(kemPub)]
    );

    if (result.rowCount === 0) {
      return res.status(409).json({ error: 'conflict', message: 'username already registered' });
    }
    return res.status(201).json({ username });
  } catch (err) {
    console.error('register failed:', err);
    return res.status(500).json({ error: 'server_error' });
  }
});

// ---------- POST /challenge : issue a single-use nonce ----------
app.post('/challenge', (req, res) => {
  const { username } = req.body ?? {};

  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'invalid_input', message: 'invalid username' });
  }

  // Issued even for unknown users so the endpoint doesn't reveal who exists
  const nonce = crypto.randomBytes(32).toString('base64');
  req.session.challenge = { username, nonce, expiresAt: Date.now() + NONCE_TTL_MS };

  return res.json({ nonce, expires_in: NONCE_TTL_MS / 1000, username });
});

// ---------- POST /verify : check Ed25519 signature over the nonce ----------
app.post('/verify', async (req, res) => {
  const challenge = req.session.challenge;
  req.session.challenge = null; // single use: consumed even if verification fails

  const { username, signature } = req.body ?? {};

  if (!challenge) {
    return res.status(400).json({ error: 'no_challenge', message: 'request a challenge first' });
  }
  if (Date.now() > challenge.expiresAt) {
    return res.status(401).json({ error: 'expired', message: 'challenge expired' });
  }
  if (username !== challenge.username) {
    return res.status(401).json({ error: 'unauthorized', message: 'authentication failed' });
  }

  let ok = false;
  try {
    const { rows } = await pool.query(
      'SELECT sign_pub FROM users WHERE username = $1',
      [username]
    );
    const sig = decodeB64(signature, 64, 'signature');
    const msg = Buffer.concat([AUTH_CONTEXT, Buffer.from(challenge.nonce, 'base64')]);
    ok = rows.length === 1 && ed25519.verify(sig, msg, rows[0].sign_pub);
  } catch (err) {
    console.error('verify failed:', err.message);
    ok = false;
  }
  if (!ok) {
    return res.status(401).json({ error: 'unauthorized', message: 'authentication failed' });
  }

  // New session ID after login (prevents session fixation)
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'server_error' });
    req.session.username = username;
    return res.json({ ok: true, username });
  });
});

export default app;
