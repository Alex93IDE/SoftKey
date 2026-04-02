const express = require('express');
const { generateSync, createGuardrails } = require('otplib');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const app = express();
const PORT = 3333;
const SECRETS_FILE = path.join(__dirname, 'secrets.json');
const AUTH_FILE    = path.join(__dirname, 'auth.json');
const SESSION_FILE = path.join(__dirname, 'session.json');
const PBKDF2_ITER  = 300000;
const KEY_LEN      = 32;
const SESSION_MS   = 30 * 24 * 60 * 60 * 1000; // 30 days

app.use(express.json());
app.use(express.static(__dirname));

// --- In-memory master key ---
let masterKey = null;

// =====================
// CRYPTO HELPERS
// =====================

function deriveKey(password, saltHex) {
  return crypto.pbkdf2Sync(password, Buffer.from(saltHex, 'hex'), PBKDF2_ITER, KEY_LEN, 'sha256');
}

function aesEncrypt(plaintext, key) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
  const data = Buffer.concat([
    cipher.update(Buffer.isBuffer(plaintext) ? plaintext : Buffer.from(plaintext)),
    cipher.final(),
  ]);
  return {
    iv:  iv.toString('hex'),
    tag: cipher.getAuthTag().toString('hex'),
    data: data.toString('hex'),
  };
}

function aesDecrypt(envelope, key) {
  const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(envelope.iv, 'hex'));
  decipher.setAuthTag(Buffer.from(envelope.tag, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(envelope.data, 'hex')),
    decipher.final(),
  ]);
}

// =====================
// AUTH FILE
// =====================

function loadAuth() {
  if (!fs.existsSync(AUTH_FILE)) return null;
  try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8')); } catch { return null; }
}

function saveAuth(data) {
  fs.writeFileSync(AUTH_FILE, JSON.stringify(data, null, 2));
}

// =====================
// SESSION FILE
// =====================

function loadSessions() {
  if (!fs.existsSync(SESSION_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(SESSION_FILE, 'utf-8')); } catch { return []; }
}

function saveSessions(sessions) {
  fs.writeFileSync(SESSION_FILE, JSON.stringify(sessions, null, 2));
}

function createSession(key) {
  const tokenBuf  = crypto.randomBytes(32);
  const tokenHex  = tokenBuf.toString('hex');
  const tokenHash = crypto.createHash('sha256').update(tokenBuf).digest('hex');
  const encrypted = aesEncrypt(key, tokenBuf);

  const sessions = loadSessions().filter(s => s.expiresAt > Date.now());
  sessions.push({ tokenHash, encrypted, expiresAt: Date.now() + SESSION_MS });
  saveSessions(sessions);
  return tokenHex;
}

function resumeSession(tokenHex) {
  const tokenBuf  = Buffer.from(tokenHex, 'hex');
  const tokenHash = crypto.createHash('sha256').update(tokenBuf).digest('hex');
  const sessions  = loadSessions();
  const session   = sessions.find(s => s.tokenHash === tokenHash && s.expiresAt > Date.now());
  if (!session) return null;
  return aesDecrypt(session.encrypted, tokenBuf);
}

function deleteSession(tokenHex) {
  const tokenBuf  = Buffer.from(tokenHex, 'hex');
  const tokenHash = crypto.createHash('sha256').update(tokenBuf).digest('hex');
  const sessions  = loadSessions().filter(s => s.tokenHash !== tokenHash);
  saveSessions(sessions);
}

// =====================
// SECRETS
// =====================

function loadSecrets() {
  if (!masterKey || !fs.existsSync(SECRETS_FILE)) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf-8'));
    return JSON.parse(aesDecrypt(raw, masterKey).toString('utf-8'));
  } catch {
    return [];
  }
}

function saveSecrets(secrets) {
  if (!masterKey) throw new Error('Not authenticated');
  fs.writeFileSync(
    SECRETS_FILE,
    JSON.stringify(aesEncrypt(JSON.stringify(secrets), masterKey), null, 2)
  );
}

// =====================
// MIDDLEWARE
// =====================

function requireAuth(_req, res, next) {
  if (!masterKey) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

// =====================
// TOTP
// =====================

const GUARDRAILS = createGuardrails({ MIN_SECRET_BYTES: 1 });

function generateToken(secret, epoch) {
  try {
    return generateSync({ secret, guardrails: GUARDRAILS, ...(epoch !== undefined && { epoch }) });
  } catch {
    return null;
  }
}

// =====================
// AUTH API
// =====================

app.get('/api/auth/status', (_req, res) => {
  res.json({ setup: !!loadAuth(), authenticated: !!masterKey });
});

app.post('/api/auth/setup', (req, res) => {
  if (loadAuth()) return res.status(400).json({ error: 'Already set up' });

  const { password } = req.body;
  if (!password || password.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const newMasterKey = crypto.randomBytes(32);

  const passwordSalt = crypto.randomBytes(32).toString('hex');
  const passwordKey  = deriveKey(password, passwordSalt);
  const encryptedMasterKey = aesEncrypt(newMasterKey, passwordKey);

  const recoveryCode = crypto.randomBytes(20).toString('hex');
  const recoverySalt = crypto.randomBytes(32).toString('hex');
  const recoveryKey  = deriveKey(recoveryCode, recoverySalt);
  const encryptedMasterKeyRecovery = aesEncrypt(newMasterKey, recoveryKey);

  saveAuth({ passwordSalt, encryptedMasterKey, recoverySalt, encryptedMasterKeyRecovery });

  masterKey = newMasterKey;

  // Migrate existing plaintext secrets if present
  let existing = [];
  if (fs.existsSync(SECRETS_FILE)) {
    try {
      const raw = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf-8'));
      if (Array.isArray(raw)) existing = raw;
    } catch { /* start fresh */ }
  }
  saveSecrets(existing);

  const sessionToken = createSession(masterKey);
  res.json({ recoveryCode, sessionToken });
});

app.post('/api/auth/login', (req, res) => {
  const auth = loadAuth();
  if (!auth) return res.status(400).json({ error: 'Not set up' });

  const { password } = req.body;
  if (!password) return res.status(400).json({ error: 'Password required' });

  try {
    const key = deriveKey(password, auth.passwordSalt);
    masterKey = aesDecrypt(auth.encryptedMasterKey, key);
    const sessionToken = createSession(masterKey);
    res.json({ ok: true, sessionToken });
  } catch {
    masterKey = null;
    res.status(401).json({ error: 'Incorrect password' });
  }
});

app.post('/api/auth/resume', (req, res) => {
  const { sessionToken } = req.body;
  if (!sessionToken) return res.status(400).json({ error: 'Session token required' });

  try {
    const key = resumeSession(sessionToken);
    if (!key) return res.status(401).json({ error: 'Session expired' });
    masterKey = key;
    res.json({ ok: true });
  } catch {
    res.status(401).json({ error: 'Invalid session' });
  }
});

app.post('/api/auth/recover', (req, res) => {
  const auth = loadAuth();
  if (!auth) return res.status(400).json({ error: 'Not set up' });

  const { recoveryCode, newPassword } = req.body;
  if (!recoveryCode || !newPassword) {
    return res.status(400).json({ error: 'Recovery code and new password are required' });
  }
  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const normalizedCode = recoveryCode.replace(/[^a-fA-F0-9]/g, '').toLowerCase();

  try {
    const recoveryKey   = deriveKey(normalizedCode, auth.recoverySalt);
    const decryptedKey  = aesDecrypt(auth.encryptedMasterKeyRecovery, recoveryKey);

    const newPasswordSalt     = crypto.randomBytes(32).toString('hex');
    const newPasswordKey      = deriveKey(newPassword, newPasswordSalt);
    const newEncryptedMasterKey = aesEncrypt(decryptedKey, newPasswordKey);

    saveAuth({ ...auth, passwordSalt: newPasswordSalt, encryptedMasterKey: newEncryptedMasterKey });
    masterKey = decryptedKey;
    const sessionToken = createSession(masterKey);
    res.json({ ok: true, sessionToken });
  } catch {
    res.status(401).json({ error: 'Incorrect recovery code' });
  }
});

app.post('/api/auth/logout', (req, res) => {
  const { sessionToken } = req.body;
  if (sessionToken) deleteSession(sessionToken);
  masterKey = null;
  res.json({ ok: true });
});

// =====================
// TOKENS API
// =====================

app.get('/api/tokens', requireAuth, (_req, res) => {
  const secrets    = loadSecrets();
  const nowEpoch   = Math.floor(Date.now() / 1000);
  const timeRemaining = 30 - (nowEpoch % 30);

  const tokens = secrets.map(entry => ({
    id:        entry.id,
    name:      entry.name,
    token:     generateToken(entry.secret),
    nextToken: generateToken(entry.secret, nowEpoch + 30),
    timeRemaining,
    period: 30,
  }));

  res.json({ tokens, timeRemaining });
});

app.post('/api/secrets', requireAuth, (req, res) => {
  const { name, secret } = req.body;
  if (!name || !secret) return res.status(400).json({ error: 'name and secret are required' });

  const secrets  = loadSecrets();
  const newEntry = {
    id:     Date.now().toString(),
    name:   name.trim(),
    secret: secret.replace(/\s/g, '').toUpperCase(),
  };
  secrets.push(newEntry);
  saveSecrets(secrets);
  res.json({ success: true, id: newEntry.id });
});

app.delete('/api/secrets/:id', requireAuth, (req, res) => {
  const secrets  = loadSecrets();
  const filtered = secrets.filter(e => e.id !== req.params.id);
  if (filtered.length === secrets.length) return res.status(404).json({ error: 'Not found' });
  saveSecrets(filtered);
  res.json({ success: true });
});

// GET /api/export — returns otpauth:// URIs as plain text
app.get('/api/export', requireAuth, (_req, res) => {
  const secrets = loadSecrets();
  if (secrets.length === 0) return res.status(404).json({ error: 'No secrets to export' });
  const uris = secrets.map(s =>
    `otpauth://totp/${encodeURIComponent(s.name)}?secret=${s.secret}&issuer=${encodeURIComponent(s.name)}`
  );
  res.setHeader('Content-Type', 'text/plain; charset=utf-8');
  res.send(uris.join('\n'));
});

// POST /api/import — accepts otpauth:// URIs, mode: merge | replace
app.post('/api/import', requireAuth, (req, res) => {
  const { content, mode } = req.body;
  if (!content) return res.status(400).json({ error: 'content is required' });
  if (mode !== 'merge' && mode !== 'replace') return res.status(400).json({ error: 'mode must be merge or replace' });

  const lines = content.split(/\r?\n/).map(l => l.trim()).filter(l => l.startsWith('otpauth://totp/'));
  if (lines.length === 0) return res.status(400).json({ error: 'No valid otpauth:// URIs found' });

  const imported = [];
  for (const line of lines) {
    try {
      const url = new URL(line);
      const secret = url.searchParams.get('secret');
      if (!secret) continue;
      // label is the path minus leading slash, URL-decoded
      const label = decodeURIComponent(url.pathname.replace(/^\//, ''));
      const issuer = url.searchParams.get('issuer');
      const name = label || issuer || 'Unknown';
      imported.push({ id: Date.now().toString() + Math.random().toString(36).slice(2,6), name: name.trim(), secret: secret.replace(/\s/g,'').toUpperCase() });
    } catch { /* skip malformed lines */ }
  }

  if (imported.length === 0) return res.status(400).json({ error: 'No valid entries could be parsed' });

  const existing = mode === 'replace' ? [] : loadSecrets();
  // Avoid duplicates by secret value when merging
  const existingSecrets = new Set(existing.map(e => e.secret));
  const toAdd = mode === 'replace' ? imported : imported.filter(e => !existingSecrets.has(e.secret));
  saveSecrets([...existing, ...toAdd]);
  res.json({ imported: toAdd.length, skipped: imported.length - toAdd.length });
});

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Softkey running on http://localhost:${PORT}`);
});
