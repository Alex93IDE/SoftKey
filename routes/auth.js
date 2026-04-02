const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');
const { deriveKey, aesEncrypt, aesDecrypt } = require('../lib/crypto');
const { createSession, resumeSession, deleteSession } = require('../lib/sessions');
const state   = require('../lib/state');

module.exports = function (dataDir) {
  const router       = express.Router();
  const AUTH_FILE    = path.join(dataDir, 'auth.json');
  const SECRETS_FILE = path.join(dataDir, 'secrets.json');
  const SESSION_FILE = path.join(dataDir, 'session.json');

  function loadAuth() {
    if (!fs.existsSync(AUTH_FILE)) return null;
    try { return JSON.parse(fs.readFileSync(AUTH_FILE, 'utf-8')); } catch { return null; }
  }

  function saveAuth(data) {
    fs.writeFileSync(AUTH_FILE, JSON.stringify(data, null, 2));
  }

  router.get('/status', (_req, res) => {
    res.json({ setup: !!loadAuth(), authenticated: !!state.get() });
  });

  router.post('/setup', (req, res) => {
    if (loadAuth()) return res.status(400).json({ error: 'Already set up' });

    const { password } = req.body;
    if (!password || password.length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const newMasterKey = crypto.randomBytes(32);

    const passwordSalt        = crypto.randomBytes(32).toString('hex');
    const passwordKey         = deriveKey(password, passwordSalt);
    const encryptedMasterKey  = aesEncrypt(newMasterKey, passwordKey);

    const recoveryCode               = crypto.randomBytes(20).toString('hex');
    const recoverySalt               = crypto.randomBytes(32).toString('hex');
    const recoveryKey                = deriveKey(recoveryCode, recoverySalt);
    const encryptedMasterKeyRecovery = aesEncrypt(newMasterKey, recoveryKey);

    saveAuth({ passwordSalt, encryptedMasterKey, recoverySalt, encryptedMasterKeyRecovery });
    state.set(newMasterKey);

    // Migrate existing plaintext secrets if present
    let existing = [];
    if (fs.existsSync(SECRETS_FILE)) {
      try {
        const raw = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf-8'));
        if (Array.isArray(raw)) existing = raw;
      } catch { /* start fresh */ }
    }
    fs.writeFileSync(
      SECRETS_FILE,
      JSON.stringify(aesEncrypt(JSON.stringify(existing), state.get()), null, 2)
    );

    const sessionToken = createSession(SESSION_FILE, state.get());
    res.json({ recoveryCode, sessionToken });
  });

  router.post('/login', (req, res) => {
    const auth = loadAuth();
    if (!auth) return res.status(400).json({ error: 'Not set up' });

    const { password } = req.body;
    if (!password) return res.status(400).json({ error: 'Password required' });

    try {
      const key = deriveKey(password, auth.passwordSalt);
      state.set(aesDecrypt(auth.encryptedMasterKey, key));
      const sessionToken = createSession(SESSION_FILE, state.get());
      res.json({ ok: true, sessionToken });
    } catch {
      state.clear();
      res.status(401).json({ error: 'Incorrect password' });
    }
  });

  router.post('/resume', (req, res) => {
    const { sessionToken } = req.body;
    if (!sessionToken) return res.status(400).json({ error: 'Session token required' });

    try {
      const key = resumeSession(SESSION_FILE, sessionToken);
      if (!key) return res.status(401).json({ error: 'Session expired' });
      state.set(key);
      res.json({ ok: true });
    } catch {
      res.status(401).json({ error: 'Invalid session' });
    }
  });

  router.post('/recover', (req, res) => {
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
      const recoveryKey        = deriveKey(normalizedCode, auth.recoverySalt);
      const decryptedKey       = aesDecrypt(auth.encryptedMasterKeyRecovery, recoveryKey);

      const newPasswordSalt      = crypto.randomBytes(32).toString('hex');
      const newPasswordKey       = deriveKey(newPassword, newPasswordSalt);
      const newEncryptedMasterKey = aesEncrypt(decryptedKey, newPasswordKey);

      saveAuth({ ...auth, passwordSalt: newPasswordSalt, encryptedMasterKey: newEncryptedMasterKey });
      state.set(decryptedKey);
      const sessionToken = createSession(SESSION_FILE, state.get());
      res.json({ ok: true, sessionToken });
    } catch {
      res.status(401).json({ error: 'Incorrect recovery code' });
    }
  });

  router.post('/logout', (req, res) => {
    const { sessionToken } = req.body;
    if (sessionToken) deleteSession(SESSION_FILE, sessionToken);
    state.clear();
    res.json({ ok: true });
  });

  return router;
};
