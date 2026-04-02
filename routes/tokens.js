const express = require('express');
const fs      = require('fs');
const path    = require('path');
const { aesEncrypt, aesDecrypt } = require('../lib/crypto');
const { generateToken }          = require('../lib/totp');
const state   = require('../lib/state');

module.exports = function (dataDir) {
  const router       = express.Router();
  const SECRETS_FILE = path.join(dataDir, 'secrets.json');

  function requireAuth(_req, res, next) {
    if (!state.get()) return res.status(401).json({ error: 'Not authenticated' });
    next();
  }

  function loadSecrets() {
    const masterKey = state.get();
    if (!masterKey || !fs.existsSync(SECRETS_FILE)) return [];
    try {
      const raw = JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf-8'));
      return JSON.parse(aesDecrypt(raw, masterKey).toString('utf-8'));
    } catch {
      return [];
    }
  }

  function saveSecrets(secrets) {
    const masterKey = state.get();
    if (!masterKey) throw new Error('Not authenticated');
    fs.writeFileSync(
      SECRETS_FILE,
      JSON.stringify(aesEncrypt(JSON.stringify(secrets), masterKey), null, 2)
    );
  }

  router.get('/tokens', requireAuth, (_req, res) => {
    const secrets  = loadSecrets();
    const nowEpoch = Math.floor(Date.now() / 1000);

    const tokens = secrets.map(entry => {
      const digits    = entry.digits || 6;
      const period    = entry.period || 30;
      const remaining = period - (nowEpoch % period);
      return {
        id:            entry.id,
        issuer:        entry.issuer || entry.name,
        account:       entry.account || '',
        token:         generateToken(entry.secret, undefined, digits, period),
        nextToken:     generateToken(entry.secret, nowEpoch + period, digits, period),
        timeRemaining: remaining,
        period,
      };
    });

    res.json({ tokens, timeRemaining: 30 - (nowEpoch % 30) });
  });

  router.post('/secrets', requireAuth, (req, res) => {
    const { name, secret, issuer, account } = req.body;
    if (!name || !secret) return res.status(400).json({ error: 'name and secret are required' });

    const secrets  = loadSecrets();
    const newEntry = {
      id:      Date.now().toString(),
      name:    name.trim(),
      issuer:  (issuer || name).trim(),
      account: (account || '').trim(),
      secret:  secret.replace(/\s/g, '').toUpperCase(),
    };
    secrets.push(newEntry);
    saveSecrets(secrets);
    res.json({ success: true, id: newEntry.id });
  });

  router.delete('/secrets/:id', requireAuth, (req, res) => {
    const secrets  = loadSecrets();
    const filtered = secrets.filter(e => e.id !== req.params.id);
    if (filtered.length === secrets.length) return res.status(404).json({ error: 'Not found' });
    saveSecrets(filtered);
    res.json({ success: true });
  });

  router.get('/export', requireAuth, (_req, res) => {
    const secrets = loadSecrets();
    if (secrets.length === 0) return res.status(404).json({ error: 'No secrets to export' });
    const uris = secrets.map(s => {
      const digits = s.digits || 6;
      const period = s.period || 30;
      let uri = `otpauth://totp/${encodeURIComponent(s.name)}?secret=${s.secret}&issuer=${encodeURIComponent(s.name)}`;
      if (digits !== 6) uri += `&digits=${digits}`;
      if (period !== 30) uri += `&period=${period}`;
      return uri;
    });
    res.setHeader('Content-Type', 'text/plain; charset=utf-8');
    res.send(uris.join('\n'));
  });

  router.post('/import', requireAuth, (req, res) => {
    const { content, mode } = req.body;
    if (!content) return res.status(400).json({ error: 'content is required' });
    if (mode !== 'merge' && mode !== 'replace') {
      return res.status(400).json({ error: 'mode must be merge or replace' });
    }

    let lines = [];
    try {
      const parsed = JSON.parse(content);
      if (Array.isArray(parsed.entries)) {
        lines = parsed.entries
          .map(e => e?.content?.uri)
          .filter(u => typeof u === 'string' && u.startsWith('otpauth://totp/'));
      }
    } catch { /* not JSON — fall through to plain text */ }

    if (lines.length === 0) {
      lines = content.split(/\r?\n/).map(l => l.trim()).filter(l => l.startsWith('otpauth://totp/'));
    }
    if (lines.length === 0) return res.status(400).json({ error: 'No valid otpauth:// URIs found' });

    const imported = [];
    for (const line of lines) {
      try {
        const url    = new URL(line);
        const secret = url.searchParams.get('secret');
        if (!secret) continue;
        const rawLabel   = decodeURIComponent(url.pathname.replace(/^\//, ''));
        const issuer     = url.searchParams.get('issuer') || '';
        let account      = rawLabel;
        let labelIssuer  = '';
        if (rawLabel.includes(':')) {
          [labelIssuer, account] = rawLabel.split(/:(.+)/);
        }
        const effectiveIssuer  = issuer || labelIssuer;
        const effectiveAccount = (effectiveIssuer && account !== effectiveIssuer) ? account : '';
        const name   = effectiveIssuer || account || 'Unknown';
        const digits = parseInt(url.searchParams.get('digits') || '6');
        const period = parseInt(url.searchParams.get('period') || '30');
        const entry  = {
          id:      Date.now().toString() + Math.random().toString(36).slice(2, 6),
          name:    name.trim(),
          issuer:  name.trim(),
          account: effectiveAccount.trim(),
          secret:  secret.replace(/\s/g, '').toUpperCase(),
        };
        if (digits !== 6) entry.digits = digits;
        if (period !== 30) entry.period = period;
        imported.push(entry);
      } catch { /* skip malformed lines */ }
    }

    if (imported.length === 0) return res.status(400).json({ error: 'No valid entries could be parsed' });

    const existing        = mode === 'replace' ? [] : loadSecrets();
    const existingSecrets = new Set(existing.map(e => e.secret));
    const toAdd           = mode === 'replace' ? imported : imported.filter(e => !existingSecrets.has(e.secret));
    saveSecrets([...existing, ...toAdd]);
    res.json({ imported: toAdd.length, skipped: imported.length - toAdd.length });
  });

  return router;
};
