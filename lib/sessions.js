const fs = require('fs');
const crypto = require('crypto');
const { aesEncrypt, aesDecrypt } = require('./crypto');

const SESSION_MS = 30 * 24 * 60 * 60 * 1000;

function loadSessions(sessionFile) {
  if (!fs.existsSync(sessionFile)) return [];
  try { return JSON.parse(fs.readFileSync(sessionFile, 'utf-8')); } catch { return []; }
}

function saveSessions(sessionFile, sessions) {
  fs.writeFileSync(sessionFile, JSON.stringify(sessions, null, 2));
}

function createSession(sessionFile, key) {
  const tokenBuf = crypto.randomBytes(32);
  const tokenHex = tokenBuf.toString('hex');
  const tokenHash = crypto.createHash('sha256').update(tokenBuf).digest('hex');
  const encrypted = aesEncrypt(key, tokenBuf);

  const sessions = loadSessions(sessionFile).filter(s => s.expiresAt > Date.now());
  sessions.push({ tokenHash, encrypted, expiresAt: Date.now() + SESSION_MS });
  saveSessions(sessionFile, sessions);
  return tokenHex;
}

function resumeSession(sessionFile, tokenHex) {
  const tokenBuf = Buffer.from(tokenHex, 'hex');
  const tokenHash = crypto.createHash('sha256').update(tokenBuf).digest('hex');
  const sessions = loadSessions(sessionFile);
  const session = sessions.find(s => s.tokenHash === tokenHash && s.expiresAt > Date.now());
  if (!session) return null;
  return aesDecrypt(session.encrypted, tokenBuf);
}

function deleteSession(sessionFile, tokenHex) {
  const tokenBuf = Buffer.from(tokenHex, 'hex');
  const tokenHash = crypto.createHash('sha256').update(tokenBuf).digest('hex');
  const sessions = loadSessions(sessionFile).filter(s => s.tokenHash !== tokenHash);
  saveSessions(sessionFile, sessions);
}

module.exports = { createSession, resumeSession, deleteSession };
