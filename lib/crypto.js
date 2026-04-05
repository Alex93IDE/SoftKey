const crypto = require('crypto');

const PBKDF2_ITER = 300000;
const KEY_LEN = 32;

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
    iv: iv.toString('hex'),
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

module.exports = { deriveKey, aesEncrypt, aesDecrypt };
