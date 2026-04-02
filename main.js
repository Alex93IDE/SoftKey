const express = require('express');
const { generateSync, createGuardrails } = require('otplib');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = 3333;
const SECRETS_FILE = path.join(__dirname, 'secrets.json');

app.use(express.json());
app.use(express.static(__dirname));

// --- Helpers ---

function loadSecrets() {
  if (!fs.existsSync(SECRETS_FILE)) return [];
  try {
    return JSON.parse(fs.readFileSync(SECRETS_FILE, 'utf-8'));
  } catch {
    return [];
  }
}

function saveSecrets(secrets) {
  fs.writeFileSync(SECRETS_FILE, JSON.stringify(secrets, null, 2));
}

function generateToken(secret) {
  try {
    return generateSync({ secret, guardrails: createGuardrails({ MIN_SECRET_BYTES: 1 }) });
  } catch {
    return null;
  }
}

// --- API ---

// GET all tokens (name + current code + time remaining)
app.get('/api/tokens', (_req, res) => {
  const secrets = loadSecrets();
  const timeRemaining = 30 - (Math.floor(Date.now() / 1000) % 30);

  const tokens = secrets.map(entry => ({
    id: entry.id,
    name: entry.name,
    token: generateToken(entry.secret),
    timeRemaining,
    period: 30,
  }));

  res.json({ tokens, timeRemaining });
});

// POST add a new secret
app.post('/api/secrets', (req, res) => {
  const { name, secret } = req.body;

  if (!name || !secret) {
    return res.status(400).json({ error: 'name and secret are required' });
  }

  const secrets = loadSecrets();
  const newEntry = {
    id: Date.now().toString(),
    name: name.trim(),
    secret: secret.replace(/\s/g, '').toUpperCase(),
  };

  secrets.push(newEntry);
  saveSecrets(secrets);

  res.json({ success: true, id: newEntry.id });
});

// DELETE a secret by id
app.delete('/api/secrets/:id', (req, res) => {
  const secrets = loadSecrets();
  const filtered = secrets.filter(e => e.id !== req.params.id);

  if (filtered.length === secrets.length) {
    return res.status(404).json({ error: 'Not found' });
  }

  saveSecrets(filtered);
  res.json({ success: true });
});

// Serve frontend
app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Softkey corriendo en http://localhost:${PORT}`);
});
