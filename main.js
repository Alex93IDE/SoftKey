const express = require('express');
const path = require('path');
const { version } = require('./package.json');

const app = express();
const PORT = process.env.PORT || 3333;
const DATA_DIR = process.env.DATA_DIR || __dirname;

// When this process started, as one number: YYYYMMDDHHmm. There is no build
// step, so the start time stands in for the build date: an update only takes
// effect after a restart, so comparing it before and after shows it went in.
function startStamp() {
  const d = new Date();
  const two = (n) => String(n).padStart(2, '0');
  return `${d.getFullYear()}${two(d.getMonth() + 1)}${two(d.getDate())}`
    + `${two(d.getHours())}${two(d.getMinutes())}`;
}
const STARTED = startStamp();

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Public on purpose: the login screen shows it before there is a session.
app.get('/api/version', (_req, res) => {
  res.json({ version, started: STARTED });
});

app.use('/api/auth', require('./routes/auth')(DATA_DIR));
app.use('/api', require('./routes/tokens')(DATA_DIR));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Softkey running on http://localhost:${PORT}`);
});
