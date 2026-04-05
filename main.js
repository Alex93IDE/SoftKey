const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3333;
const DATA_DIR = process.env.DATA_DIR || __dirname;

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.use('/api/auth', require('./routes/auth')(DATA_DIR));
app.use('/api', require('./routes/tokens')(DATA_DIR));

app.get('/', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Softkey running on http://localhost:${PORT}`);
});
