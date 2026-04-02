const RADIUS = 20;
const CIRC   = 2 * Math.PI * RADIUS;

let tokens = [];
let timeRemaining = 30;
let recoveryCodeValue = '';

// =====================
// VIEW MANAGEMENT
// =====================

function showView(id) {
  document.querySelectorAll('.auth-view').forEach(v => v.classList.remove('active'));
  if (id) document.getElementById(id).classList.add('active');
}

// =====================
// AUTH INIT
// =====================

async function initAuth() {
  try {
    // Clear any old session token left in localStorage (pre-fix sessions stored there)
    localStorage.removeItem('sk_session');

    // Try to resume an existing session first
    const saved = sessionStorage.getItem('sk_session');
    if (saved) {
      const res = await fetch('/api/auth/resume', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ sessionToken: saved }),
      });
      if (res.ok) {
        showView(null);
        fetchTokens();
        return;
      }
      // Session expired or invalid — clear it
      sessionStorage.removeItem('sk_session');
    }

    // Fall back to status check
    const res = await fetch('/api/auth/status');
    const { setup } = await res.json();
    if (!setup) {
      showView('view-setup');
      setTimeout(() => document.getElementById('setup-password').focus(), 100);
    } else {
      showView('view-login');
      setTimeout(() => document.getElementById('login-password').focus(), 100);
    }
  } catch {
    showView('view-login');
  }
}

// =====================
// SETUP
// =====================

async function doSetup() {
  const password = document.getElementById('setup-password').value;
  const confirm  = document.getElementById('setup-confirm').value;
  const errEl    = document.getElementById('setup-error');
  const btn      = document.getElementById('setup-btn');

  errEl.style.display = 'none';

  if (password.length < 8) {
    errEl.textContent = 'Password must be at least 8 characters.';
    errEl.style.display = 'block';
    return;
  }
  if (password !== confirm) {
    errEl.textContent = 'Passwords do not match.';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Creating...';

  try {
    const res = await fetch('/api/auth/setup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    const data = await res.json();

    if (!res.ok) {
      errEl.textContent = data.error || 'Setup failed.';
      errEl.style.display = 'block';
      return;
    }

    if (data.sessionToken) sessionStorage.setItem('sk_session', data.sessionToken);
    recoveryCodeValue = data.recoveryCode;
    document.getElementById('recovery-code-display').textContent = formatRecoveryCode(data.recoveryCode);
    document.getElementById('recovery-confirmed').checked = false;
    document.getElementById('recovery-continue-btn').disabled = true;
    showView('view-recovery-code');
  } catch {
    errEl.textContent = 'Connection error.';
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Create Password';
  }
}

function formatRecoveryCode(code) {
  return code.match(/.{1,8}/g).join('-');
}

async function copyRecovery() {
  try {
    await navigator.clipboard.writeText(recoveryCodeValue);
    const btn = document.getElementById('copy-recovery-btn');
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  } catch {
    showToast('Could not copy');
  }
}

function toggleContinueBtn() {
  const checked = document.getElementById('recovery-confirmed').checked;
  document.getElementById('recovery-continue-btn').disabled = !checked;
}

function onRecoveryContinue() {
  recoveryCodeValue = '';
  showView(null);
  fetchTokens();
}

// =====================
// LOGIN
// =====================

async function doLogin() {
  const password = document.getElementById('login-password').value;
  const errEl    = document.getElementById('login-error');
  const btn      = document.getElementById('login-btn');

  errEl.style.display = 'none';

  if (!password) {
    errEl.textContent = 'Password is required.';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Unlocking...';

  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password }),
    });
    const data = await res.json();

    if (!res.ok) {
      errEl.textContent = data.error || 'Login failed.';
      errEl.style.display = 'block';
      return;
    }

    document.getElementById('login-password').value = '';
    if (data.sessionToken) sessionStorage.setItem('sk_session', data.sessionToken);
    showView(null);
    fetchTokens();
  } catch {
    errEl.textContent = 'Connection error.';
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Unlock';
  }
}

// =====================
// RECOVER
// =====================

async function doRecover() {
  const recoveryCode = document.getElementById('recover-code').value.replace(/[^a-fA-F0-9]/g, '');
  const newPassword  = document.getElementById('recover-password').value;
  const errEl        = document.getElementById('recover-error');
  const btn          = document.getElementById('recover-btn');

  errEl.style.display = 'none';

  if (!recoveryCode || !newPassword) {
    errEl.textContent = 'All fields are required.';
    errEl.style.display = 'block';
    return;
  }
  if (newPassword.length < 8) {
    errEl.textContent = 'Password must be at least 8 characters.';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Recovering...';

  try {
    const res = await fetch('/api/auth/recover', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ recoveryCode, newPassword }),
    });
    const data = await res.json();

    if (!res.ok) {
      errEl.textContent = data.error || 'Recovery failed.';
      errEl.style.display = 'block';
      return;
    }

    document.getElementById('recover-code').value = '';
    document.getElementById('recover-password').value = '';
    if (data.sessionToken) sessionStorage.setItem('sk_session', data.sessionToken);
    showView(null);
    fetchTokens();
  } catch {
    errEl.textContent = 'Connection error.';
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
    btn.textContent = 'Reset Password';
  }
}

// =====================
// LOGOUT
// =====================

async function doLogout() {
  const sessionToken = sessionStorage.getItem('sk_session');
  sessionStorage.removeItem('sk_session');
  await fetch('/api/auth/logout', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ sessionToken }),
  });
  tokens = [];
  renderTokens();
  showView('view-login');
  setTimeout(() => document.getElementById('login-password').focus(), 100);
}

// =====================
// TOKENS
// =====================

async function fetchTokens() {
  try {
    const res = await fetch('/api/tokens');
    if (res.status === 401) {
      if (!document.querySelector('.auth-view.active')) showView('view-login');
      return;
    }
    const data = await res.json();
    tokens        = data.tokens;
    timeRemaining = data.timeRemaining;
    renderTokens();
  } catch {
    // silent
  }
}

function renderTokens() {
  const list = document.getElementById('tokens-list');

  if (tokens.length === 0) {
    list.innerHTML = '<div class="empty-state">No tokens yet. Tap Add to get started.</div>';
    return;
  }

  list.innerHTML = tokens.map(t => {
    const tr        = t.timeRemaining;
    const pct       = tr / (t.period || 30);
    const offset    = CIRC * (1 - pct);
    const ringClass = tr <= 5 ? 'danger' : tr <= 10 ? 'warn' : '';
    const code      = t.token || 'ERROR';
    const codeClass = t.token ? '' : 'invalid';
    const formatted = t.token ? t.token.slice(0,3) + ' ' + t.token.slice(3) : 'Invalid';
    const nextFmt   = t.nextToken ? t.nextToken.slice(0,3) + ' ' + t.nextToken.slice(3) : '—';

    return `
      <div class="token-card" id="card-${t.id}">
        <div class="ring-wrap">
          <svg width="48" height="48" viewBox="0 0 48 48">
            <circle class="ring-bg" cx="24" cy="24" r="${RADIUS}" />
            <circle class="ring-fg ${ringClass}" cx="24" cy="24" r="${RADIUS}"
              stroke-dasharray="${CIRC}" stroke-dashoffset="${offset}" />
          </svg>
          <div class="ring-text">${tr}</div>
        </div>
        <div class="token-info">
          <div class="token-issuer">${escHtml(t.issuer)}</div>
          ${t.account ? `<div class="token-account">${escHtml(t.account)}</div>` : ''}
          <div class="token-code ${codeClass}" title="Click to copy"
               onclick="copyToken('${t.id}', '${code}', this)">${formatted}</div>
          <div class="token-next">next: ${nextFmt}</div>
        </div>
        <button class="delete-btn" title="Delete" onclick="deleteToken('${t.id}')">&#x2715;</button>
      </div>
    `;
  }).join('');
}

function updateCountdown() {
  const sec = 30 - (Math.floor(Date.now() / 1000) % 30);
  if (sec !== timeRemaining) {
    timeRemaining = sec;
    if (sec === 30) { fetchTokens(); return; }
    const now = Math.floor(Date.now() / 1000);
    tokens = tokens.map(t => ({
      ...t,
      timeRemaining: (t.period || 30) - (now % (t.period || 30)),
    }));
    renderTokens();
  }
}

async function copyToken(id, code, el) {
  if (!code || code === 'ERROR') return;
  try {
    await navigator.clipboard.writeText(code);
    el.classList.add('copied');
    el.textContent = 'Copied!';
    setTimeout(() => {
      el.classList.remove('copied');
      const t = tokens.find(x => x.id === id);
      if (t && t.token) el.textContent = t.token.slice(0,3) + ' ' + t.token.slice(3);
    }, 1200);
  } catch {
    showToast('Could not copy');
  }
}

async function addToken() {
  const name   = document.getElementById('inp-name').value.trim();
  const secret = document.getElementById('inp-secret').value.trim();
  const errEl  = document.getElementById('form-error');
  const btn    = document.getElementById('add-btn');

  errEl.style.display = 'none';

  if (!name || !secret) {
    errEl.textContent = 'Name and secret are required.';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled = true;

  try {
    const account = document.getElementById('inp-account').value.trim();
    const res = await fetch('/api/secrets', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, secret, issuer: name, account }),
    });
    const data = await res.json();

    if (!res.ok) {
      errEl.textContent = data.error || 'Failed to add token.';
      errEl.style.display = 'block';
      return;
    }

    document.getElementById('inp-name').value    = '';
    document.getElementById('inp-account').value = '';
    document.getElementById('inp-secret').value  = '';
    closeModal();
    showToast('Token added');
    await fetchTokens();
  } catch {
    errEl.textContent = 'Connection error.';
    errEl.style.display = 'block';
  } finally {
    btn.disabled = false;
  }
}

async function deleteToken(id) {
  if (!confirm('Delete this token?')) return;
  try {
    await fetch(`/api/secrets/${id}`, { method: 'DELETE' });
    await fetchTokens();
  } catch {
    showToast('Failed to delete token');
  }
}

async function exportTokens() {
  if (tokens.length === 0) { showToast('No tokens to export'); return; }
  try {
    const res = await fetch('/api/export');
    if (!res.ok) { showToast('Export failed'); return; }
    const text = await res.text();
    const blob = new Blob([text], { type: 'text/plain' });
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement('a');
    a.href     = url;
    a.download = 'softkey-export.txt';
    a.click();
    URL.revokeObjectURL(url);
    showToast(`Exported ${tokens.length} token${tokens.length !== 1 ? 's' : ''}`);
  } catch {
    showToast('Export failed');
  }
}

// =====================
// IMPORT MODAL
// =====================

function openImportModal() {
  document.getElementById('import-overlay').classList.add('open');
  document.getElementById('import-content').value = '';
  document.getElementById('import-file').value    = '';
  document.getElementById('import-preview').textContent = '';
  document.getElementById('import-error').style.display = 'none';
  document.querySelector('input[name="import-mode"][value="merge"]').checked = true;
}

function closeImportModal() {
  document.getElementById('import-overlay').classList.remove('open');
}

function handleImportOverlayClick(e) {
  if (e.target === document.getElementById('import-overlay')) closeImportModal();
}

function onImportFile(event) {
  const file = event.target.files[0];
  if (!file) return;
  const reader = new FileReader();
  reader.onload = e => {
    document.getElementById('import-content').value = e.target.result;
    updateImportPreview();
  };
  reader.readAsText(file);
}

function updateImportPreview() {
  const content = document.getElementById('import-content').value.trim();
  const preview = document.getElementById('import-preview');
  if (!content) { preview.textContent = ''; return; }

  let count = 0;
  try {
    const parsed = JSON.parse(content);
    if (Array.isArray(parsed.entries)) {
      count = parsed.entries.filter(e => e?.content?.uri?.startsWith('otpauth://totp/')).length;
    }
  } catch { /* plain text */ }
  if (count === 0) count = content.split(/\r?\n/).filter(l => l.trim().startsWith('otpauth://totp/')).length;

  if (count === 0) {
    preview.textContent = 'No valid otpauth:// URIs found.';
    preview.style.color = 'var(--danger)';
  } else {
    preview.textContent = `${count} token${count !== 1 ? 's' : ''} found`;
    preview.style.color = 'var(--success)';
  }
}

async function doImport() {
  const content = document.getElementById('import-content').value.trim();
  const mode    = document.querySelector('input[name="import-mode"]:checked').value;
  const errEl   = document.getElementById('import-error');
  const btn     = document.getElementById('import-btn');

  errEl.style.display = 'none';

  if (!content) {
    errEl.textContent = 'Paste content or select a file.';
    errEl.style.display = 'block';
    return;
  }

  btn.disabled    = true;
  btn.textContent = 'Importing...';

  try {
    const res = await fetch('/api/import', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ content, mode }),
    });
    const data = await res.json();

    if (!res.ok) {
      errEl.textContent = data.error || 'Import failed.';
      errEl.style.display = 'block';
      return;
    }

    closeImportModal();
    let msg = `Imported ${data.imported} token${data.imported !== 1 ? 's' : ''}`;
    if (data.skipped > 0) msg += ` (${data.skipped} duplicate${data.skipped !== 1 ? 's' : ''} skipped)`;
    showToast(msg);
    await fetchTokens();
  } catch {
    errEl.textContent = 'Connection error.';
    errEl.style.display = 'block';
  } finally {
    btn.disabled    = false;
    btn.textContent = 'Import';
  }
}

// =====================
// SETTINGS MODAL
// =====================

function openSettingsModal() {
  renderAutolockOptions();
  document.getElementById('settings-overlay').classList.add('open');
}

function closeSettingsModal() {
  document.getElementById('settings-overlay').classList.remove('open');
}

function handleSettingsOverlayClick(e) {
  if (e.target === document.getElementById('settings-overlay')) closeSettingsModal();
}

function renderAutolockOptions() {
  const current = getAutolockMin();
  document.querySelectorAll('.autolock-opt').forEach(btn => {
    btn.classList.toggle('active', parseInt(btn.dataset.min) === current);
  });
  updateAutolockHint(current);
}

function setAutolock(minutes) {
  localStorage.setItem('sk_autolock', minutes);
  renderAutolockOptions();
  resetAutolockTimer();
}

function getAutolockMin() {
  const v = localStorage.getItem('sk_autolock');
  return v === null ? 5 : parseInt(v);
}

function updateAutolockHint(minutes) {
  const hint = document.getElementById('autolock-hint');
  hint.textContent = minutes === 0
    ? 'The app will never lock automatically.'
    : `The app will lock after ${minutes} minute${minutes !== 1 ? 's' : ''} of inactivity.`;
}

// =====================
// AUTO-LOCK TIMER
// =====================

let autolockTimer = null;

function resetAutolockTimer() {
  if (autolockTimer) { clearTimeout(autolockTimer); autolockTimer = null; }
  const minutes = getAutolockMin();
  if (minutes === 0) return;
  autolockTimer = setTimeout(() => {
    if (!document.querySelector('.auth-view.active')) {
      showToast('Locked due to inactivity');
      setTimeout(doLogout, 800);
    }
  }, minutes * 60 * 1000);
}

['mousemove', 'mousedown', 'keydown', 'touchstart', 'scroll', 'click'].forEach(evt => {
  document.addEventListener(evt, resetAutolockTimer, { passive: true });
});

// =====================
// MODAL
// =====================

function openModal() {
  document.getElementById('modal-overlay').classList.add('open');
  setTimeout(() => document.getElementById('inp-name').focus(), 300);
}

function closeModal() {
  document.getElementById('modal-overlay').classList.remove('open');
  document.getElementById('form-error').style.display = 'none';
}

function handleOverlayClick(e) {
  if (e.target === document.getElementById('modal-overlay')) closeModal();
}

// =====================
// UTILS
// =====================

function showToast(msg) {
  const t = document.getElementById('toast');
  t.textContent = msg;
  t.classList.add('show');
  setTimeout(() => t.classList.remove('show'), 2000);
}

function escHtml(str) {
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

document.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closeModal(); closeImportModal(); closeSettingsModal(); }
  if (e.key === 'Enter') {
    const id = document.activeElement.id;
    if (id === 'inp-name' || id === 'inp-secret')                  addToken();
    else if (id === 'setup-password' || id === 'setup-confirm')    doSetup();
    else if (id === 'login-password')                              doLogin();
    else if (id === 'recover-code' || id === 'recover-password')   doRecover();
  }
});

// =====================
// START
// =====================
initAuth();
setInterval(updateCountdown, 500);
setInterval(fetchTokens, 30000);
resetAutolockTimer();
