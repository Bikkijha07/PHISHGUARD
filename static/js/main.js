/**
 * PhishGuard — Main JavaScript
 * Handles API calls, result rendering, animations
 */

// ── Particles ──────────────────────────────────────────
function initParticles() {
  const container = document.getElementById('particles');
  const count = 25;
  for (let i = 0; i < count; i++) {
    const p = document.createElement('div');
    p.className = 'particle';
    p.style.left = `${Math.random() * 100}%`;
    p.style.width = `${Math.random() * 3 + 1}px`;
    p.style.height = p.style.width;
    p.style.animationDuration = `${Math.random() * 15 + 8}s`;
    p.style.animationDelay = `${Math.random() * 10}s`;
    container.appendChild(p);
  }
}

// ── Stats Loader ────────────────────────────────────────
async function loadStats() {
  try {
    const res = await fetch('/api/stats');
    const data = await res.json();
    document.getElementById('statTotal').textContent = data.total_scans;
    document.getElementById('statPhishing').textContent = data.phishing_detected;
    document.getElementById('statSuspicious').textContent = data.suspicious_detected;
    document.getElementById('statSafe').textContent = data.safe_detected;
  } catch (e) { /* silent */ }
}

// ── History Loader ──────────────────────────────────────
async function loadHistory() {
  try {
    const res = await fetch('/api/history');
    const data = await res.json();
    renderHistory(data.history || []);
  } catch (e) { /* silent */ }
}

function renderHistory(history) {
  const container = document.getElementById('historyList');
  if (!history.length) {
    container.innerHTML = '<div class="history-empty">🔍 No scans yet. Paste a URL above to get started.</div>';
    return;
  }
  container.innerHTML = history.map(item => {
    const verdictClass = item.verdict === 'PHISHING' ? 'danger' : item.verdict === 'SUSPICIOUS' ? 'warning' : 'safe';
    return `
      <div class="history-item" onclick="reuseUrl('${escapeHtml(item.url)}')">
        <div class="history-verdict-dot" style="background:${item.color}; --dot-color:${item.color}"></div>
        <span class="history-url" title="${escapeHtml(item.url)}">${escapeHtml(item.url)}</span>
        <span class="history-score" style="color:${item.color}">${item.score}</span>
        <span class="history-verdict feature-badge ${verdictClass}">${item.icon} ${item.verdict}</span>
        <span class="history-time">${item.timestamp}</span>
      </div>
    `;
  }).join('');
}

function reuseUrl(url) {
  document.getElementById('urlInput').value = url;
  document.getElementById('urlInput').focus();
  showToast('📋 URL loaded — click Scan to re-analyze');
}

// ── URL Validation ──────────────────────────────────────
function isValidUrl(url) {
  return url.trim().length > 3;
}

// ── Main Scan Function ──────────────────────────────────
async function scanUrl() {
  const input = document.getElementById('urlInput');
  const url = input.value.trim();

  if (!url) {
    showToast('⚠️ Please enter a URL to scan', true);
    input.focus();
    return;
  }

  if (!isValidUrl(url)) {
    showToast('⚠️ Enter a valid URL', true);
    return;
  }

  // UI: Start loading
  const btn = document.getElementById('scanBtn');
  const btnText = document.getElementById('btnText');
  const btnIcon = document.getElementById('btnIcon');
  const spinner = document.getElementById('btnSpinner');
  const scanProgress = document.getElementById('scanProgress');
  const scanStatus = document.getElementById('scanStatus');

  btn.disabled = true;
  btnText.textContent = 'Scanning...';
  btnIcon.style.display = 'none';
  spinner.style.display = 'block';
  scanProgress.classList.add('active');

  const statusMessages = [
    '🔍 Extracting URL features...',
    '🧠 Analyzing domain structure...',
    '🛡️ Checking security rules...',
    '📊 Calculating risk score...',
  ];
  let msgIdx = 0;
  const msgInterval = setInterval(() => {
    scanStatus.textContent = statusMessages[msgIdx % statusMessages.length];
    msgIdx++;
  }, 400);

  try {
    const res = await fetch('/api/analyze', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url })
    });

    const data = await res.json();

    if (data.error) {
      showToast(`❌ ${data.error}`, true);
      return;
    }

    renderResults(data);
    await loadStats();
    await loadHistory();
  } catch (err) {
    showToast('❌ Connection error. Is the server running?', true);
    console.error(err);
  } finally {
    clearInterval(msgInterval);
    btn.disabled = false;
    btnText.textContent = 'Scan URL';
    btnIcon.style.display = '';
    spinner.style.display = 'none';
    scanProgress.classList.remove('active');
    scanStatus.textContent = '';
  }
}

// ── Render Results ──────────────────────────────────────
function renderResults(data) {
  const section = document.getElementById('resultsSection');
  const { url, score, risk, features, red_flags } = data;

  // Scanned URL display
  document.getElementById('scannedUrl').textContent = url;

  // Verdict card
  const verdictCard = document.getElementById('verdictCard');
  verdictCard.style.cssText = `
    border-color: ${risk.color};
    --verdict-color: ${risk.color};
    background: linear-gradient(135deg, var(--bg-card), rgba(${hexToRgb(risk.color)}, 0.05));
    box-shadow: 0 0 40px rgba(${hexToRgb(risk.color)}, 0.08);
  `;
  document.getElementById('verdictIcon').textContent = risk.icon;
  document.getElementById('verdictLabel').textContent = risk.label;
  document.getElementById('verdictLabel').style.color = risk.color;
  document.getElementById('verdictMessage').textContent = risk.message;

  const rec = document.getElementById('verdictRecommendation');
  rec.textContent = risk.recommendation;
  rec.style.borderLeftColor = risk.color;
  rec.style.background = `rgba(${hexToRgb(risk.color)}, 0.06)`;
  rec.style.color = risk.color;

  // Gauge
  animateGauge(score, risk.color);

  // Features list
  renderFeatures(features);

  // Red flags
  renderRedFlags(red_flags);

  // Show section
  section.classList.add('active');
  section.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

// ── Gauge Animation ─────────────────────────────────────
function animateGauge(score, color) {
  const fill = document.getElementById('gaugeFill');
  const scoreText = document.getElementById('gaugeScore');
  const totalCircum = 251;
  const offset = totalCircum - (totalCircum * score / 100);

  fill.style.stroke = color;
  fill.style.filter = `drop-shadow(0 0 6px ${color})`;

  // Animate score counter
  let current = 0;
  const duration = 1500;
  const step = score / (duration / 16);
  const counter = setInterval(() => {
    current = Math.min(current + step, score);
    scoreText.textContent = Math.round(current);
    if (current >= score) clearInterval(counter);
  }, 16);

  // Animate fill
  requestAnimationFrame(() => {
    fill.style.strokeDashoffset = totalCircum; // reset
    requestAnimationFrame(() => {
      fill.style.strokeDashoffset = offset;
    });
  });
}

// ── Render Feature List ─────────────────────────────────
function renderFeatures(features) {
  const container = document.getElementById('featureList');
  container.innerHTML = '';

  Object.entries(features).forEach(([key, feat]) => {
    const isSuspicious = feat.suspicious;
    const weight = feat.weight || 0;

    let badgeClass = 'safe';
    let badgeText = '✓ OK';
    if (isSuspicious && weight >= 4) { badgeClass = 'danger'; badgeText = '✗ HIGH'; }
    else if (isSuspicious && weight >= 2) { badgeClass = 'danger'; badgeText = '✗ RISK'; }
    else if (isSuspicious) { badgeClass = 'warning'; badgeText = '⚠ LOW'; }

    const item = document.createElement('div');
    item.className = 'feature-item';
    item.innerHTML = `
      <div class="feature-info">
        <div class="feature-name">${escapeHtml(feat.label)}</div>
        <div class="feature-desc" title="${escapeHtml(feat.description)}">${escapeHtml(feat.description)}</div>
      </div>
      <div class="feature-badge ${badgeClass}">${badgeText}</div>
    `;
    container.appendChild(item);
  });
}

// ── Render Red Flags ────────────────────────────────────
function renderRedFlags(redFlags) {
  const container = document.getElementById('redFlagsList');
  container.innerHTML = '';

  if (!redFlags || redFlags.length === 0) {
    container.innerHTML = `
      <div class="no-flags">
        <span class="emoji">🛡️</span>
        No significant red flags detected!
      </div>`;
    return;
  }

  redFlags.forEach(flag => {
    const div = document.createElement('div');
    div.className = 'red-flag-item';
    div.innerHTML = `
      <div class="red-flag-icon">🚩</div>
      <div>
        <div class="red-flag-label">${escapeHtml(flag.label)}</div>
        <div class="red-flag-desc">${escapeHtml(flag.description)}</div>
      </div>
      <div class="weight-badge">+${flag.weight} pts</div>
    `;
    container.appendChild(div);
  });
}

// ── Quick Example Buttons ───────────────────────────────
function setExample(url) {
  document.getElementById('urlInput').value = url;
  document.getElementById('urlInput').focus();
}

// ── Toast ───────────────────────────────────────────────
let toastTimer;
function showToast(msg, isError = false) {
  const toast = document.getElementById('toast');
  toast.textContent = msg;
  toast.style.borderColor = isError ? 'rgba(255,23,68,0.4)' : 'rgba(0,200,255,0.35)';
  toast.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.remove('show'), 3500);
}

// ── Helpers ─────────────────────────────────────────────
function escapeHtml(str) {
  if (typeof str !== 'string') str = String(str);
  return str.replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function hexToRgb(hex) {
  const r = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
  return r ? `${parseInt(r[1],16)}, ${parseInt(r[2],16)}, ${parseInt(r[3],16)}` : '0,200,255';
}

// ── Keyboard Support ────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  initParticles();
  loadStats();
  loadHistory();

  document.getElementById('urlInput').addEventListener('keydown', (e) => {
    if (e.key === 'Enter') scanUrl();
  });

  // Auto-refresh stats every 10s
  setInterval(() => { loadStats(); loadHistory(); }, 10000);
});
