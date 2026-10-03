'use strict';

const $ = (id) => document.getElementById(id);
const SEVS = ['critical', 'high', 'medium', 'low', 'info'];

let state = null;
const filters = { text: '', sev: '', scope: '', newOnly: false };
const expanded = new Set();

/* ---------- helpers ---------- */

function esc(s) {
  return String(s ?? '').replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

// Rating colour: the same thresholds everywhere so a number always reads the
// same way.
function scoreColor(n) {
  if (n >= 85) return 'var(--good)';
  if (n >= 60) return 'var(--medium)';
  if (n >= 35) return 'var(--high)';
  return 'var(--critical)';
}

function ago(iso) {
  if (!iso) return 'never';
  const secs = (Date.now() - new Date(iso).getTime()) / 1000;
  if (secs < 90) return 'just now';
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

function chips(counts) {
  const parts = SEVS
    .filter((s) => (counts?.[s] || 0) > 0)
    .map((s) => `<span class="chip chip-${s}">${counts[s]} ${s.slice(0, 4)}</span>`);
  return parts.length ? parts.join('') : '<span class="chip chip-clean">clean</span>';
}

// Severity mix rendered as a single proportional bar.
function bars(counts) {
  const total = SEVS.reduce((a, s) => a + (counts?.[s] || 0), 0);
  if (!total) return `<span style="width:100%;background:var(--good)"></span>`;
  return SEVS.filter((s) => counts[s] > 0)
    .map((s) => `<span style="width:${(counts[s] / total) * 100}%;background:var(--${s})"></span>`)
    .join('');
}

/* ---------- rendering ---------- */

function render() {
  const sc = state?.scan;
  renderBanner();
  if (!sc) {
    $('subtitle').textContent = 'no scan yet';
    return;
  }
  $('subtitle').textContent =
    `${sc.facts?.containers || 0} containers · ${sc.facts?.projects || 0} projects · ` +
    `${sc.facts?.mode || ''} scan ${ago(sc.startedAt)} · ${(sc.durationMs / 1000).toFixed(1)}s`;
  $('rating-num').textContent = sc.score;
  $('rating-num').style.color = scoreColor(sc.score);
  $('report').textContent = sc.report || '—';

  renderAlerts(sc);
  renderDomains(sc);
  renderAgents(sc);
  renderSuggestions(sc);
  renderProjects(sc);
  renderScopeFilter(sc);
  renderFindings(sc);

  const resolved = sc.resolved ? ` · ${sc.resolved} resolved since last scan` : '';
  const isnew = sc.newCount ? ` · ${sc.newCount} new` : '';
  $('foot-info').textContent = `Scan ${sc.id}${isnew}${resolved}`;
}

function renderBanner() {
  const b = $('banner');
  if (state?.running) {
    b.className = 'banner busy';
    b.textContent = `Scan running — ${state.progress || 'working'}… this page updates when it finishes.`;
  } else if (state?.error) {
    b.className = 'banner err';
    b.textContent = state.error;
  } else {
    b.className = 'banner hidden';
  }
}

function renderAlerts(sc) {
  const alerts = sc.alerts || [];
  const sec = $('alerts-section');
  if (!alerts.length) { sec.classList.add('hidden'); return; }
  sec.classList.remove('hidden');
  const crit = alerts.filter((a) => a.severity === 'critical').length;
  $('alerts-count').textContent = `${crit} critical, ${alerts.length - crit} high`;
  $('alerts').innerHTML = alerts.slice(0, 8).map((f) => `
    <div class="alert">
      <span class="dot dot-${f.severity}"></span>
      <div class="alert-body">
        <div class="alert-title">${esc(f.title)}${f.new ? ' <span class="badge-new">NEW</span>' : ''}</div>
        <div class="alert-meta">${esc(f.target)} · ${esc(f.scopeKey)} · found by ${esc(f.agent)}</div>
      </div>
      <button class="btn btn-sm" data-jump="${f.id}">Details</button>
    </div>`).join('');
}

function renderDomains(sc) {
  // Projects domain aggregates every project finding.
  const pc = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  let worst = null;
  for (const p of sc.projects || []) {
    for (const s of SEVS) pc[s] += p.counts?.[s] || 0;
    if (!worst || p.score < worst.score) worst = p;
  }
  const pscore = Math.min(...[100, ...(sc.projects || []).map((p) => p.score)]);
  $('projects-score').textContent = isFinite(pscore) ? pscore : '—';
  $('projects-score').style.color = scoreColor(pscore);
  $('projects-sub').textContent = worst
    ? `${(sc.projects || []).length} stacks · weakest: ${worst.key} (${worst.score}/100)`
    : 'no projects found';
  $('projects-bars').innerHTML = bars(pc);

  for (const [key, data] of [['machine', sc.machine], ['network', sc.network]]) {
    const total = SEVS.reduce((a, s) => a + (data?.counts?.[s] || 0), 0);
    $(`${key}-score`).textContent = data?.score ?? '—';
    $(`${key}-score`).style.color = scoreColor(data?.score ?? 100);
    $(`${key}-sub`).textContent = total
      ? `${total} finding${total === 1 ? '' : 's'}`
      : 'no findings';
    $(`${key}-bars`).innerHTML = bars(data?.counts);
  }
}

function renderAgents(sc) {
  const agents = sc.agents || [];
  const ok = agents.filter((a) => a.status === 'ok').length;
  $('agents-sub').textContent = `${ok}/${agents.length} reporting · ${agents.reduce((a, x) => a + x.checks, 0)} checks run`;
  $('agents').innerHTML = agents.map((a) => `
    <div class="agent ${esc(a.status)}">
      <div class="agent-top">
        <span class="agent-name">${esc(a.title)}</span>
        <span class="agent-status">${esc(a.status)}</span>
      </div>
      <div class="agent-role">${esc(a.role)}</div>
      <div class="agent-stats">${a.findings} findings · ${a.checks} checks · ${a.durationMs}ms</div>
      ${a.message ? `<div class="agent-stats" style="margin-top:4px">${esc(a.message)}</div>` : ''}
    </div>`).join('');
}

function renderSuggestions(sc) {
  const ss = sc.suggestions || [];
  if (!ss.length) { $('suggestions-card').classList.add('hidden'); return; }
  $('suggestions-card').classList.remove('hidden');
  $('suggestions').innerHTML = ss.slice(0, 8).map((s, i) => `
    <li class="suggestion">
      <span class="num">${i + 1}</span>
      <div>
        <h4>${esc(s.title)}</h4>
        <p>${esc(s.why)}</p>
        ${s.action ? `<p><strong>Do:</strong> ${esc(s.action)}</p>` : ''}
        ${s.cmd ? `<div class="cmd"><code>${esc(s.cmd)}</code>
          <div class="cmd-actions"><button class="btn btn-sm" data-copy="${esc(s.cmd)}">Copy</button></div></div>` : ''}
        <div class="chips"><span class="tag">${esc(s.effort)}</span>${s.scopeKey ? `<span class="tag">${esc(s.scopeKey)}</span>` : ''}</div>
      </div>
    </li>`).join('');
}

function renderProjects(sc) {
  const ps = sc.projects || [];
  $('projects-count').textContent = `${ps.length} compose stacks`;
  $('project-grid').innerHTML = ps.map((p) => `
    <button class="project ${filters.scope === p.key ? 'active' : ''}" data-project="${esc(p.key)}">
      <div class="project-top">
        <span class="project-name" title="${esc(p.key)}">${esc(p.key)}</span>
        <span class="project-score" style="color:${scoreColor(p.score)}">${p.score}</span>
      </div>
      <div class="project-meta">${(p.items || []).length} container${(p.items || []).length === 1 ? '' : 's'}</div>
      <div class="chips">${chips(p.counts)}</div>
    </button>`).join('');
}

function renderScopeFilter(sc) {
  const sel = $('scope-filter');
  const keys = [...new Set((sc.findings || []).map((f) => f.scopeKey))].sort();
  const current = sel.value;
  sel.innerHTML = '<option value="">All scopes</option>' +
    keys.map((k) => `<option value="${esc(k)}">${esc(k)}</option>`).join('');
  sel.value = filters.scope || current || '';
}

function matches(f) {
  if (filters.sev && f.severity !== filters.sev) return false;
  if (filters.scope && f.scopeKey !== filters.scope) return false;
  if (filters.newOnly && !f.new) return false;
  if (filters.text) {
    const hay = `${f.title} ${f.detail} ${f.target} ${f.scopeKey} ${f.agent} ${f.rule}`.toLowerCase();
    if (!hay.includes(filters.text.toLowerCase())) return false;
  }
  return true;
}

function renderFindings(sc) {
  const list = (sc.findings || []).filter(matches);
  if (!list.length) {
    $('findings').innerHTML = `<div class="empty">No findings match these filters.</div>`;
    return;
  }
  $('findings').innerHTML = list.map((f) => {
    const open = expanded.has(f.id);
    const canApply = state?.fixesEnabled && f.fixApply && f.fixCmd;
    return `
    <div class="finding" id="f-${f.id}">
      <button class="finding-head" data-toggle="${f.id}">
        <span class="sev sev-${f.severity}">${f.severity}</span>
        <span class="finding-title">${esc(f.title)}
          ${f.new ? '<span class="badge-new">NEW</span>' : ''}
          <span class="finding-target">· ${esc(f.target)}</span>
        </span>
        <span class="caret">${open ? '▲' : '▼'}</span>
      </button>
      ${open ? `
      <div class="finding-body">
        <p>${esc(f.detail)}</p>
        ${f.fix ? `<div><div class="fix-label">Recommended fix</div><p style="margin:0">${esc(f.fix)}</p></div>` : ''}
        ${f.fixCmd ? `
          <div>
            <div class="fix-label">${canApply ? 'Command (can be applied from here)' : 'Command'}</div>
            <div class="cmd">
              <code>${esc(f.fixCmd)}</code>
              <div class="cmd-actions">
                <button class="btn btn-sm" data-copy="${esc(f.fixCmd)}">Copy</button>
                ${canApply ? `<button class="btn btn-sm btn-apply" data-apply="${f.id}">Apply</button>` : ''}
              </div>
            </div>
            <div class="fix-out" id="out-${f.id}"></div>
          </div>` : ''}
        <div class="meta-row">
          <span>agent: ${esc(f.agent)}</span>
          <span>rule: ${esc(f.rule)}</span>
          <span>scope: ${esc(f.scope)}/${esc(f.scopeKey)}</span>
          <span>first seen: ${ago(f.firstSeen)}</span>
        </div>
      </div>` : ''}
    </div>`;
  }).join('');
}

/* ---------- actions ---------- */

async function poll() {
  try {
    const r = await fetch('/api/state');
    state = await r.json();
    render();
  } catch (e) {
    $('banner').className = 'banner err';
    $('banner').textContent = 'Cannot reach the sentinel server.';
  }
}

async function startScan(mode) {
  $('btn-quick').disabled = true;
  $('btn-full').disabled = true;
  try {
    await fetch(`/api/scan?mode=${mode}`, { method: 'POST' });
    await poll();
  } finally {
    setTimeout(() => {
      $('btn-quick').disabled = false;
      $('btn-full').disabled = false;
    }, 1500);
  }
}

async function applyFix(id, btn) {
  const out = $(`out-${id}`);
  btn.disabled = true;
  btn.textContent = 'Applying…';
  try {
    const r = await fetch('/api/fix', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const text = await r.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { ok: false, error: text }; }
    out.textContent = data.ok
      ? `✓ applied${data.output ? `\n${data.output}` : ''}\nRe-scan to confirm the finding is gone.`
      : `✗ ${data.error || 'failed'}${data.output ? `\n${data.output}` : ''}`;
    btn.textContent = data.ok ? 'Applied' : 'Retry';
    btn.disabled = !!data.ok;
  } catch (e) {
    out.textContent = `✗ ${e}`;
    btn.textContent = 'Retry';
    btn.disabled = false;
  }
}

document.addEventListener('click', (ev) => {
  const t = ev.target.closest('[data-toggle],[data-copy],[data-apply],[data-project],[data-jump]');
  if (!t) return;

  if (t.dataset.toggle) {
    const id = t.dataset.toggle;
    expanded.has(id) ? expanded.delete(id) : expanded.add(id);
    renderFindings(state.scan);
  } else if (t.dataset.copy !== undefined) {
    navigator.clipboard.writeText(t.dataset.copy).then(() => {
      const old = t.textContent;
      t.textContent = 'Copied';
      setTimeout(() => { t.textContent = old; }, 1200);
    });
  } else if (t.dataset.apply) {
    applyFix(t.dataset.apply, t);
  } else if (t.dataset.project) {
    filters.scope = filters.scope === t.dataset.project ? '' : t.dataset.project;
    $('scope-filter').value = filters.scope;
    render();
  } else if (t.dataset.jump) {
    const id = t.dataset.jump;
    // Clear filters so the target is definitely in the list, then open it.
    filters.sev = ''; filters.scope = ''; filters.text = ''; filters.newOnly = false;
    $('sev-filter').value = ''; $('scope-filter').value = ''; $('search').value = ''; $('new-only').checked = false;
    expanded.add(id);
    renderFindings(state.scan);
    $(`f-${id}`)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
  }
});

$('btn-quick').onclick = () => startScan('quick');
$('btn-full').onclick = () => startScan('full');
// With no explicit choice the page follows the OS, so the first click has to
// toggle away from what is actually on screen — not from a hardcoded default.
function effectiveTheme() {
  const set = document.documentElement.dataset.theme;
  if (set === 'dark' || set === 'light') return set;
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

$('btn-theme').onclick = () => {
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('sentinel-theme', next); } catch {}
};
$('search').oninput = (e) => { filters.text = e.target.value; renderFindings(state.scan); };
$('sev-filter').onchange = (e) => { filters.sev = e.target.value; renderFindings(state.scan); };
$('scope-filter').onchange = (e) => { filters.scope = e.target.value; render(); };
$('new-only').onchange = (e) => { filters.newOnly = e.target.checked; renderFindings(state.scan); };

try {
  const saved = localStorage.getItem('sentinel-theme');
  if (saved) document.documentElement.dataset.theme = saved;
} catch {}

poll();
setInterval(poll, 4000);
