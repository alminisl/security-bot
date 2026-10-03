'use strict';

const $ = (id) => document.getElementById(id);
const SEVS = ['critical', 'high', 'medium', 'low', 'info'];
const ABBR = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };
const BANDS = [[85, 'good'], [60, 'warn'], [35, 'poor'], [0, 'bad']];
const LABEL = { good: 'Solid', warn: 'Needs work', poor: 'Weak', bad: 'Critical' };
const TABS = ['overview', 'docker', 'machine', 'network', 'map', 'packages', 'traffic'];

// Which scopes feed each tab's findings list.
const TAB_SCOPES = {
  docker: (f) => f.scope === 'project',
  machine: (f) => f.scope === 'machine',
  network: (f) => f.scope === 'network',
  packages: (f) => f.scope === 'packages',
  traffic: (f) => f.scope === 'traffic',
};

let state = null;
let lastPayload = '';
let dirty = true;
const built = new Set();
const smooth = !matchMedia('(prefers-reduced-motion: reduce)').matches;

/* ---------- helpers ---------- */

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

const band = (n) => BANDS.find(([t]) => n >= t)[1];

function ago(iso) {
  if (!iso) return 'never';
  const secs = (Date.now() - new Date(iso).getTime()) / 1000;
  if (secs < 90) return 'just now';
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  return `${Math.round(secs / 86400)}d ago`;
}

function humanBytes(n) {
  n = Number(n) || 0;
  const u = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0, f = n;
  while (f >= 1024 && i < u.length - 1) { f /= 1024; i++; }
  return i === 0 ? `${n} B` : `${f.toFixed(1)} ${u[i]}`;
}

function chips(counts) {
  const parts = SEVS.filter((s) => (counts?.[s] || 0) > 0)
    .map((s) => `<span class="chip" data-sev="${s}">${counts[s]} ${ABBR[s]}</span>`);
  return parts.length ? parts.join('') : '<span class="chip" data-sev="clean">clean</span>';
}

function bars(counts) {
  const total = SEVS.reduce((a, s) => a + (counts?.[s] || 0), 0);
  if (!total) return '<span style="width:100%;background:var(--sev-good-mark)"></span>';
  return SEVS.filter((s) => counts[s] > 0)
    .map((s) => `<span style="width:${(counts[s] / total) * 100}%;background:var(--sev-${s}-mark)"></span>`)
    .join('');
}

const CARET = `<svg class="caret" viewBox="0 0 12 12" aria-hidden="true" focusable="false">
  <path d="M3 4.5 6 7.5 9 4.5" fill="none" stroke="currentColor" stroke-width="1.6"
        stroke-linecap="round" stroke-linejoin="round"/></svg>`;

function showBanner(kind, text) {
  const b = $('banner');
  if (!kind) { b.hidden = true; return; }
  b.className = 'banner ' + kind;
  b.textContent = text;
  b.hidden = false;
}

/* ---------- data ---------- */

async function poll() {
  if (document.visibilityState === 'hidden') return;
  try {
    const r = await fetch('/api/state');
    const txt = await r.text();
    if (txt === lastPayload) return; // nothing changed: leave the DOM alone
    lastPayload = txt;
    state = JSON.parse(txt);
    dirty = true;
    built.clear();
    render();
  } catch {
    showBanner('err', 'Cannot reach the sentinel server.');
  }
}

/* ---------- shell ---------- */

function render() {
  const sc = state?.scan;

  if (state?.running) showBanner('busy', `Scan running — ${state.progress || 'working'}…`);
  else if (state?.error) showBanner('err', state.error);
  else showBanner(null);

  const chip = $('mode-chip');
  chip.dataset.mode = state?.fixesEnabled ? 'fixes' : 'readonly';
  chip.textContent = state?.fixesEnabled ? 'Fixes enabled' : 'Read-only';
  chip.title = state?.fixesEnabled
    ? 'This dashboard can run prepared fix commands on the host.'
    : 'This dashboard cannot change anything. Start with --enable-fixes to allow fixes.';

  if (!sc) { $('subtitle').textContent = 'no scan yet'; return; }

  const f = sc.facts || {};
  $('subtitle').innerHTML = `${esc(f.containers || 0)} containers · ${esc(f.projects || 0)} projects · ` +
    `${esc(f.packages || 0)} packages · <span title="scan ${esc(sc.id)}">${esc(f.mode || '')} scan ${ago(sc.startedAt)}</span>`;
  $('report').textContent = sc.report || '—';

  renderScore(sc, state.history);
  renderTiles(sc);
  renderAlerts(sc);
  renderTabCounts(sc);
  renderPanel(currentTab());
  dirty = false;
}

function renderScore(sc, history) {
  const n = sc.score, b = band(n);
  $('overall-num').textContent = n;
  const pill = $('overall-band');
  pill.textContent = LABEL[b];
  pill.dataset.band = b;

  const m = $('overall-meter');
  m.dataset.band = b;
  m.querySelector('.meter-fill').style.setProperty('--v', n);

  const pts = (history || []).slice(-24).map((h) => h.score);
  sparkline($('overall-spark'), pts, b);

  const prev = pts.length > 1 ? pts[pts.length - 2] : null;
  const d = prev == null ? null : n - prev;
  $('overall-sub').textContent = 'overall, out of 100';
  const bits = [];
  if (d != null) bits.push(d === 0 ? 'unchanged since the last scan'
    : `${d > 0 ? 'up' : 'down'} ${Math.abs(d)} since the last scan`);
  if (sc.newCount) bits.push(`${sc.newCount} new`);
  if (sc.resolved) bits.push(`${sc.resolved} resolved`);
  $('overall-delta').textContent = bits.join(' · ');
}

function sparkline(el, pts, b) {
  const n = pts.length;
  if (n < 2) { el.replaceChildren(); return; }
  const W = 120, H = 36, P = 4;
  const x = (i) => P + (i / (n - 1)) * (W - 2 * P);
  const y = (v) => H - P - (Math.max(0, Math.min(100, v)) / 100) * (H - 2 * P);
  const d = pts.map((v, i) => `${i ? 'L' : 'M'}${x(i).toFixed(1)} ${y(v).toFixed(1)}`).join(' ');
  const mark = `var(--sev-${{ good: 'good', warn: 'medium', poor: 'high', bad: 'critical' }[b]}-mark)`;
  el.innerHTML =
    `<path d="${d} L${x(n - 1).toFixed(1)} ${H - P} L${P} ${H - P} Z" fill="${mark}" fill-opacity=".10"/>` +
    `<path d="${d}" fill="none" stroke="${mark}" stroke-width="2" vector-effect="non-scaling-stroke"
            stroke-linecap="round" stroke-linejoin="round"/>` +
    `<circle cx="${x(n - 1).toFixed(1)}" cy="${y(pts[n - 1]).toFixed(1)}" r="3.5"
             fill="${mark}" stroke="var(--surface)" stroke-width="2"/>`;
}

// The Projects tile headlines the median, not the minimum: one bad stack out of
// sixteen is not the rating of the whole estate. The worst is marked as a tick.
function renderTiles(sc) {
  const scores = (sc.projects || []).map((p) => p.score).sort((a, b) => a - b);
  const median = scores.length ? scores[Math.floor(scores.length / 2)] : 100;
  const worst = scores.length ? scores[0] : 100;
  const pc = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const p of sc.projects || []) for (const s of SEVS) pc[s] += p.counts?.[s] || 0;

  const tiles = [
    { tab: 'docker', label: 'Projects', score: median, sub: `median of ${scores.length} · worst ${worst}`, counts: pc, tick: worst },
    { tab: 'machine', label: 'Machine', score: sc.machine?.score ?? 100, sub: subFor(sc.machine), counts: sc.machine?.counts },
    { tab: 'network', label: 'Network', score: sc.network?.score ?? 100, sub: subFor(sc.network), counts: sc.network?.counts },
    { tab: 'packages', label: 'Packages', score: sc.packages?.score ?? 100, sub: subFor(sc.packages), counts: sc.packages?.counts },
    { tab: 'traffic', label: 'Traffic', score: sc.traffic?.score ?? 100, sub: subFor(sc.traffic), counts: sc.traffic?.counts },
  ];

  $('tiles').innerHTML = tiles.map((t) => {
    const b = band(t.score);
    return `<button class="tile" data-goto="${t.tab}" data-band="${b}">
      <div class="tile-head">
        <span class="tile-label">${esc(t.label)}</span>
        <span class="tile-score num">${t.score}</span>
      </div>
      <p class="tile-sub">${esc(t.sub)}</p>
      <div class="meter" data-band="${b}">
        <div class="meter-fill" style="--v:${t.score}"></div>
        ${t.tick != null ? `<i class="meter-tick" style="--at:${t.tick}"></i>` : ''}
      </div>
      <div class="chips">${chips(t.counts)}</div>
    </button>`;
  }).join('');
}

function subFor(scope) {
  const total = SEVS.reduce((a, s) => a + (scope?.counts?.[s] || 0), 0);
  return total ? `${total} finding${total === 1 ? '' : 's'}` : 'no findings';
}

function renderAlerts(sc) {
  const alerts = sc.alerts || [];
  const sec = $('alerts-section');
  if (!alerts.length) { sec.hidden = true; return; }
  sec.hidden = false;
  const crit = alerts.filter((a) => a.severity === 'critical').length;
  $('alerts-count').textContent = `${crit} critical, ${alerts.length - crit} high`;
  $('alerts').innerHTML = alerts.slice(0, 8).map((f) => `
    <div class="alert">
      <span class="dot dot-${f.severity}" aria-hidden="true"></span>
      <span class="vh">${esc(f.severity)}: </span>
      <div class="alert-body">
        <div class="alert-title">${esc(f.title)}${f.new ? ' <span class="badge-new">NEW</span>' : ''}</div>
        <div class="alert-meta">${esc(f.target)} · ${esc(f.scopeKey)} · ${esc(f.agent)}</div>
      </div>
      <button class="btn btn-sm" data-jump="${esc(f.id)}" data-jump-scope="${esc(f.scope)}">Details</button>
    </div>`).join('');
}

function renderTabCounts(sc) {
  for (const [tab, pred] of Object.entries(TAB_SCOPES)) {
    const btn = $('tab-' + tab);
    if (!btn) continue;
    const fs = (sc.findings || []).filter(pred);
    btn.querySelector('.tab-count')?.remove();
    if (!fs.length) continue;
    const worst = SEVS.find((s) => fs.some((f) => f.severity === s));
    const span = document.createElement('span');
    span.className = 'tab-count';
    span.dataset.sev = worst;
    span.textContent = fs.length;
    span.setAttribute('aria-label', `${fs.length} findings, worst ${worst}`);
    btn.append(span);
  }
}

/* ---------- tabs ---------- */

const strip = $('tablist');
const tabEls = () => [...strip.querySelectorAll('[role="tab"]')];
const currentTab = () => tabEls().find((t) => t.getAttribute('aria-selected') === 'true')?.dataset.tab || 'overview';

function selectTab(name, { focus = false, push = true } = {}) {
  if (!TABS.includes(name)) name = 'overview';
  for (const t of tabEls()) {
    const on = t.dataset.tab === name;
    t.setAttribute('aria-selected', String(on));
    t.tabIndex = on ? 0 : -1;
    $(t.getAttribute('aria-controls')).hidden = !on;
    if (on && focus) {
      t.focus();
      // Optional call: keeping the active tab in view is a nicety, and must not
      // be able to stop the panel below from rendering.
      t.scrollIntoView?.({ inline: 'nearest', block: 'nearest', behavior: smooth ? 'smooth' : 'auto' });
    }
  }
  if (push && location.hash.slice(1) !== name) history.replaceState(null, '', '#' + name);
  renderPanel(name);
}

strip.addEventListener('click', (e) => {
  const t = e.target.closest('[role="tab"]');
  if (t) selectTab(t.dataset.tab, { focus: true });
});

strip.addEventListener('keydown', (e) => {
  const list = tabEls();
  const i = list.findIndex((t) => t.getAttribute('aria-selected') === 'true');
  const go = (j) => { e.preventDefault(); selectTab(list[(j + list.length) % list.length].dataset.tab, { focus: true }); };
  switch (e.key) {
    case 'ArrowRight': case 'ArrowDown': return go(i + 1);
    case 'ArrowLeft': case 'ArrowUp': return go(i - 1);
    case 'Home': return go(0);
    case 'End': return go(list.length - 1);
  }
});

// Panels build their DOM the first time they are revealed, and again only when
// the data changes. Six panels of hundreds of rows should not all be live.
function renderPanel(name) {
  const sc = state?.scan;
  if (!sc) return;
  if (built.has(name) && !dirty) return;
  ({
    overview: renderOverview, docker: renderDocker, machine: renderMachine,
    network: renderNetwork, map: renderMap, packages: renderPackages, traffic: renderTraffic,
  }[name] || (() => {}))(sc);
  built.add(name);
}

/* ---------- panels ---------- */

function renderOverview(sc) {
  const agents = sc.agents || [];
  const ok = agents.filter((a) => a.status === 'ok').length;
  $('agents-sub').textContent =
    `${ok}/${agents.length} reporting · ${agents.reduce((a, x) => a + x.checks, 0)} checks`;
  $('agents').innerHTML = agents.map((a) => `
    <div class="agent" data-status="${esc(a.status)}">
      <div class="agent-top">
        <span class="agent-name">${esc(a.title)}</span>
        <span class="agent-status">${esc(a.status)}</span>
      </div>
      <div class="agent-role">${esc(a.role)}</div>
      <div class="agent-stats">${a.findings} findings · ${a.checks} checks · ${a.durationMs}ms</div>
      ${a.message ? `<div class="agent-stats">${esc(a.message)}</div>` : ''}
    </div>`).join('');

  const ss = sc.suggestions || [];
  $('suggestions-section').hidden = !ss.length;
  $('suggestions').innerHTML = ss.map((s, i) => `
    <li class="suggestion">
      <span class="rank num">${i + 1}</span>
      <div>
        <h4>${esc(s.title)}</h4>
        <p>${esc(s.why)}</p>
        ${s.action ? `<p><strong>Do:</strong> ${esc(s.action)}</p>` : ''}
        ${s.cmd ? cmdBlock(s.cmd, null) : ''}
        <div class="tags"><span class="tag">${esc(s.effort)}</span>${s.scopeKey ? `<span class="tag">${esc(s.scopeKey)}</span>` : ''}</div>
      </div>
    </li>`).join('');
}

function renderDocker(sc) {
  const ps = sc.projects || [];
  $('projects-count').textContent = `${ps.length} compose stacks`;
  $('project-grid').innerHTML = ps.map((p) => {
    const b = band(p.score);
    return `<button class="project" data-project="${esc(p.key)}" data-band="${b}" aria-pressed="false"
                    aria-label="${esc(p.key)}, rated ${p.score} out of 100">
      <div class="project-top">
        <span class="project-name" title="${esc(p.key)}">${esc(p.key)}</span>
        <span class="project-score num">${p.score}</span>
      </div>
      <div class="project-meta">${(p.items || []).length} container${(p.items || []).length === 1 ? '' : 's'}</div>
      <div class="bars">${bars(p.counts)}</div>
      <div class="chips">${chips(p.counts)}</div>
    </button>`;
  }).join('');
  buildFindings('docker', sc);
}

function renderMachine(sc) { buildFindings('machine', sc); }

function renderNetwork(sc) {
  const ds = sc.devices || [];
  const online = ds.filter((d) => d.online).length;
  $('devices-sub').textContent = `${ds.length} seen · ${online} online`;
  $('devices-rows').innerHTML = ds.map((d) => {
    const kind = d.new ? 'new' : d.online ? 'online' : 'offline';
    const label = d.new ? 'new' : d.online ? 'online' : 'offline';
    return `<tr>
      <td class="name">${esc(d.name)}</td>
      <td class="sub mono">${esc(d.addr)}</td>
      <td class="sub">${esc(d.source)}${d.os ? ' · ' + esc(d.os) : ''}</td>
      <td class="sub">${esc(d.note || '')}</td>
      <td class="status"><span class="pill" data-kind="${kind}">${label}</span></td>
    </tr>`;
  }).join('') || '<tr><td colspan="5" class="empty">No devices discovered.</td></tr>';
  buildFindings('network', sc);
}

function renderTraffic(sc) {
  const usage = (sc.netUsage || []).filter((u) => u.rxBytes + u.txBytes > 0);
  $('usage-sub').textContent = `${usage.length} containers with traffic`;
  $('usage-rows').innerHTML = usage.map((u) => {
    const delta = (u.rxDelta || 0) + (u.txDelta || 0);
    const spiked = (u.spike || 0) >= 5;
    return `<tr>
      <td class="name">${esc(u.name)}</td>
      <td class="n sub">${humanBytes(u.rxBytes)}</td>
      <td class="n sub">${humanBytes(u.txBytes)}</td>
      <td class="n sub">${humanBytes(delta)}</td>
      <td class="status">${spiked
        ? `<span class="pill" data-kind="outdated">${u.spike.toFixed(0)}× normal</span>`
        : '<span class="pill" data-kind="current">steady</span>'}</td>
    </tr>`;
  }).join('') || '<tr><td colspan="5" class="empty">No traffic recorded yet. The sampler needs the dashboard running.</td></tr>';

  const flows = sc.flows || [];
  const svc = flows.filter((f) => !f.peer).length;
  $('flows-sub').textContent = `${svc} service endpoints · ${flows.length - svc} recurring peers`;
  $('flows-rows').innerHTML = flows.map((f) => {
    const kind = f.new ? 'new' : f.peer ? 'peer' : 'current';
    const label = f.new ? 'new' : f.peer ? 'peer' : 'known';
    return `<tr>
      <td class="name mono">${esc(f.remote)}</td>
      <td class="sub">${esc(f.host || '—')}</td>
      <td class="n sub">${esc(f.proto)}/${esc(f.port)}</td>
      <td class="n sub">${f.samples}</td>
      <td class="status"><span class="pill" data-kind="${kind}">${label}</span></td>
    </tr>`;
  }).join('') || '<tr><td colspan="5" class="empty">No outbound connections recorded yet.</td></tr>';
  buildFindings('traffic', sc);
}

/* ---------- packages ---------- */

const pkgFilters = { text: '', manager: '', attentionOnly: true };
let pkgRows = [], pkgShown = 0;
const PKG_PAGE = 150;

function flattenPackages(sc) {
  const out = [];
  for (const set of sc.inventory || []) {
    for (const it of set.items || []) out.push({ ...it, manager: set.manager, label: set.label });
  }
  // Attention first, then by name, so the useful rows are in the first chunk.
  return out.sort((a, b) => (Number(!!b.security) - Number(!!a.security))
    || (Number(!!b.outdated) - Number(!!a.outdated))
    || a.name.localeCompare(b.name));
}

function renderPackages(sc) {
  const sets = sc.inventory || [];
  const total = sets.reduce((a, s) => a + s.count, 0);
  const outdated = sets.reduce((a, s) => a + s.outdated, 0);
  $('pkg-summary').textContent = sets.length
    ? `${total} packages across ${sets.length} managers, ${outdated} with updates available. ` +
      sets.map((s) => `${s.label}: ${s.shown}`).join(' · ')
    : 'No package managers detected.';

  const sel = $('pkg-manager');
  if (sel.options.length <= 1) {
    for (const s of sets) {
      const o = document.createElement('option');
      o.value = s.manager; o.textContent = s.label;
      sel.append(o);
    }
  }
  pkgRows = flattenPackages(sc);
  pkgPaint(true);
  buildFindings('packages', sc);
}

function pkgMatch(p) {
  if (pkgFilters.manager && p.manager !== pkgFilters.manager) return false;
  if (pkgFilters.attentionOnly && !p.outdated && !p.security) return false;
  if (pkgFilters.text && !(`${p.name} ${p.version} ${p.source || ''}`.toLowerCase()
      .includes(pkgFilters.text))) return false;
  return true;
}

function pkgRowHTML(p) {
  const kind = p.security ? 'security' : p.outdated ? 'outdated' : 'current';
  const label = p.security ? 'security' : p.outdated ? 'update' : 'current';
  return `<tr>
    <td class="name" title="${esc(p.name)}">${esc(p.name)}</td>
    <td class="sub">${esc(p.label)}</td>
    <td class="n sub">${esc(p.version || '—')}</td>
    <td class="n sub">${esc(p.latest || '—')}</td>
    <td class="status"><span class="pill" data-kind="${kind}">${label}</span></td>
  </tr>`;
}

// Chunked with an explicit "show more": 2000 rows in one innerHTML janks a
// phone, and a scroll observer leaves the page incomplete at rest.
function pkgPaint(reset) {
  const body = $('pkg-rows');
  if (reset) { body.innerHTML = ''; pkgShown = 0; }
  const matching = pkgRows.filter(pkgMatch);
  const slice = matching.slice(pkgShown, pkgShown + PKG_PAGE);
  body.insertAdjacentHTML('beforeend', slice.map(pkgRowHTML).join(''));
  pkgShown += slice.length;
  const remaining = matching.length - pkgShown;
  const more = $('pkg-more');
  more.hidden = remaining <= 0;
  more.textContent = `Show ${Math.min(PKG_PAGE, remaining)} more of ${remaining} remaining`;
  if (!matching.length) {
    body.innerHTML = '<tr><td colspan="5" class="empty">No packages match these filters.</td></tr>';
  }
}

/* ---------- findings ---------- */

const filterState = {}; // one per tab, so a filter on Packages never leaks to Traffic

// Repeat occurrences of a rule collapse into one row with a count. The scoring
// model already treats them as diminishing; the UI should too.
function groupByRule(findings) {
  const m = new Map();
  for (const f of findings) {
    let g = m.get(f.rule);
    if (!g) m.set(f.rule, g = { rule: f.rule, severity: f.severity, agent: f.agent, items: [], anyNew: false });
    g.items.push(f);
    g.anyNew = g.anyNew || f.new;
    if (SEVS.indexOf(f.severity) < SEVS.indexOf(g.severity)) g.severity = f.severity;
  }
  return [...m.values()].sort((a, b) =>
    SEVS.indexOf(a.severity) - SEVS.indexOf(b.severity) || b.items.length - a.items.length);
}

function cmdBlock(cmd, findingId) {
  const canApply = state?.fixesEnabled && findingId;
  return `<div>
    <div class="fix-label">${canApply ? 'Command — can be applied from here' : 'Command'}</div>
    <div class="cmd">
      <code>${esc(cmd)}</code>
      <div class="cmd-actions">
        <button class="btn btn-sm" data-copy>Copy</button>
        ${canApply ? `<button class="btn btn-sm btn-apply" data-apply="${esc(findingId)}">Apply</button>` : ''}
      </div>
    </div>
    ${findingId ? `<div class="fix-out" id="out-${esc(findingId)}" role="status" aria-live="polite"></div>` : ''}
  </div>`;
}

function findingRow(g) {
  const lead = g.items[0];
  const n = g.items.length;
  const id = lead.id;
  const title = n > 1 ? lead.title.replace(/^\d+\s/, '') : lead.title;
  const target = n > 1 ? `${n} targets` : lead.target;
  return `<div class="finding" data-sev="${g.severity}" id="f-${esc(id)}">
    <button class="finding-head" data-toggle="${esc(id)}" aria-expanded="false" aria-controls="b-${esc(id)}">
      <span class="sev" data-sev="${g.severity}">${g.severity}</span>
      <span class="finding-title">${esc(title)}
        ${g.anyNew ? '<span class="badge-new">NEW</span>' : ''}
        ${n > 1 ? `<span class="count-chip">×${n}</span>` : ''}
      </span>
      <span class="finding-target">${esc(target)}</span>
      ${CARET}
    </button>
    <div class="finding-body" id="b-${esc(id)}" hidden>
      <p>${esc(lead.detail)}</p>
      ${n > 1 ? `<div><div class="fix-label">Affected</div>
        <ul class="target-list">${g.items.map((f) =>
          `<li>${esc(f.target)}${f.scopeKey && f.scopeKey !== f.target ? ` · ${esc(f.scopeKey)}` : ''}${f.new ? ' · new' : ''}</li>`).join('')}</ul></div>` : ''}
      ${lead.fix ? `<div><div class="fix-label">Recommended fix</div><p>${esc(lead.fix)}</p></div>` : ''}
      ${lead.fixCmd ? cmdBlock(lead.fixCmd, lead.fixApply ? lead.id : null) : ''}
      <div class="meta-row">
        <span>agent: ${esc(lead.agent)}</span>
        <span>rule: ${esc(lead.rule)}</span>
        <span>first seen: ${ago(lead.firstSeen)}</span>
      </div>
    </div>
  </div>`;
}

function buildFindings(tab, sc) {
  const host = document.querySelector(`[data-findings="${tab}"]`);
  if (!host) return;
  const all = (sc.findings || []).filter(TAB_SCOPES[tab]);
  const fs = filterState[tab] ||= { text: '', sev: '', scope: '', newOnly: false };

  const scopes = [...new Set(all.map((f) => f.scopeKey))].sort();
  host.innerHTML = `
    <div class="section-head">
      <h3>Findings</h3>
      <div class="filters">
        <input type="search" data-f="text" aria-label="Filter findings by text" placeholder="Filter findings…" autocomplete="off">
        <select data-f="sev" aria-label="Filter by severity">
          <option value="">All severities</option>
          ${SEVS.map((s) => `<option value="${s}">${s}</option>`).join('')}
        </select>
        ${scopes.length > 1 ? `<select data-f="scope" aria-label="Filter by scope">
          <option value="">All scopes</option>
          ${scopes.map((s) => `<option value="${esc(s)}">${esc(s)}</option>`).join('')}
        </select>` : ''}
        <label class="check"><input type="checkbox" data-f="newOnly"> New only</label>
        <span class="muted" data-count></span>
      </div>
    </div>
    <div class="findings" data-list></div>
    <div class="empty" data-empty hidden>No findings match these filters.</div>`;

  const list = host.querySelector('[data-list]');
  const groups = groupByRule(all);

  // Grouped by severity with a sticky header, which beats a filter for
  // "show me the criticals" because it works while scrolling.
  let html = '';
  for (const sev of SEVS) {
    const inSev = groups.filter((g) => g.severity === sev);
    if (!inSev.length) continue;
    html += `<div class="sev-group" data-sev="${sev}"><h4>${sev} · ${inSev.length}</h4>` +
      inSev.map(findingRow).join('') + '</div>';
  }
  list.innerHTML = html;

  // Remember the group behind each row so filtering needs no re-render.
  for (const el of list.querySelectorAll('.finding')) {
    const id = el.id.slice(2);
    el._g = groups.find((g) => g.items[0].id === id);
  }

  for (const input of host.querySelectorAll('[data-f]')) {
    const key = input.dataset.f;
    if (input.type === 'checkbox') { input.checked = fs[key]; input.onchange = () => { fs[key] = input.checked; applyFindingFilters(tab); }; }
    else {
      input.value = fs[key] || '';
      const run = () => { fs[key] = input.value; applyFindingFilters(tab); };
      if (input.tagName === 'SELECT') input.onchange = run;
      else { let t; input.oninput = () => { clearTimeout(t); t = setTimeout(run, 120); }; }
    }
  }
  applyFindingFilters(tab);
}

function applyFindingFilters(tab) {
  const host = document.querySelector(`[data-findings="${tab}"]`);
  if (!host) return;
  const fs = filterState[tab];
  let shown = 0, total = 0;
  for (const el of host.querySelectorAll('.finding')) {
    const g = el._g;
    total++;
    const ok = !!g && groupMatches(g, fs);
    el.hidden = !ok;
    if (ok) shown++;
  }
  for (const grp of host.querySelectorAll('.sev-group')) {
    grp.hidden = ![...grp.querySelectorAll('.finding')].some((e) => !e.hidden);
  }
  host.querySelector('[data-empty]').hidden = shown > 0;
  host.querySelector('[data-count]').textContent = shown === total ? `${total} shown` : `${shown} of ${total}`;
}

function groupMatches(g, fs) {
  if (fs.sev && g.severity !== fs.sev) return false;
  if (fs.newOnly && !g.anyNew) return false;
  if (fs.scope && !g.items.some((f) => f.scopeKey === fs.scope)) return false;
  if (fs.text) {
    const hay = g.items.map((f) => `${f.title} ${f.detail} ${f.target} ${f.scopeKey} ${f.agent} ${f.rule}`)
      .join(' ').toLowerCase();
    if (!hay.includes(fs.text.toLowerCase())) return false;
  }
  return true;
}

/* ---------- network map ---------- */

// Deterministic layered layout: networks across the top, this host in the
// middle, container clusters per compose project below. A force simulation
// would move nodes between scans and make the picture harder to learn.
function renderMap(sc) {
  const W = 1000, H = 620;
  const svg = $('map');
  const devices = sc.devices || [];
  const tailnet = devices.filter((d) => d.source === 'tailnet' && !/this host/.test(d.note || ''));
  const lan = devices.filter((d) => d.source !== 'tailnet');
  const projects = sc.projects || [];
  const containers = sc.containers || [];

  // Worst severity touching each container, for its colour.
  const worstFor = (name) => {
    let worst = null;
    for (const f of sc.findings || []) {
      if (f.target === name || f.target.startsWith(name + ':')) {
        if (!worst || SEVS.indexOf(f.severity) < SEVS.indexOf(worst)) worst = f.severity;
      }
    }
    return worst;
  };
  const exposedPorts = (c) => (c.ports || []).filter((p) => p.hostIp === '0.0.0.0');

  const node = (x, y, r, cls, label, detail, shape) => ({ x, y, r, cls, label, detail, shape });
  const nodes = [];
  const edges = [];

  const HOST = { x: W / 2, y: 300 };
  const ROUTER = { x: 250, y: 150 };
  const TSHUB = { x: 750, y: 150 };

  nodes.push(node(W / 2, 48, 13, 'n-info', 'internet', 'The public internet. Outbound destinations are on the Traffic tab.', 'cloud'));
  edges.push({ a: { x: W / 2, y: 48 }, b: ROUTER });
  edges.push({ a: { x: W / 2, y: 48 }, b: TSHUB });

  nodes.push(node(ROUTER.x, ROUTER.y, 12, 'n-info', 'router', 'Your LAN gateway. Everything published on 0.0.0.0 is reachable from here.', 'box'));
  nodes.push(node(TSHUB.x, TSHUB.y, 12, 'n-info', 'tailnet', `${tailnet.length} peers can reach this host over Tailscale.`, 'box'));

  // LAN devices and tailnet peers fan out beneath their hub.
  const fan = (list, hub, x0, x1, y, source) => {
    list.forEach((d, i) => {
      const x = list.length === 1 ? (x0 + x1) / 2 : x0 + (i / (list.length - 1)) * (x1 - x0);
      const stale = /offline \d+d/.test(d.note || '');
      const cls = d.new ? 'n-low' : stale ? 'n-medium' : d.online ? 'n-good' : 'n-offline';
      const label = d.name.length > 14 ? d.name.slice(0, 13) + '…' : d.name;
      nodes.push(node(x, y, 7, cls, label,
        `${d.name} · ${d.addr} · ${source}${d.os ? ' · ' + d.os : ''}${d.note ? ' · ' + d.note : ''}`, 'dot'));
      edges.push({ a: hub, b: { x, y } });
    });
  };
  fan(lan, ROUTER, 70, 440, 228, 'local network');
  fan(tailnet, TSHUB, 570, 950, 228, 'tailnet');

  // This host.
  nodes.push(node(HOST.x, HOST.y, 22, 'n-host', 'this host',
    `${containers.length} containers · machine rated ${sc.machine?.score ?? 100}/100 · network ${sc.network?.score ?? 100}/100`, 'host'));
  edges.push({ a: ROUTER, b: HOST });
  edges.push({ a: TSHUB, b: HOST });

  // Project clusters below the host, worst-rated first.
  const cols = 4, cw = W / cols, rowH = 72, y0 = 392;
  projects.forEach((p, i) => {
    const cx = (i % cols) * cw + cw / 2;
    const cy = y0 + Math.floor(i / cols) * rowH;
    edges.push({ a: HOST, b: { x: cx, y: cy - 14 }, faint: true });
    nodes.push(node(cx, cy - 20, 0, '', p.key.length > 16 ? p.key.slice(0, 15) + '…' : p.key,
      `project ${p.key} · rated ${p.score}/100 · ${(p.items || []).length} containers`, 'label'));

    const mem = containers.filter((c) => c.project === p.key);
    mem.forEach((c, j) => {
      const span = Math.min(mem.length, 6);
      const spacing = 20;
      const sx = cx - ((span - 1) * spacing) / 2 + (j % 6) * spacing;
      const sy = cy + 4 + Math.floor(j / 6) * 18;
      const w = worstFor(c.name);
      const exposed = exposedPorts(c);
      nodes.push({
        x: sx, y: sy, r: 6, cls: w ? 'n-' + w : 'n-good', label: '', shape: 'dot',
        ring: exposed.length > 0,
        detail: `${c.name} · ${c.image}${w ? ' · worst finding: ' + w : ' · no findings'}` +
          (exposed.length ? ` · LAN-exposed: ${exposed.map((p2) => p2.hostPort).join(', ')}` : ''),
        goto: c.project,
      });
      // Draw a line to the router only for the serious exposures, or the
      // picture turns into fourteen crossing curves.
      for (const f of sc.findings || []) {
        if (f.rule === 'port-exposed' && f.severity === 'high' && f.target.startsWith(c.name + ':')) {
          edges.push({ a: { x: sx, y: sy }, b: ROUTER, exposed: true });
          break;
        }
      }
    });
  });

  const zone = (x, y, t) => `<text class="zone-label" x="${x}" y="${y}">${esc(t)}</text>`;
  const edgePath = (e) => {
    const mx = (e.a.x + e.b.x) / 2, my = (e.a.y + e.b.y) / 2 + (e.exposed ? -40 : 0);
    return `<path class="edge${e.exposed ? ' exposed' : ''}" d="M${e.a.x} ${e.a.y} Q${mx} ${my} ${e.b.x} ${e.b.y}"${e.faint ? ' opacity=".25"' : ''}/>`;
  };
  const shapeFor = (n) => {
    if (n.shape === 'label') return '';
    if (n.shape === 'host') return `<rect class="${n.cls}" x="${-n.r}" y="${-14}" width="${n.r * 2}" height="28" rx="6"/>`;
    if (n.shape === 'box') return `<rect class="${n.cls}" x="${-n.r}" y="${-9}" width="${n.r * 2}" height="18" rx="4"/>`;
    return `<circle class="${n.cls}" r="${n.r}"/>` +
      (n.ring ? `<circle r="${n.r + 3.5}" fill="none" stroke="var(--sev-high-mark)" stroke-width="1.5"/>` : '');
  };

  svg.innerHTML =
    zone(16, 24, 'internet') + zone(16, 130, 'local network') + zone(570, 130, 'tailnet') +
    zone(16, 296, 'this host') + zone(16, 372, 'containers by project') +
    edges.map(edgePath).join('') +
    nodes.map((n, i) => `<g class="node" transform="translate(${n.x} ${n.y})" tabindex="0" role="button"
         data-node="${i}" aria-label="${esc(n.detail || n.label)}">
      ${shapeFor(n)}
      ${n.label ? `<text class="node-label" y="${n.shape === 'label' ? 0 : n.r + 11}" text-anchor="middle">${esc(n.label)}</text>` : ''}
    </g>`).join('');

  svg._nodes = nodes;
  $('map-detail').textContent = 'Select a node to see what was found on it.';
}

/* ---------- actions ---------- */

// navigator.clipboard does not exist on an insecure origin, which is exactly
// what a tailnet IP is. Fall back to selecting the text so the platform copy
// gesture still works, and say so rather than failing silently.
async function copyText(text, btn) {
  const done = (ok) => {
    const old = btn.dataset.label || btn.textContent;
    btn.dataset.label = old;
    btn.textContent = ok ? 'Copied' : 'Selected — press Ctrl/⌘+C';
    setTimeout(() => { btn.textContent = btn.dataset.label || old; }, 1600);
  };
  try {
    if (navigator.clipboard?.writeText) { await navigator.clipboard.writeText(text); return done(true); }
    throw new Error('no clipboard api');
  } catch {
    const code = btn.closest('.cmd')?.querySelector('code');
    if (code) {
      const r = document.createRange(); r.selectNodeContents(code);
      const s = getSelection(); s.removeAllRanges(); s.addRange(r);
    }
    done(false);
  }
}

async function applyFix(id, btn) {
  const out = $(`out-${id}`);
  btn.disabled = true;
  btn.textContent = 'Applying…';
  try {
    const r = await fetch('/api/fix', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ id }),
    });
    const text = await r.text();
    let data;
    try { data = JSON.parse(text); } catch { data = { ok: false, error: text }; }
    if (out) {
      out.textContent = data.ok
        ? `Applied.${data.output ? '\n' + data.output : ''}\nRe-scan to confirm the finding is gone.`
        : `Failed: ${data.error || 'unknown error'}${data.output ? '\n' + data.output : ''}`;
    }
    btn.textContent = data.ok ? 'Applied' : 'Retry';
    btn.disabled = !!data.ok;
  } catch (e) {
    if (out) out.textContent = `Failed: ${e}`;
    btn.textContent = 'Retry';
    btn.disabled = false;
  }
}

document.addEventListener('click', (ev) => {
  const t = ev.target.closest('[data-toggle],[data-copy],[data-apply],[data-project],[data-jump],[data-goto],[data-node]');
  if (!t) return;

  if (t.hasAttribute('data-copy')) {
    const code = t.closest('.cmd')?.querySelector('code');
    if (code) copyText(code.textContent, t);

  } else if (t.dataset.toggle) {
    // Toggle in place: re-rendering would throw focus to the body and lose
    // the reader's place in a long list.
    const body = $(`b-${t.dataset.toggle}`);
    if (!body) return;
    const open = body.hidden;
    body.hidden = !open;
    t.setAttribute('aria-expanded', String(open));

  } else if (t.dataset.apply) {
    applyFix(t.dataset.apply, t);

  } else if (t.dataset.goto) {
    selectTab(t.dataset.goto, { focus: true });

  } else if (t.dataset.project) {
    const fs = filterState.docker ||= { text: '', sev: '', scope: '', newOnly: false };
    const on = fs.scope !== t.dataset.project;
    fs.scope = on ? t.dataset.project : '';
    for (const b of document.querySelectorAll('[data-project]')) {
      b.setAttribute('aria-pressed', String(b.dataset.project === fs.scope));
    }
    const sel = document.querySelector('[data-findings="docker"] [data-f="scope"]');
    if (sel) sel.value = fs.scope;
    applyFindingFilters('docker');

  } else if (t.dataset.jump) {
    const tab = { project: 'docker', machine: 'machine', network: 'network', packages: 'packages', traffic: 'traffic' }[t.dataset.jumpScope] || 'docker';
    selectTab(tab);
    const id = t.dataset.jump;
    const fs = filterState[tab];
    if (fs) { fs.text = ''; fs.sev = ''; fs.scope = ''; fs.newOnly = false; }
    buildFindings(tab, state.scan);
    const row = $(`f-${id}`);
    if (row) {
      row.querySelector('.finding-body').hidden = false;
      row.querySelector('.finding-head').setAttribute('aria-expanded', 'true');
      row.scrollIntoView?.({ behavior: smooth ? 'smooth' : 'auto', block: 'center' });
    }

  } else if (t.dataset.node) {
    const n = $('map')._nodes?.[+t.dataset.node];
    if (n) $('map-detail').textContent = n.detail || n.label;
  }
});

// Enter/Space on a map node, which is a <g> and gets no click from the keyboard.
$('map').addEventListener('keydown', (ev) => {
  if (ev.key !== 'Enter' && ev.key !== ' ') return;
  const g = ev.target.closest('[data-node]');
  if (!g) return;
  ev.preventDefault();
  const n = $('map')._nodes?.[+g.dataset.node];
  if (n) $('map-detail').textContent = n.detail || n.label;
});

async function startScan(mode) {
  $('btn-quick').disabled = true;
  $('btn-full').disabled = true;
  try {
    await fetch(`/api/scan?mode=${mode}`, { method: 'POST' });
    lastPayload = '';
    await poll();
  } finally {
    setTimeout(() => { $('btn-quick').disabled = false; $('btn-full').disabled = false; }, 1500);
  }
}

$('btn-quick').onclick = () => startScan('quick');
$('btn-full').onclick = () => startScan('full');

function effectiveTheme() {
  const set = document.documentElement.dataset.theme;
  if (set === 'dark' || set === 'light') return set;
  return matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

$('btn-theme').onclick = () => {
  const next = effectiveTheme() === 'dark' ? 'light' : 'dark';
  document.documentElement.dataset.theme = next;
  $('btn-theme').setAttribute('aria-pressed', String(next === 'dark'));
  $('theme-label').textContent = next === 'dark' ? 'Switch to light theme' : 'Switch to dark theme';
  try { localStorage.setItem('sentinel-theme', next); } catch {}
  if (built.has('map') && state?.scan) renderMap(state.scan); // re-read the CSS vars
};
$('btn-theme').setAttribute('aria-pressed', String(effectiveTheme() === 'dark'));

$('pkg-search').oninput = (e) => {
  pkgFilters.text = e.target.value.toLowerCase();
  clearTimeout($('pkg-search')._t);
  $('pkg-search')._t = setTimeout(() => pkgPaint(true), 120);
};
$('pkg-manager').onchange = (e) => { pkgFilters.manager = e.target.value; pkgPaint(true); };
$('pkg-outdated').onchange = (e) => { pkgFilters.attentionOnly = e.target.checked; pkgPaint(true); };
$('pkg-more').onclick = () => pkgPaint(false);

addEventListener('hashchange', () => selectTab(location.hash.slice(1), { push: false }));
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'visible') poll(); });

selectTab(location.hash.slice(1) || 'overview', { push: false });
poll();
setInterval(poll, 8000);
