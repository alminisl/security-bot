import { JSDOM, VirtualConsole } from 'jsdom';
import fs from 'node:fs';

const BASE = '/home/perun/Projects/security-bot/internal/web/assets/';
let html = fs.readFileSync(BASE + 'index.html', 'utf8');
const css = fs.readFileSync(BASE + 'style.css', 'utf8');
// jsdom does not fetch <link>, so inline the real stylesheet: without it the
// cascade is not exercised and a display rule defeating [hidden] goes unseen.
html = html.replace('<link rel="stylesheet" href="style.css">', `<style>${css}</style>`);
const appjs = fs.readFileSync(BASE + 'app.js', 'utf8');
const state = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'));

const errors = [];
const vc = new VirtualConsole();
vc.on('jsdomError', (e) => errors.push('jsdomError: ' + (e.detail?.stack || e.message)));
vc.on('error', (...a) => errors.push('console.error: ' + a.join(' ')));

const dom = new JSDOM(html, {
  runScripts: 'dangerously', pretendToBeVisual: true, virtualConsole: vc,
  url: 'http://100.107.207.69:7777/',
});
const { window } = dom;

// Minimal fetch stub returning the real scan payload.
window.fetch = async (url, opts) => {
  if (String(url).startsWith('/api/state')) {
    return { ok: true, text: async () => JSON.stringify(state) };
  }
  return { ok: true, text: async () => JSON.stringify({ started: true }) };
};
window.matchMedia = window.matchMedia || ((q) => ({ matches: false, addEventListener(){}, removeEventListener(){} }));
Object.defineProperty(window.document, 'visibilityState', { value: 'visible', configurable: true });
// jsdom implements no layout, so these do not exist. Browsers all have them.
window.Element.prototype.scrollIntoView = function () {};

try {
  window.eval(appjs);
} catch (e) { errors.push('eval threw: ' + e.stack); }

await new Promise((r) => setTimeout(r, 400));

const d = window.document;
const $ = (id) => d.getElementById(id);
const out = [];
const chk = (name, cond, extra='') => out.push(`${cond ? 'PASS' : 'FAIL'}  ${name}${extra ? ' — ' + extra : ''}`);

chk('hero score rendered', $('overall-num').textContent !== '—', 'got "' + $('overall-num').textContent + '"');
chk('band label set', /Solid|Needs work|Weak|Critical/.test($('overall-band').textContent), $('overall-band').textContent);
chk('meter band attr', !!$('overall-meter').dataset.band, $('overall-meter').dataset.band);
chk('sparkline drawn', $('overall-spark').querySelectorAll('path').length >= 2);
chk('tiles rendered (5)', $('tiles').querySelectorAll('.tile').length === 5, String($('tiles').querySelectorAll('.tile').length));
chk('alerts visible', $('alerts-section').hidden === false && $('alerts').querySelectorAll('.alert').length > 0,
    $('alerts').querySelectorAll('.alert').length + ' alerts');
chk('report text', $('report').textContent.length > 20);
chk('subtitle', $('subtitle').textContent.includes('containers'));
chk('mode chip', $('mode-chip').textContent.length > 0, $('mode-chip').textContent);
chk('agents rendered', $('agents').querySelectorAll('.agent').length === state.scan.agents.length,
    $('agents').querySelectorAll('.agent').length + ' of ' + state.scan.agents.length);
chk('suggestions rendered', $('suggestions').querySelectorAll('.suggestion').length > 0);
chk('tab counts added', d.querySelectorAll('.tab-count').length > 0, d.querySelectorAll('.tab-count').length + ' tabs badged');

// Walk every tab, checking each renders without error and produces content.
const tabs = ['overview','docker','machine','network','map','packages','traffic'];
for (const t of tabs) {
  const before = errors.length;
  $('tab-' + t).dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  const panel = $('panel-' + t);
  const visible = panel.hidden === false;
  const content = panel.textContent.trim().length;
  chk(`tab ${t}`, visible && content > 20 && errors.length === before,
      `${content} chars${errors.length > before ? ', ERRORS: ' + errors.slice(before).join(' | ') : ''}`);
}

// Specific panel content
$('tab-docker').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
chk('project cards', $('project-grid').querySelectorAll('.project').length === state.scan.projects.length,
    $('project-grid').querySelectorAll('.project').length + ' of ' + state.scan.projects.length);
const dockerFindings = d.querySelector('[data-findings="docker"]');
chk('docker findings grouped', dockerFindings.querySelectorAll('.finding').length > 0,
    dockerFindings.querySelectorAll('.finding').length + ' rows from ' +
    state.scan.findings.filter(f=>f.scope==='project').length + ' findings');
chk('severity groups', dockerFindings.querySelectorAll('.sev-group').length > 0,
    dockerFindings.querySelectorAll('.sev-group').length + ' groups');

// Expansion must not destroy the row
const head = dockerFindings.querySelector('.finding-head');
if (!head) {
  chk('expand sets aria-expanded', false, 'no .finding-head; host innerHTML length=' + dockerFindings.innerHTML.length +
      '; first 300: ' + dockerFindings.innerHTML.slice(0,300).replace(/\n/g,' '));
} else {
  head.dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  chk('expand sets aria-expanded', head.getAttribute('aria-expanded') === 'true');
  chk('expand reveals body', dockerFindings.querySelector('.finding-body').hidden === false);
  chk('row survives expand', d.contains(head));
}

$('tab-network').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
chk('device rows', $('devices-rows').querySelectorAll('tr').length === (state.scan.devices||[]).length,
    $('devices-rows').querySelectorAll('tr').length + ' of ' + (state.scan.devices||[]).length);

$('tab-map').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
const mapNodes = $('map').querySelectorAll('.node');
chk('map nodes drawn', mapNodes.length > 20, mapNodes.length + ' nodes');
chk('map edges drawn', $('map').querySelectorAll('.edge').length > 20, $('map').querySelectorAll('.edge').length + ' edges');
if (mapNodes.length) mapNodes[mapNodes.length-1].dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
chk('map node click shows detail', !$('map-detail').textContent.startsWith('Select a node'), $('map-detail').textContent.slice(0,60));

$('tab-packages').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
chk('package rows', $('pkg-rows').querySelectorAll('tr').length > 0, $('pkg-rows').querySelectorAll('tr').length + ' rows');
chk('package summary', $('pkg-summary').textContent.includes('packages'));

$('tab-traffic').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
chk('usage rows', $('usage-rows').querySelectorAll('tr').length > 0, $('usage-rows').querySelectorAll('tr').length + ' rows');
chk('flow rows', $('flows-rows').querySelectorAll('tr').length > 0, $('flows-rows').querySelectorAll('tr').length + ' rows');

// Computed-style checks: the `hidden` attribute must actually hide, which an
// author display rule can silently defeat.
const shown = (el) => window.getComputedStyle(el).display !== 'none';
$('tab-machine').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
const others = ['overview','docker','network','map','packages','traffic'];
chk('only the selected panel is displayed',
    shown($('panel-machine')) && others.every((t) => !shown($('panel-' + t))),
    'visible: ' + ['machine',...others].filter((t)=>shown($('panel-'+t))).join(',') || 'none');
chk('hidden finding body is not displayed', (() => {
  $('tab-docker').dispatchEvent(new window.MouseEvent('click', { bubbles: true }));
  // An earlier assertion expanded the first one, so pick a still-collapsed body.
  const bodies = [...d.querySelectorAll('[data-findings="docker"] .finding-body')];
  const b = bodies.find((x) => x.hidden);
  return !!b && !shown(b) && bodies.some((x) => !x.hidden && shown(x));
})(), 'collapsed hidden, expanded visible');
chk('hidden alert band is not displayed', (() => {
  const a = $('alerts-section'); const was = a.hidden;
  a.hidden = true; const ok = !shown(a); a.hidden = was; return ok;
})());

// Accessibility spot checks
chk('no emoji in markup', !/[\u{1F300}-\u{1FAFF}\u{2600}-\u{27BF}]/u.test(html), 'checked index.html');
chk('all tabs have aria-controls', [...d.querySelectorAll('[role=tab]')].every(t=>$(t.getAttribute('aria-controls'))));
chk('roving tabindex', [...d.querySelectorAll('[role=tab]')].filter(t=>t.tabIndex===0).length === 1);
chk('search inputs labelled', [...d.querySelectorAll('input[type=search]')].every(i=>i.getAttribute('aria-label')));
chk('selects labelled', [...d.querySelectorAll('select')].every(i=>i.getAttribute('aria-label')));
chk('banner is live region', $('banner').getAttribute('aria-live') === 'polite');

console.log(out.join('\n'));
const fails = out.filter(l=>l.startsWith('FAIL'));
console.log(`\n${out.length - fails.length}/${out.length} passed`);
if (errors.length) console.log('\nJS ERRORS:\n' + errors.slice(0,8).join('\n'));
process.exit(fails.length ? 1 : 0);
