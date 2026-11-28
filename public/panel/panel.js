'use strict';
// SENSI MACRO reseller panel. Every value from the server is rendered with textContent — never innerHTML.
// The day buttons call POST /api/reseller/keys/generate: the same key-fetch function as the public API (/api/v1/keys).
const $ = id => document.getElementById(id);
const h = (tag, attrs = {}, ...kids) => {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v; else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else if (v === true) e.setAttribute(k, ''); else if (v !== false && v != null) e.setAttribute(k, v);
  }
  for (const c of kids.flat()) if (c != null) e.append(c);
  return e;
};
let csrf = '', me = null, qty = 1, busy = false, lastKeys = [];

async function api(method, path, body) {
  const res = await fetch('/api/reseller' + path, { method, credentials: 'same-origin',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf }, body: body ? JSON.stringify(body) : undefined });
  let data = {}; try { data = await res.json(); } catch {}
  if (res.status === 401 && path !== '/login') { showLogin(data.error || 'Please sign in'); throw new Error(data.error || 'Please sign in'); }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}
let tt; function toast(msg, bad) { const t = $('toast'); t.textContent = msg; t.className = 'show' + (bad ? ' bad' : ''); clearTimeout(tt); tt = setTimeout(() => { t.className = ''; }, bad ? 5000 : 2200); }
async function copy(text, msg = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(msg); }
  catch { const ta = h('textarea', {}); ta.value = text; document.body.append(ta); ta.select(); try { document.execCommand('copy'); toast(msg); } catch { toast('Copy failed', true); } ta.remove(); }
}
function confirmBox(title, text, ok = 'OK') {
  $('dlgTitle').textContent = title; $('dlgText').textContent = text; $('dlgOk').textContent = ok;
  const d = $('dlg'); return new Promise(res => { d.addEventListener('close', () => res(d.returnValue === 'ok'), { once: true }); d.returnValue = 'cancel'; d.showModal(); });
}

// ── auth ──────────────────────────────────────────────────────
function showLogin(msg = '') { $('app').hidden = true; $('login').hidden = false; $('pw').value = ''; $('loginErr').textContent = msg; csrf = ''; me = null; }
function showApp() { $('login').hidden = true; $('app').hidden = false; renderMe(); loadKeys(); }
$('showPw').addEventListener('click', e => { const p = $('pw'), on = p.type === 'password'; p.type = on ? 'text' : 'password'; e.target.textContent = on ? 'Hide' : 'Show'; e.target.setAttribute('aria-pressed', String(on)); });
$('loginForm').addEventListener('submit', async e => {
  e.preventDefault(); $('loginErr').textContent = ''; $('loginBtn').disabled = true;
  try { const r = await api('POST', '/login', { username: $('user').value.trim(), password: $('pw').value }); csrf = r.csrfToken; me = r.reseller; showApp(); }
  catch (err) { $('loginErr').textContent = err.message === 'Failed to fetch' ? 'Cannot reach the server. It may be waking up — wait a minute and try again.' : err.message; }
  finally { $('loginBtn').disabled = false; }
});
$('logout').addEventListener('click', async () => { try { await api('POST', '/logout'); } catch {} showLogin(); });
(async () => { try { const r = await fetch('/api/reseller/session', { credentials: 'same-origin' }); if (r.ok) { const d = await r.json(); csrf = d.csrfToken; me = d.reseller; return showApp(); } } catch {} showLogin(); })();

// ── header / quota ────────────────────────────────────────────
const origin = location.origin;
function renderMe() {
  if (!me) return;
  $('who').textContent = '@' + me.username;
  $('qLeft').textContent = me.keysLeft;
  const segs = 20, frac = me.keyLimit ? me.keysUsed / me.keyLimit : 1, on = Math.min(segs, Math.round(frac * segs));
  const m = $('meter'); m.className = 'meter' + (me.keysLeft === 0 ? ' out' : me.keyLimit && me.keysLeft / me.keyLimit <= 0.1 ? ' low' : '');
  m.setAttribute('aria-label', `${me.keysUsed} of ${me.keyLimit} keys used`);
  m.replaceChildren(...Array.from({ length: segs }, (_, i) => h('i', { class: i < on ? 'on' : '' })));
  $('qText').textContent = `${me.keysUsed} of ${me.keyLimit} keys used`;
  const b = $('blocked'), can = me.apiEnabled && me.keysLeft > 0;
  b.hidden = can; b.textContent = !me.apiEnabled ? 'Key fetching (API) is blocked by the owner. You can still see your keys.' : 'Your key limit is used up. Ask the owner to raise it.';
  renderLadder(can);
  $('apiState').textContent = me.apiEnabled ? 'API: enabled' : 'API: blocked by the owner'; $('apiState').className = 'apistate ' + (me.apiEnabled ? 'on' : 'off');
  $('apiHint').textContent = me.apiHint || '—'; $('apiBase').textContent = origin + '/api/v1';
  $('exGet').textContent = `curl -X POST ${origin}/api/v1/keys \\\n  -H "X-Api-Key: YOUR_API_KEY" \\\n  -H "Content-Type: application/json" \\\n  -d '{"days":5,"count":3}'`;
  $('exMe').textContent = `curl ${origin}/api/v1/me \\\n  -H "X-Api-Key: YOUR_API_KEY"`;
}

// ── the 1–7 day ladder ────────────────────────────────────────
function renderLadder(can) {
  const n = Math.min(qty, me ? me.keysLeft : 0);
  $('ladder').replaceChildren(...[1, 2, 3, 4, 5, 6, 7].map(d => h('li', { class: 'day' },
    h('div', { class: 'dl' }, h('b', {}, String(d)), d === 1 ? 'day' : 'days'),
    h('div', { class: 'ticks', 'aria-hidden': 'true' }, ...Array.from({ length: 7 }, (_, i) => h('i', { class: i < d ? 'on' : '' }))),
    h('button', { disabled: !can || busy, onclick: () => getKeys(d) }, can ? `Get ${qty > 1 ? Math.min(qty, me.keysLeft) + ' keys' : 'key'}` : 'Locked'))));
}
document.querySelectorAll('.qty button').forEach(b => b.addEventListener('click', () => {
  qty = Number(b.dataset.q); document.querySelectorAll('.qty button').forEach(x => x.classList.toggle('on', x === b)); renderMe();
}));
async function getKeys(days) {
  if (busy || !me) return; busy = true; renderLadder(false);
  const count = Math.min(qty, me.keysLeft);
  try {
    const r = await api('POST', '/keys/generate', { days, count, label: $('label').value.trim() });
    me = { ...me, keysUsed: r.keysUsed, keysLeft: r.keysLeft, keyLimit: r.keyLimit };
    lastKeys = r.keys; showOut(days, r.keys);
    const mk = $('markLive'); mk.classList.remove('spin'); void mk.getBoundingClientRect(); mk.classList.add('spin');
    toast(`${r.count} key${r.count > 1 ? 's' : ''} ready`); loadKeys();
  } catch (e) { toast(e.message, true); try { const s = await api('GET', '/session'); me = s.reseller; } catch {} }
  finally { busy = false; renderMe(); }
}
function showOut(days, keys) {
  $('out').hidden = false; $('cmd').textContent = `sensi keys --days ${days} --count ${keys.length}`;
  $('outKeys').replaceChildren(...keys.map(k => h('li', {}, h('code', {}, k), h('button', { class: 'ghost', onclick: () => copy(k) }, 'Copy'))));
  $('out').scrollIntoView({ block: 'nearest', behavior: 'smooth' });
}
$('copyAll').addEventListener('click', () => lastKeys.length && copy(lastKeys.join('\n'), `Copied ${lastKeys.length} keys`));

// ── my keys ───────────────────────────────────────────────────
const STATUS = { active: 'Active', unused: 'Not used yet', expired: 'Expired', revoked: 'Revoked', full: 'In use' };
async function loadKeys() {
  try {
    const r = await api('GET', '/keys'); me = r.reseller || me; renderMe();
    $('keysEmpty').hidden = r.items.length > 0;
    $('keyList').replaceChildren(...r.items.map(k => h('li', {},
      h('code', { title: 'Tap to copy', onclick: () => copy(k.key) }, k.key),
      h('span', { class: 'pill ' + (k.status === 'active' && !k.used ? 'unused' : k.status) }, STATUS[k.status === 'active' && !k.used ? 'unused' : k.status] || k.status),
      h('small', {}, `${k.days} day${k.days > 1 ? 's' : ''} · made ${k.createdAt.slice(0, 10)}${k.expiresAt ? ' · ends ' + k.expiresAt.slice(0, 10) : ''}${k.label ? ' · ' + k.label : ''}`))));
  } catch {}
}

// ── tabs / api tab ────────────────────────────────────────────
document.querySelectorAll('.tabs button').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('.tabs button').forEach(x => { x.classList.toggle('on', x === b); x.setAttribute('aria-selected', String(x === b)); });
  for (const t of ['get', 'keys', 'api']) $('tab-' + t).hidden = b.dataset.tab !== t;
  if (b.dataset.tab === 'keys') loadKeys();
}));
document.querySelectorAll('[data-copy]').forEach(b => b.addEventListener('click', () => copy($(b.dataset.copy).textContent)));
$('regen').addEventListener('click', async () => {
  if (!await confirmBox('New API key?', 'Your current API key stops working immediately. Update your scripts with the new key.', 'Generate')) return;
  try { const r = await api('POST', '/api-key'); $('newKey').textContent = r.apiKey; $('newKeyBox').hidden = false; me = { ...me, apiHint: r.apiHint }; $('apiHint').textContent = r.apiHint; }
  catch (e) { toast(e.message, true); }
});
