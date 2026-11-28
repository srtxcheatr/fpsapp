'use strict';
// All data is rendered with textContent / createElement — never innerHTML — so labels/notes can't inject markup.
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
const ls = { get: k => { try { return localStorage.getItem(k) || ''; } catch { return ''; } }, set: (k, v) => { try { localStorage.setItem(k, v); } catch {} } };
const ss = { get: k => { try { return sessionStorage.getItem(k) || ''; } catch { return ''; } }, set: (k, v) => { try { v ? sessionStorage.setItem(k, v) : sessionStorage.removeItem(k); } catch {} } };
let BASE = ls.get('srtx_base'), tok = ss.get('srtx_tok');
let csrf = '', offset = 0, total = 0, rowsOnPage = [], auditBefore = null, lastGen = [];
const hdrs = () => ({ 'Content-Type': 'application/json', 'X-CSRF-Token': csrf, ...(BASE && tok ? { 'X-Admin-Token': tok } : {}) });
const LIMIT = 50, selected = new Set();
const SITES = { site1: 'SRT', site2: 'SENSI', site3: 'KALEYYY', site4: 'NK' };

// ── API ──────────────────────────────────────────────────────
async function api(method, path, body) {
  const res = await fetch(BASE + path, { method, credentials: BASE ? 'omit' : 'same-origin', headers: hdrs(), body: body ? JSON.stringify(body) : undefined });
  let data = {}; try { data = await res.json(); } catch {}
  if (res.status === 401) { showLogin(); throw new Error('Session expired — please sign in again'); }
  if (!res.ok) throw new Error(data.error || data.message || `HTTP ${res.status}`);
  return data;
}
let tt; function toast(msg, bad) {
  const t = $('toast'); t.textContent = msg; t.style.background = bad ? 'var(--bad)' : ''; t.style.color = bad ? '#fff' : '';
  t.classList.add('show'); clearTimeout(tt); tt = setTimeout(() => t.classList.remove('show'), bad ? 6000 : 3000);
}
const run = async fn => { try { return await fn(); } catch (e) { toast(e.message, true); } };
async function copy(text, msg = 'Copied') {
  try { await navigator.clipboard.writeText(text); toast(msg); }
  catch { const ta = h('textarea', {}); ta.value = text; document.body.append(ta); ta.select(); try { document.execCommand('copy'); toast(msg); } catch { toast('Copy failed — select and copy manually', true); } ta.remove(); }
}

// ── Dialog helper ────────────────────────────────────────────
function ask(title, fields = [], { text = '', ok = 'OK', danger = false } = {}) {
  const dlg = $('dlg'); $('dlgTitle').textContent = title;
  const body = $('dlgBody'); body.replaceChildren(text ? h('p', {}, text) : '',
    ...fields.map(f => h('label', {}, f.label, h('input', { name: f.name, type: f.type || 'text', value: f.value ?? '', min: f.min, max: f.max, autocomplete: 'off', inputmode: f.type === 'number' ? 'numeric' : null }))));
  const okBtn = $('dlgOk'); okBtn.textContent = ok; okBtn.className = danger ? 'solid-danger' : 'primary';
  return new Promise(resolve => {
    dlg.addEventListener('close', () => {
      if (dlg.returnValue !== 'ok') return resolve(null);
      resolve(Object.fromEntries([...body.querySelectorAll('input')].map(i => [i.name, i.value])));
    }, { once: true });
    dlg.returnValue = 'cancel'; dlg.showModal();
    const first = body.querySelector('input'); if (first) first.select();
  });
}
const confirmDo = async (title, text, fn, ok = 'Confirm', danger = false) => { if (await ask(title, [], { text, ok, danger })) await fn(); };

// ── Auth ─────────────────────────────────────────────────────
function showLogin() { $('app').hidden = true; $('login').hidden = false; $('pw').value = ''; $('base').value = BASE; if (BASE) $('base').closest('details').open = true; }
async function showApp() { $('login').hidden = true; $('app').hidden = false; await refresh(); }
$('loginForm').addEventListener('submit', async e => {
  e.preventDefault(); $('loginErr').textContent = '';
  const b = $('base').value.trim().replace(/\/+$/, '');
  if (b && !/^https?:\/\/[^\s/]+$/i.test(b)) { $('loginErr').textContent = 'Server URL must look like https://your-app.onrender.com'; return; }
  try {
    const res = await fetch(b + '/api/admin/login', { method: 'POST', credentials: b ? 'omit' : 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ password: $('pw').value }) });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) {
      if (!d.error && (res.status === 404 || res.status === 405)) throw new Error(`HTTP ${res.status}: this address is not the key server. Open “Server settings” and enter the server URL.`);
      throw new Error(d.error || `HTTP ${res.status}`);
    }
    BASE = b; ls.set('srtx_base', b); tok = b ? d.token : ''; ss.set('srtx_tok', tok);
    csrf = d.csrfToken; await showApp();
  } catch (err) { $('loginErr').textContent = err.message === 'Failed to fetch' ? 'Cannot reach the server (offline, waking up, or blocked). Wait a minute and try again.' : err.message; }
});
$('logout').addEventListener('click', () => run(async () => { await api('POST', '/api/admin/logout'); csrf = ''; tok = ''; ss.set('srtx_tok', ''); showLogin(); }));
(async () => {
  try { const r = await fetch(BASE + '/api/admin/session', { credentials: BASE ? 'omit' : 'same-origin', headers: BASE && tok ? { 'X-Admin-Token': tok } : {} });
    if (r.ok) { csrf = (await r.json()).csrfToken || ''; return showApp(); } } catch {}
  showLogin();
})();

// ── Tabs ─────────────────────────────────────────────────────
document.querySelectorAll('.tab').forEach(b => b.addEventListener('click', () => {
  document.querySelectorAll('.tab').forEach(x => x.classList.toggle('on', x === b));
  for (const t of ['keys', 'resellers', 'app', 'audit']) $('tab-' + t).hidden = b.dataset.tab !== t;
  if (b.dataset.tab === 'resellers' && window.loadResellers) window.loadResellers();
  if (b.dataset.tab === 'audit') { auditBefore = null; $('auditRows').replaceChildren(); loadAudit(); }
  if (b.dataset.tab === 'app' && window.loadAppControl) window.loadAppControl();
}));

// ── Helpers ──────────────────────────────────────────────────
const query = () => new URLSearchParams({ search: $('q').value.trim(), status: $('fStatus').value, site: $('fSite').value,
  type: $('fType').value, sort: $('fSort').value, order: $('fSort').value === 'key' ? 'asc' : 'desc' });
const fmtDate = s => s ? s.replace('T', ' ').slice(0, 16) : '—';
const daysLeft = k => k.expiresAt ? Math.ceil((new Date(k.expiresAt) - Date.now()) / 86400000) : null;
function expiryNode(k) {
  if (!k.expiresAt) return k.lastUsedAt ? h('span', { class: 'mut' }, 'Never') : h('span', { class: 'mut' }, `${k.durationDays || 7} days after 1st login`);
  const d = daysLeft(k);
  const rel = d > 0 ? (d === 1 ? 'tomorrow' : `in ${d} days`) : 'expired';
  return h('span', { class: d > 0 && d <= 3 ? 'soon' : '' }, `${fmtDate(k.expiresAt).slice(0, 10)} · ${rel}`);
}
function statusBadge(k) {
  const label = k.status === 'active' ? (k.full ? 'Active · full' : !k.lastUsedAt ? 'Unused' : 'Active') : k.status[0].toUpperCase() + k.status.slice(1);
  const cls = k.status === 'active' && !k.lastUsedAt ? 'b-unused' : `b-${k.status}`;
  return h('span', { class: `badge ${cls}` }, label);
}
const filtersActive = () => $('q').value.trim() || $('fStatus').value !== 'all' || $('fSite').value || $('fType').value;

// ── Keys list ────────────────────────────────────────────────
async function refresh() {
  await run(async () => {
    const [list, st] = await Promise.all([api('GET', `/api/admin/keys/search?${query()}&limit=${LIMIT}&offset=${offset}`), api('GET', '/api/admin/stats')]);
    total = list.total; rowsOnPage = list.items;
    if (offset >= total && offset > 0) { offset = Math.max(0, Math.floor((total - 1) / LIMIT) * LIMIT); return refresh(); }
    const cur = $('fStatus').value;
    $('stats').replaceChildren(...[['Total', st.total, 'all'], ['Active', st.active, 'active'], ['Unused', st.unused, 'unused'], ['Full', st.maxed, 'full'],
      ['Expired', st.expired, 'expired'], ['Revoked', st.revoked, 'revoked']].map(([l, v, f]) =>
      h('button', { class: cur === f ? 'on' : '', title: `Show ${l.toLowerCase()} keys`, onclick: () => { $('fStatus').value = f; reload(); } }, h('b', {}, String(v)), h('span', {}, l))));
    renderRows(); renderBulk();
    $('pageInfo').textContent = total ? `${offset + 1}–${Math.min(offset + LIMIT, total)} of ${total}` : '';
    $('prev').disabled = offset === 0; $('next').disabled = offset + LIMIT >= total;
    $('clearFilters').hidden = !filtersActive();
    const empty = $('empty'); empty.hidden = total > 0;
    if (!total) empty.textContent = filtersActive() ? 'No keys match your search or filters.' : 'No keys yet. Tap “+ New keys” to create your first one.';
  });
}
function renderRows() {
  $('rows').replaceChildren(...rowsOnPage.map(k => {
    const sel = selected.has(k.key);
    const lbl = [k.label, k.note].filter(Boolean).join(' — ');
    return h('tr', { class: sel ? 'sel' : '' },
      h('td', { class: 'c' }, h('input', { type: 'checkbox', 'aria-label': `Select ${k.key}`, checked: sel,
        onchange: e => { e.target.checked ? selected.add(k.key) : selected.delete(k.key); e.target.closest('tr').classList.toggle('sel', e.target.checked); renderBulk(); } })),
      h('td', { class: 'keycell' }, h('code', {}, k.key)),
      h('td', { class: 'st' }, statusBadge(k)),
      h('td', { class: 'ex' }, expiryNode(k)),
      h('td', { class: 'dv' }, `${k.loginCount || 0} of ${k.loginLimit || 1} used`),
      h('td', { class: 'wrap lb' + (lbl ? '' : ' none') }, lbl || '—'),
      h('td', { class: 'lu' }, fmtDate(k.lastUsedAt)),
      h('td', { class: 'ac' }, h('div', { class: 'acts' },
        h('button', { onclick: () => copy(k.key) }, 'Copy'),
        h('button', { onclick: () => openDetail(k.key) }, 'Manage'))));
  }));
  $('chkAll').checked = rowsOnPage.length > 0 && rowsOnPage.every(k => selected.has(k.key));
}

// ── Key detail / manage dialog ───────────────────────────────
function openDetail(key) {
  const k = rowsOnPage.find(x => x.key === key); if (!k) return;
  const dlg = $('detail'), close = () => dlg.close();
  const act = (label, fn, cls = '') => h('button', { class: cls, onclick: () => { close(); run(fn); } }, label);
  const kv = [['Status', statusBadge(k)], ['Site', SITES[k.siteId] || k.prefix || '—'], ['Expires', k.expiresAt ? `${fmtDate(k.expiresAt)} UTC` : expiryNode(k)],
    ['Devices used', `${k.loginCount || 0} of ${k.loginLimit || 1}`], ['Device ID', k.hwid ? h('code', {}, k.hwid) : 'Not locked yet'],
    ['Label', k.label || '—'], ['Note', k.note || '—'], ['Created', fmtDate(k.createdAt)], ['Last used', fmtDate(k.lastUsedAt)]];
  if (k.status === 'revoked' && k.revokeReason) kv.splice(1, 0, ['Revoke reason', k.revokeReason]);
  $('detailBody').replaceChildren(
    h('div', { class: 'dhead' }, h('div', { class: 'dkey' }, h('code', {}, k.key)), h('button', { class: 'link', onclick: close, 'aria-label': 'Close' }, '✕')),
    h('dl', { class: 'kv' }, kv.flatMap(([a, b]) => [h('dt', {}, a), h('dd', {}, b)])),
    h('div', { class: 'dacts' },
      act('Copy key', async () => copy(k.key)),
      act('Add days…', () => extendDialog([k.key])),
      act('Set expiry…', () => expiryDialog(k)),
      act('Edit label…', () => editDialog(k)),
      k.status === 'revoked' ? act('Restore key', () => doOne(k.key, 'restore', {}, 'Key restored'), 'primary') : act('Revoke…', () => revokeDialog([k.key], k.key)),
      act('Reset device', () => confirmDo('Reset device?', `${k.key} will be unlocked from its current device so it can be used on a new one.`, () => api('POST', `/api/admin/key/${k.key}/reset-device`).then(() => { toast('Device reset'); return refresh(); }), 'Reset'))),
    h('hr'),
    h('button', { class: 'danger full', onclick: () => { close(); run(() => deleteDialog([k.key], k.key)); } }, 'Delete this key…'));
  dlg.showModal();
}
$('detail').addEventListener('click', e => { if (e.target === $('detail')) $('detail').close(); });

const doOne = async (key, path, body, msg) => { await api('POST', `/api/admin/key/${key}/${path}`, body); toast(msg); await refresh(); };
async function editDialog(k) {
  const v = await ask(`Edit — ${k.key}`, [{ name: 'label', label: 'Label', value: k.label || '' }, { name: 'note', label: 'Note', value: k.note || '' }], { ok: 'Save' });
  if (v) { await api('PATCH', `/api/admin/key/${k.key}`, { label: v.label, note: v.note }); toast('Saved'); await refresh(); }
}
async function extendDialog(keys) {
  const v = await ask(`Add days to ${keys.length > 1 ? keys.length + ' keys' : keys[0]}`, [{ name: 'days', label: 'Days to add (1–3650)', type: 'number', value: 30, min: 1, max: 3650 }], { ok: 'Add days' });
  if (v) await bulk('extend', keys, { days: Number(v.days) });
}
async function expiryDialog(k) {
  const v = await ask(`Set expiry — ${k.key}`, [{ name: 'at', label: 'Expires at (leave empty for no expiry)', type: 'datetime-local', value: k.expiresAt ? new Date(new Date(k.expiresAt) - new Date().getTimezoneOffset() * 60000).toISOString().slice(0, 16) : '' }], { text: 'Your local time. A past date expires the key immediately.', ok: 'Save' });
  if (v) { await api('POST', `/api/admin/key/${k.key}/expiry`, { expiresAt: v.at ? new Date(v.at).toISOString() : null }); toast('Expiry updated'); await refresh(); }
}
async function revokeDialog(keys, name) {
  const v = await ask(`Revoke ${name || keys.length + ' keys'}?`, [{ name: 'reason', label: 'Reason (optional)' }],
    { text: 'The key stops working on its next check and the user is logged out. You can restore it later.', ok: 'Revoke', danger: true });
  if (v) await bulk('revoke', keys, { reason: v.reason });
}
async function deleteDialog(keys, name) {
  const v = await ask(`Delete ${name || keys.length + ' keys'}?`, [], { text: 'This permanently removes the key(s) and cannot be undone.', ok: 'Delete forever', danger: true });
  if (v) await bulk('delete', keys, { confirm: true });
}
async function bulk(action, keys, extra = {}) {
  let ok = 0, skipped = 0, missing = 0;
  for (let i = 0; i < keys.length; i += 500) {
    const r = await api('POST', '/api/admin/keys/bulk', { action, keys: keys.slice(i, i + 500), ...extra });
    ok += r.processed; skipped += r.skipped.length; missing += r.notFound.length;
  }
  keys.forEach(k => selected.delete(k));
  const verb = { extend: 'extended', revoke: 'revoked', restore: 'restored', delete: 'deleted' }[action] || action;
  toast(`${ok} key${ok === 1 ? '' : 's'} ${verb}${skipped ? `, ${skipped} skipped` : ''}${missing ? `, ${missing} not found` : ''}`);
  await refresh();
}

// ── Selection / bulk bar ─────────────────────────────────────
function renderBulk() {
  $('bulk').hidden = selected.size === 0;
  $('selCount').textContent = `${selected.size} selected`;
  const more = total > selected.size;
  $('selAll').hidden = !more; $('selAll').textContent = `Select all ${total} matching`;
}
$('chkAll').addEventListener('change', e => { rowsOnPage.forEach(k => e.target.checked ? selected.add(k.key) : selected.delete(k.key)); renderRows(); renderBulk(); });
$('selClear').addEventListener('click', () => { selected.clear(); renderRows(); renderBulk(); });
$('selAll').addEventListener('click', () => run(async () => {
  const r = await api('GET', `/api/admin/keys/ids?${query()}`); r.keys.forEach(k => selected.add(k));
  if (r.capped) toast(`Selection capped at ${r.keys.length} of ${r.total}`, true); renderRows(); renderBulk();
}));
document.querySelectorAll('[data-bulk]').forEach(b => b.addEventListener('click', () => run(async () => {
  const keys = [...selected], a = b.dataset.bulk;
  if (a === 'extend') return extendDialog(keys);
  if (a === 'revoke') return revokeDialog(keys);
  if (a === 'delete') return deleteDialog(keys);
  await bulk(a, keys);
})));

// ── Filters / paging ─────────────────────────────────────────
let qt; const reload = () => { offset = 0; refresh(); };
$('q').addEventListener('input', () => { clearTimeout(qt); qt = setTimeout(reload, 300); });
['fStatus', 'fSite', 'fType', 'fSort'].forEach(id => $(id).addEventListener('change', reload));
$('clearFilters').addEventListener('click', () => { $('q').value = ''; $('fStatus').value = 'all'; $('fSite').value = ''; $('fType').value = ''; reload(); });
$('prev').addEventListener('click', () => { offset = Math.max(0, offset - LIMIT); refresh(); window.scrollTo(0, 0); });
$('next').addEventListener('click', () => { offset += LIMIT; refresh(); window.scrollTo(0, 0); });

// ── Generate ─────────────────────────────────────────────────
const gf = $('genForm');
$('newKey').addEventListener('click', () => { const p = $('genPanel'); p.hidden = !p.hidden; if (!p.hidden) { p.scrollIntoView({ block: 'nearest' }); gf.elements.label.focus(); } });
$('genClose').addEventListener('click', () => { $('genPanel').hidden = true; });
function setDur(d) { gf.elements.duration.value = d; document.querySelectorAll('#durChips button').forEach(b => b.classList.toggle('on', b.dataset.d === String(d))); }
document.querySelectorAll('#durChips button').forEach(b => b.addEventListener('click', () => { setDur(b.dataset.d); gf.elements.expiresAt.value = ''; }));
gf.elements.duration.addEventListener('input', e => setDur(e.target.value));
gf.addEventListener('submit', e => {
  e.preventDefault();
  run(async () => {
    const btn = $('genBtn'); btn.disabled = true; btn.textContent = 'Generating…';
    try {
      const f = Object.fromEntries(new FormData(gf)), body = {};
      for (const [k, v] of Object.entries(f)) if (v !== '') body[k] = v;
      if (body.expiresAt) body.expiresAt = new Date(body.expiresAt).toISOString();
      if (body.customKey) { delete body.count; delete body.length; }
      const r = await api('POST', '/api/admin/create-key', body);
      lastGen = r.keys.map(k => k.key);
      $('genOutWrap').hidden = false; $('genOut').textContent = lastGen.join('\n');
      $('genTitle').textContent = `${lastGen.length} key${lastGen.length === 1 ? '' : 's'} created`;
      toast(`${lastGen.length} key(s) created`); offset = 0; await refresh();
    } finally { btn.disabled = false; btn.textContent = 'Generate'; }
  });
});
$('genCopy').addEventListener('click', () => copy(lastGen.join('\n'), `Copied ${lastGen.length} key(s)`));
$('genDl').addEventListener('click', () => {
  const a = h('a', { href: URL.createObjectURL(new Blob([lastGen.join('\n') + '\n'], { type: 'text/plain' })), download: `keys-${new Date().toISOString().slice(0, 10)}.txt` });
  document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 1000);
});

// ── Audit ────────────────────────────────────────────────────
const ACTIONS = { 'admin.login': 'Signed in', 'admin.logout': 'Signed out', 'key.create': 'Created keys', 'key.revoke': 'Revoked', 'key.restore': 'Restored',
  'key.extend': 'Extended', 'key.set_expiry': 'Changed expiry', 'key.delete': 'Deleted', 'key.reset_device': 'Reset device', 'key.edit': 'Edited', 'app.config': 'App settings', 'app.asset_put': 'Uploaded app file', 'app.asset_delete': 'Removed app file' };
async function loadAudit() {
  await run(async () => {
    const r = await api('GET', `/api/admin/audit?limit=50${auditBefore ? `&before=${auditBefore}` : ''}`);
    $('auditRows').append(...r.items.map(e => h('tr', {},
      h('td', {}, String(e.seq)), h('td', {}, fmtDate(e.ts)), h('td', {}, ACTIONS[e.action] || e.action),
      h('td', { class: 'wrap' }, `${e.count || 0}${e.keys && e.keys.length ? ': ' + e.keys.slice(0, 3).join(', ') + (e.keys.length > 3 ? '…' : '') : ''}`),
      h('td', { class: 'wrap' }, JSON.stringify(e.details || {}).slice(0, 200)))));
    auditBefore = r.nextBefore; $('auditMore').hidden = !auditBefore;
  });
}
$('auditMore').addEventListener('click', loadAudit);
$('verifyChain').addEventListener('click', () => run(async () => {
  const r = await api('GET', '/api/admin/audit/verify');
  $('chainRes').textContent = r.ok ? `✔ Log intact (${r.checked} entries)` : `✘ Log tampered at #${r.brokenAt} (${r.reason})`;
  $('chainRes').className = r.ok ? '' : 'err';
}));
