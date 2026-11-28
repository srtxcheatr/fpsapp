'use strict';
// "Resellers" tab of the OWNER panel. Uses helpers from admin.js ($, h, api, run, toast, ask, confirmDo, copy). Never uses innerHTML.
(() => {
  let items = [];
  const when = iso => iso ? iso.replace('T', ' ').slice(0, 16) + ' UTC' : 'never';
  const randPw = () => { const c = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnpqrstuvwxyz23456789', a = new Uint32Array(14); crypto.getRandomValues(a); return [...a].map(n => c[n % c.length]).join(''); };
  const FORMATS = [['plain', 'Plain — SRT_XXXXXX'], ['grouped', 'Grouped — XE_XX_XX_XX_XX'], ['dashed', 'Dashed — XC-XXXX-XXXX-XXXX']];
  const resetUrl = r => `${location.origin}${r.resetPath}`;
  const path = u => `/api/admin/resellers/${encodeURIComponent(u)}`;

  function showSecret(title, lines) {                       // one-time secrets (password / API key) in the shared detail dialog
    const d = $('detail');
    $('detailBody').replaceChildren(h('h3', {}, title), h('p', { class: 'hint' }, 'Copy this now — it cannot be shown again.'),
      ...lines.flatMap(([label, value]) => [h('small', {}, label), h('div', { class: 'keybox' }, value), h('button', { onclick: () => copy(value) }, 'Copy')]),
      h('div', { class: 'row', }, h('button', { class: 'primary', onclick: () => d.close() }, 'Done')));
    d.showModal();
  }

  async function createNew() {
    const v = await ask('New reseller', [
      { label: 'Username (a–z, 0–9, _)', name: 'username' }, { label: 'Password (min 8)', name: 'password', value: randPw() },
      { label: 'Key limit (total keys they may make)', name: 'keyLimit', type: 'number', value: 50, min: 0, max: 1000000 },
      { label: 'Key starts with (2–10 letters/digits, e.g. SRT, XE)', name: 'keyPrefix', value: 'SRT', maxlength: 10 },
      { label: 'Key length (plain/grouped 6–8 · dashed 8, 12 or 16 · blank = auto)', name: 'keyLength', type: 'number', value: '', min: 6, max: 16 },
      { label: 'Key style', name: 'keyFormat', type: 'select', options: FORMATS, value: 'plain' },
      { label: 'Note (optional)', name: 'note' }], { ok: 'Create' });
    if (!v) return;
    const r = await api('POST', '/api/admin/resellers', { ...v, keyLimit: Number(v.keyLimit), keyLength: v.keyLength === '' ? undefined : Number(v.keyLength) });
    toast('Reseller created');
    const x = r.reseller;
    showSecret('@' + x.username + ' is ready', [['Panel address', location.origin + '/panel/'], ['Username', x.username], ['Password', v.password], ['Key limit', String(x.keyLimit)],
      ['Key style', x.keyExample], ['Reset page (give to their customers)', resetUrl(x)], ['API key', r.apiKey]]);
    await load();
  }

  async function showKeys(r) {
    const d = $('detail'), res = await api('GET', path(r.username) + '/keys');
    const rows = res.items.map(k => h('tr', {}, h('td', {}, h('code', {}, k.key)), h('td', {}, k.days + 'd'), h('td', {}, k.status), h('td', {}, k.createdAt.slice(0, 10))));
    $('detailBody').replaceChildren(h('h3', {}, `Keys made by @${r.username} (${res.items.length})`),
      res.items.length ? h('div', { class: 'tablewrap' }, h('table', {}, h('thead', {}, h('tr', {}, ...['Key', 'Days', 'Status', 'Made'].map(t => h('th', {}, t)))), h('tbody', {}, rows)))
        : h('p', { class: 'hint' }, 'No keys yet.'),
      h('div', { class: 'row' }, h('button', { class: 'primary', onclick: () => d.close() }, 'Close')));
    d.showModal();
  }

  const act = (r, label, fn, opts = {}) => h('button', { class: opts.danger ? 'danger' : '', onclick: () => run(fn) }, label);

  function card(r) {
    const pct = r.keyLimit ? Math.min(100, Math.round(r.keysUsed / r.keyLimit * 100)) : 100;
    const bar = h('div', { class: 'bar' + (r.keysLeft === 0 ? ' out' : pct >= 90 ? ' low' : '') }, h('i', {}));
    bar.firstChild.style.width = pct + '%';
    const limitInput = h('input', { name: 'keyLimit', type: 'number', min: 0, max: 1000000, inputmode: 'numeric', value: r.keyLimit });
    const noteInput = h('input', { name: 'note', maxlength: 200, value: r.note });
    const prefixInput = h('input', { name: 'keyPrefix', maxlength: 10, value: r.keyPrefix });
    const lenInput = h('input', { name: 'keyLength', type: 'number', min: 6, max: 16, inputmode: 'numeric', value: r.keyLength });
    const fmtInput = h('select', { name: 'keyFormat' }, ...FORMATS.map(([v, t]) => h('option', { value: v, ...(v === r.keyFormat ? { selected: true } : {}) }, t)));
    return h('section', { class: 'card rs' },
      h('div', { class: 'rshead' }, h('span', { class: 'nm' }, '@' + r.username),
        h('span', { class: 'chips2' }, h('span', { class: 'badge ' + (r.status === 'active' ? 'ok' : 'off') }, r.status === 'active' ? 'Active' : 'Blocked'),
          h('span', { class: 'badge ' + (r.apiEnabled ? 'ok' : 'off') }, r.apiEnabled ? 'API on' : 'API blocked'))),
      h('div', { class: 'usage' }, h('b', {}, `${r.keysUsed} / ${r.keyLimit}`), ` keys used · ${r.keysLeft} left`, bar,
        h('div', { class: 'days' }, ...[1, 2, 3, 4, 5, 6, 7].map(d => h('span', {}, `${d}d · ${r.usedByDay[d] || 0}`)))),
      h('div', { class: 'meta' }, `Last sign-in: ${when(r.lastLoginAt)} · Last API use: ${when(r.lastApiAt)} · API key: ${r.apiHint || '—'}${r.note ? ' · ' + r.note : ''}`),
      h('div', { class: 'meta' }, `Key style: ${r.keyExample} · Reset page: `, h('code', {}, resetUrl(r)), ' ', h('button', { onclick: () => copy(resetUrl(r)) }, 'Copy')),
      h('div', { class: 'acts' },
        h('button', { onclick: () => run(() => showKeys(r)) }, 'View keys'),
        h('button', { class: r.apiEnabled ? 'danger' : 'primary', onclick: () => run(async () => { await api('PATCH', path(r.username), { apiEnabled: !r.apiEnabled }); toast(r.apiEnabled ? 'API blocked' : 'API enabled'); await load(); }) }, r.apiEnabled ? 'Block API' : 'Enable API'),
        h('button', { class: r.status === 'active' ? 'danger' : 'primary', onclick: () => run(async () => { await api('PATCH', path(r.username), { status: r.status === 'active' ? 'blocked' : 'active' }); toast(r.status === 'active' ? 'Account blocked' : 'Account unblocked'); await load(); }) }, r.status === 'active' ? 'Block account' : 'Unblock')),
      h('details', {}, h('summary', {}, 'Settings'),
        h('div', { class: 'setgrid' }, h('label', {}, 'Key limit', limitInput), h('label', {}, 'Note', noteInput),
          h('label', {}, 'Key starts with', prefixInput), h('label', {}, 'Key length (6–8; dashed 8/12/16)', lenInput), h('label', {}, 'Key style', fmtInput)),
        h('p', { class: 'hint' }, 'Key style only changes keys made from now on. Old keys keep working and can still be reset.'),
        h('div', { class: 'zone' },
          h('button', { class: 'primary', onclick: () => run(async () => { await api('PATCH', path(r.username), { keyLimit: Number(limitInput.value), note: noteInput.value, keyPrefix: prefixInput.value, keyLength: Number(lenInput.value), keyFormat: fmtInput.value }); toast('Saved'); await load(); }) }, 'Save settings'),
          act(r, 'Reset usage to 0', () => confirmDo('Reset usage?', `@${r.username} will get their full limit (${r.keyLimit}) again.`, async () => { await api('PATCH', path(r.username), { resetUsed: true }); toast('Usage reset'); await load(); }, 'Reset')),
          act(r, 'New password', async () => {
            const v = await ask('New password', [{ label: 'Password (min 8)', name: 'password', value: randPw() }], { text: 'They are signed out everywhere.', ok: 'Set' }); if (!v) return;
            await api('POST', path(r.username) + '/password', { password: v.password }); showSecret('Password changed', [['Username', r.username], ['New password', v.password]]); }),
          act(r, 'New API key', () => confirmDo('Generate a new API key?', 'The old key stops working immediately.', async () => {
            const k = await api('POST', path(r.username) + '/api-key'); showSecret('New API key for @' + r.username, [['API key', k.apiKey]]); await load(); }, 'Generate'))),
        h('div', { class: 'zone' },
          act(r, 'Revoke all their keys', () => confirmDo('Revoke ALL keys?', `Every key made by @${r.username} stops working (apps using them are logged out).`, async () => { const x = await api('POST', path(r.username) + '/revoke-keys', { confirm: true }); toast(`Revoked ${x.processed}`); }, 'Revoke all', true), { danger: true }),
          act(r, 'Delete reseller', () => confirmDo('Delete reseller?', `@${r.username} and their API key are removed. Their keys stay valid (revoke them first if you want).`, async () => { await api('DELETE', path(r.username), { confirm: true }); toast('Deleted'); await load(); }, 'Delete', true), { danger: true }))));
  }

  function render() {
    const used = items.reduce((a, r) => a + r.keysUsed, 0);
    $('rsBody').replaceChildren(
      h('div', { class: 'topbar' }, h('span', { class: 'hint' }, `${items.length} reseller${items.length === 1 ? '' : 's'} · ${used} keys made · panel: ${location.origin}/panel/ · reset pages: ${location.origin}/reset/<username>/reset`),
        h('button', { class: 'primary', onclick: () => run(createNew) }, '+ New reseller')),
      ...(items.length ? items.map(card) : [h('p', { class: 'empty' }, 'No resellers yet. Create one — they get a username, password, a key limit and an API key.')]));
  }
  async function load() { const r = await api('GET', '/api/admin/resellers'); items = r.items; render(); }
  window.loadResellers = () => run(load);
})();
