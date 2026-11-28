'use strict';
// "App control" tab. Uses helpers from admin.js ($, h, api, run, toast, confirmDo). Never uses innerHTML.
(() => {
  let cfg = null, assets = [], featureNames = [];
  const SLOT_LABEL = {
    login_logo: 'Login page logo', login_bg: 'Login page background', sound_wrong_key: 'Wrong-key sound',
    app_logo: 'App logo (dashboard / splash)', overlay_logo: 'Overlay logo', macro_e_base: 'Macro E button · base', macro_e_marks: 'Macro E button · marks',
    macro_g_base: 'Macro G button · base', macro_g_marks: 'Macro G button · marks', sharingan: 'Sensi zone icon', sound_success: 'Sound · inject success',
    sound_fail: 'Sound · inject failed', sound_restore: 'Sound · restore',
  };
  const FEATURE_LABEL = { fullScreenSensi: 'Full Screen Sensi', sensiZone: 'Sensi Zone', macroE: 'Macro E button', macroG: 'Macro G button',
    aimMarker: 'Aim marker', gtFix: 'G.T FIX', fps120: '120 FPS', touchBoost: 'Touch boost', ramBooster: 'RAM booster' };
  const field = (label, name, val, attrs = {}) => h('label', {}, label, h('input', { name, value: val ?? '', autocomplete: 'off', ...attrs }));
  const form = (id, kids) => h('form', { id, onsubmit: e => e.preventDefault() }, kids);
  const formData = f => Object.fromEntries([...f.querySelectorAll('input[name],select[name],textarea[name]')]
    .filter(i => i.type !== 'checkbox').map(i => [i.name, i.value]));
  const save = async (section, body, msg = 'Saved') => { const r = await api('PUT', `/api/admin/app/config/${section}`, body); cfg = r.config; toast(msg); render(); };

  function gateCard() {
    const g = cfg.gate, live = g.mode !== 'none' && !(g.mode === 'maintenance' && g.until && new Date(g.until) < Date.now());
    const f = form('gateForm', [
      live ? h('div', { class: 'live on' }, g.mode === 'maintenance' ? `Maintenance ON${g.until ? ' until ' + g.until.replace('T', ' ').slice(0, 16) + ' UTC' : ' (no end time)'}`
        : g.mode === 'patch' ? 'Patch screen ON — the app is blocked' : 'Notice ON (app still opens)') : h('div', { class: 'live' }, 'Off — app works normally'),
      h('label', {}, 'What should the app show?', h('select', { name: 'mode' },
        ...[['none', 'Nothing (normal)'], ['patch', 'Patched version — download new (app stays closed)'], ['maintenance', 'Closed for a while (timer)'], ['notice', 'Notice only (app still opens)']]
          .map(([v, t]) => h('option', { value: v, selected: g.mode === v }, t)))),
      field('Title', 'title', g.title, { maxlength: 80, placeholder: 'This version is patch' }),
      h('label', {}, 'Message', h('textarea', { name: 'message', rows: 3, maxlength: 400, placeholder: 'New download below' }, g.message)),
      field('Download link (https)', 'url', g.url, { type: 'url', placeholder: 'https://…' }),
      field('Closed for (minutes) — maintenance only', 'minutes', '', { type: 'number', min: 1, max: 10080, inputmode: 'numeric', placeholder: g.until ? 'leave empty to keep the current timer' : 'e.g. 60' }),
      field('Force update below version code (0 = off)', 'minVersionCode', g.minVersionCode, { type: 'number', min: 0, inputmode: 'numeric' }),
      h('div', { class: 'row' },
        h('button', { class: 'primary', onclick: () => run(() => save('gate', formData($('gateForm')), 'Applied — apps see it on their next check')) }, 'Apply'),
        h('button', { onclick: () => run(() => save('gate', { mode: 'none', title: '', message: '', url: '', minVersionCode: 0 }, 'Turned off')) }, 'Turn off')),
    ]);
    return h('section', { class: 'card' }, h('h2', {}, 'Message / patch / maintenance'),
      h('p', { class: 'hint' }, 'Shown to every app before anything else loads. Maintenance ends by itself when the timer runs out.'), f);
  }
  function stage1Card() {
    const c = cfg.stage1;
    return h('section', { class: 'card' }, h('h2', {}, 'Step 1 · Login page'),
      h('p', { class: 'hint' }, 'Downloaded when the app first opens (before any key).'),
      form('s1Form', [field('App name', 'appName', c.appName, { maxlength: 40 }), field('Login title', 'loginTitle', c.loginTitle, { maxlength: 40 }),
        field('Get-key URL (https)', 'getKeyUrl', c.getKeyUrl, { type: 'url' }),
        field('Get-key button text', 'getKeyLabel', c.getKeyLabel, { maxlength: 24 }),
        h('div', { class: 'row' }, h('button', { class: 'primary', onclick: () => run(() => save('stage1', formData($('s1Form')))) }, 'Save')),
        assetRows(1)]));
  }
  function stage2Card() {
    const c = cfg.stage2, names = [...new Set([...featureNames, ...Object.keys(c.features)])];
    return h('section', { class: 'card' }, h('h2', {}, 'Step 2 · After login (overlay, design, sounds)'),
      h('p', { class: 'hint' }, 'Only sent after the key is accepted — checked again on the server.'),
      form('s2Form', [field('App name', 'appName', c.appName, { maxlength: 40 }), field('Overlay name', 'overlayName', c.overlayName, { maxlength: 40 }),
        field('Overlay title', 'overlayTitle', c.overlayTitle, { maxlength: 40 }), field('Message of the day (optional)', 'motd', c.motd, { maxlength: 200 }),
        h('b', {}, 'Features (turn on / off for everyone)'),
        ...names.map(n => h('label', { class: 'switch' }, h('input', { type: 'checkbox', 'data-feature': n, checked: c.features[n] !== false }), FEATURE_LABEL[n] || n)),
        h('div', { class: 'row' }, h('button', { class: 'primary', onclick: () => run(() => save('stage2', { ...formData($('s2Form')),
          features: Object.fromEntries([...$('s2Form').querySelectorAll('[data-feature]')].map(i => [i.dataset.feature, i.checked])) })) }, 'Save')),
        assetRows(2)]));
  }
  function assetRows(stage) {
    return h('div', {}, h('b', {}, 'Files'), ...assets.filter(a => a.stage === stage).map(a => {
      const pick = h('input', { type: 'file', hidden: true, accept: a.kind === 'audio' || (a.mime || '').startsWith('audio') ? 'audio/mpeg,audio/ogg' : 'image/webp,image/png,image/jpeg',
        onchange: e => run(() => upload(a.slot, e.target.files[0])) });
      return h('div', { class: 'slot' },
        h('div', { class: 'nm' }, SLOT_LABEL[a.slot] || a.slot, h('br'), h('small', {}, a.missing ? 'not uploaded' : `${a.mime} · ${(a.size / 1024).toFixed(1)} KB · ${a.sha256.slice(0, 8)}`)),
        pick, h('button', { type: 'button', onclick: () => pick.click() }, a.missing ? 'Upload' : 'Replace'),
        a.missing ? null : h('button', { type: 'button', class: 'danger', onclick: () => confirmDo('Remove file?', `${SLOT_LABEL[a.slot] || a.slot} will no longer be sent to apps.`, () => run(async () => { await api('DELETE', `/api/admin/app/assets/${a.slot}`); toast('Removed'); await load(); }), 'Remove', true) }, 'Remove'));
    }));
  }
  function securityCard() {
    const c = cfg.security;
    return h('section', { class: 'card' }, h('h2', {}, 'APK check (modded APK)'),
      h('p', { class: 'hint' }, 'Paste the SHA-256 of your APK signing certificate (one per line). When enforced, any app signed with another key gets “APK modded” and no files.'),
      form('secForm', [h('label', {}, 'Allowed certificate SHA-256', h('textarea', { name: 'allowedCertSha256', rows: 3, placeholder: 'AB:CD:…' }, c.allowedCertSha256.join('\n'))),
        h('label', { class: 'switch' }, h('input', { type: 'checkbox', id: 'enfCert', checked: c.enforceCert }), 'Enforce (reject apps signed with other keys)'),
        h('div', { class: 'row' }, h('button', { class: 'primary', onclick: () => run(() => save('security', { allowedCertSha256: $('secForm').elements.allowedCertSha256.value, enforceCert: $('enfCert').checked })) }, 'Save'))]));
  }
  async function upload(slot, file) {
    if (!file) return;
    if (file.size > 700 * 1024) throw new Error('File is bigger than 700 KB');
    const data = await new Promise((res, rej) => { const r = new FileReader(); r.onload = () => res(String(r.result).split(',')[1]); r.onerror = () => rej(new Error('Could not read file')); r.readAsDataURL(file); });
    await api('POST', '/api/admin/app/assets', { slot, data }); toast('Uploaded'); await load();
  }
  function render() { $('appBody').replaceChildren(gateCard(), stage1Card(), stage2Card(), securityCard()); }
  async function load() { const r = await api('GET', '/api/admin/app/config'); cfg = r.config; assets = r.assets; featureNames = r.features; render(); }
  window.loadAppControl = () => run(load);
})();
