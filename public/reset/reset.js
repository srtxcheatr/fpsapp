'use strict';
// Reset page. Works with every key style (SRT_ABCDEF, XE_AB_CD_EF_GH, …): the key is sent exactly as typed — no prefix is added or forced.
const app = document.getElementById('app'), user = app.dataset.user || '';
const inp = document.getElementById('key'), btn = document.getElementById('go'), out = document.getElementById('result');
const show = (kind, text) => { out.hidden = false; out.className = kind; out.textContent = text; };
inp.addEventListener('input', () => { inp.value = inp.value.toUpperCase().replace(/[^A-Z0-9_-]/g, ''); });
inp.addEventListener('keydown', e => { if (e.key === 'Enter') go(); });
btn.addEventListener('click', go);
async function go() {
  const key = inp.value.trim().toUpperCase();
  if (key.length < 6) return show('warn', 'Enter your full key first.');
  if (!confirm(`Reset device for:\n${key}\n\nYour key's timer will NOT be affected.\nYou can only do this once per 24 hours.\n\nContinue?`)) return;
  btn.disabled = true; btn.textContent = 'Resetting…'; out.hidden = true;
  try {
    const res = await fetch('/api/reset-device', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ key, ...(user ? { reseller: user } : {}) }) });
    const d = await res.json().catch(() => ({}));
    const msg = d.message || d.error || 'Reset failed';
    if (d.success) show('ok', msg); else if (/cooldown/i.test(msg) || res.status === 429) show('warn', msg); else show('bad', msg);
  } catch { show('bad', 'Connection failed. The server may be waking up — wait a minute and try again.'); }
  btn.disabled = false; btn.textContent = 'Reset my device';
}
