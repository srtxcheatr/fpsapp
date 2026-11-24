'use strict';
// ═══ Device profile: saved next to the HWID, used to recognise the SAME phone after the app is deleted + reinstalled ═══
// (HWID = ANDROID_ID changes when the APK signing key changes or on factory reset; the hardware profile does not.)
const FIELDS = { name: 60, manufacturer: 40, brand: 40, model: 60, device: 40, board: 40, hardware: 40, product: 40,
                 buildId: 40, fingerprint: 160, kernel: 100, release: 16, sdk: 3, screen: 16 };
const clean = (v, max) => String(v === undefined || v === null ? '' : v).replace(/[\u0000-\u001f\u007f]/g, '').trim().slice(0, max);

// Never trust the client: whitelist fields, cap lengths. Returns null when nothing usable was sent.
function sanitizeDevice(d) {
    if (!d || typeof d !== 'object' || Array.isArray(d)) return null;
    const out = {};
    for (const [k, max] of Object.entries(FIELDS)) out[k] = clean(d[k], max);
    return out.model || out.device || out.fingerprint ? out : null;
}

const norm = s => String(s || '').toLowerCase().replace(/\s+/g, ' ').trim();
const STABLE = ['manufacturer', 'brand', 'model', 'device', 'board', 'hardware'];   // identical on the same phone model
const SOFT   = ['fingerprint', 'kernel', 'name', 'release'];                         // identical on the SAME phone (kernel/build/name)

// Same phone? ALL stable hardware fields must match (≥4 present) AND ≥2 of the soft fields (build, kernel, device name, Android version).
function matchDevice(stored, incoming) {
    if (!stored || !incoming) return { match: false, reason: 'no-profile' };
    const present = STABLE.filter(f => norm(stored[f]) && norm(incoming[f]));
    if (present.length < 4) return { match: false, reason: 'too-little-hardware-info' };
    const bad = present.filter(f => norm(stored[f]) !== norm(incoming[f]));
    if (bad.length) return { match: false, reason: 'hardware-differs:' + bad.join(',') };
    const same = SOFT.filter(f => norm(stored[f]) && norm(stored[f]) === norm(incoming[f]));
    if (same.length < 2) return { match: false, reason: 'software-differs' };
    return { match: true, reason: 'same-device', same };
}
module.exports = { FIELDS, sanitizeDevice, matchDevice };
