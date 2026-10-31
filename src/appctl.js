'use strict';
// ═══ App control: server-driven UI / assets / feature flags / gate (patch + maintenance) ═══
// Stage 1 (public):  login-page config + assets (logo, get-key URL, wrong-key sound).
// Stage 2 (key-gated): overlay menu config, names, logos, macro images, sounds, feature toggles.
// Every stage-2 call re-checks the key in the database (not just the token) and the APK certificate.
const crypto = require('crypto');
const L = require('./lib');
const { HttpError } = L;

// ── Asset slots (fixed registry: the APK asks for these names, admin uploads into them) ──
const SLOTS = {
    // stage 1 — before login
    login_logo:       { stage: 1, kind: 'image' },
    login_bg:         { stage: 1, kind: 'image' },
    sound_wrong_key:  { stage: 1, kind: 'audio' },
    // stage 2 — after the key was accepted
    app_logo:         { stage: 2, kind: 'image' },
    overlay_logo:     { stage: 2, kind: 'image' },
    macro_e_base:     { stage: 2, kind: 'image' },
    macro_e_marks:    { stage: 2, kind: 'image' },
    macro_g_base:     { stage: 2, kind: 'image' },
    macro_g_marks:    { stage: 2, kind: 'image' },
    sharingan:        { stage: 2, kind: 'image' },
    sound_success:    { stage: 2, kind: 'audio' },
    sound_fail:       { stage: 2, kind: 'audio' },
    sound_restore:    { stage: 2, kind: 'audio' },
};
const MAX_ASSET = 700 * 1024;                       // Firestore doc limit is 1 MiB; base64 adds ~33%

// Detect the real type from the bytes (never trust the client's content-type).
function sniff(buf) {
    if (buf.length < 12) return null;
    if (buf.slice(0, 4).toString('latin1') === 'RIFF' && buf.slice(8, 12).toString('latin1') === 'WEBP') return { mime: 'image/webp', kind: 'image' };
    if (buf[0] === 0x89 && buf.slice(1, 4).toString('latin1') === 'PNG') return { mime: 'image/png', kind: 'image' };
    if (buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return { mime: 'image/jpeg', kind: 'image' };
    if (buf.slice(0, 3).toString('latin1') === 'ID3' || (buf[0] === 0xff && (buf[1] & 0xe0) === 0xe0)) return { mime: 'audio/mpeg', kind: 'audio' };
    if (buf.slice(0, 4).toString('latin1') === 'OggS') return { mime: 'audio/ogg', kind: 'audio' };
    return null;
}

// ── Config defaults + strict sanitising (admin input is never stored as-is) ──
const FEATURES = ['fullScreenSensi', 'sensiZone', 'macroE', 'macroG', 'aimMarker', 'gtFix', 'fps120', 'touchBoost', 'ramBooster'];
const DEFAULTS = () => ({
    rev: 0, updatedAt: null,
    gate: { mode: 'none', title: '', message: '', url: '', until: null, minVersionCode: 0 },
    stage1: { appName: 'SENSI MACRO', loginTitle: 'LICENSE LOGIN', loginSubtitle: 'Enter your key to continue',
              getKeyUrl: '', getKeyLabel: 'GET KEY', accent: '#00E5FF' },
    stage2: { appName: 'SENSI MACRO', overlayName: 'SENSI MACRO', overlayTitle: 'SENSI MACRO', motd: '', accent: '#00E5FF',
              features: Object.fromEntries(FEATURES.map(f => [f, true])) },
    security: { enforceCert: false, allowedCertSha256: [] },
});

const str = (v, max, def = '') => (v === undefined || v === null) ? def : String(v).replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f]/g, '').trim().slice(0, max);
function httpsUrl(v, name) {
    const s = str(v, 500); if (!s) return '';
    let u; try { u = new URL(s); } catch { throw new HttpError(400, `${name} is not a valid URL`); }
    if (u.protocol !== 'https:') throw new HttpError(400, `${name} must start with https://`);
    return u.toString();
}
const color = (v, def) => { const s = str(v, 9, def); if (!/^#[0-9a-fA-F]{6}$/.test(s)) throw new HttpError(400, 'Colour must look like #00E5FF'); return s; };
const normCert = c => String(c || '').replace(/[^0-9a-fA-F]/g, '').toLowerCase();

function sanitizeSection(name, v, cur, nowMs = Date.now()) {
    v = v && typeof v === 'object' ? v : {};
    const pick = (k, max) => str(v[k], max, cur[k]);
    switch (name) {
        case 'gate': {
            const mode = ['none', 'notice', 'patch', 'maintenance'].includes(v.mode) ? v.mode : cur.mode;
            let until = cur.until;
            if (v.minutes !== undefined && v.minutes !== '') {               // "closed for N minutes" → absolute end time
                const m = L.intIn(v.minutes, null, 1, 10080, 'minutes'); until = new Date(nowMs + m * 60000).toISOString();
            } else if (v.until !== undefined) until = v.until ? new Date(v.until).toISOString() : null;
            if (until && Number.isNaN(new Date(until).getTime())) throw new HttpError(400, 'until is not a valid date');
            if (mode !== 'maintenance') until = null;
            return { mode, title: pick('title', 80), message: pick('message', 400), url: v.url === undefined ? cur.url : httpsUrl(v.url, 'Download link'),
                     until, minVersionCode: v.minVersionCode === undefined ? cur.minVersionCode : L.intIn(v.minVersionCode, 0, 0, 1000000, 'minVersionCode') };
        }
        case 'stage1': return { appName: pick('appName', 40), loginTitle: pick('loginTitle', 40), loginSubtitle: pick('loginSubtitle', 120),
            getKeyUrl: v.getKeyUrl === undefined ? cur.getKeyUrl : httpsUrl(v.getKeyUrl, 'Get-key URL'), getKeyLabel: pick('getKeyLabel', 24),
            accent: v.accent === undefined ? cur.accent : color(v.accent, cur.accent) };
        case 'stage2': {
            const features = { ...cur.features };
            if (v.features && typeof v.features === 'object') for (const [k, on] of Object.entries(v.features)) {
                if (!/^[A-Za-z][A-Za-z0-9_]{0,31}$/.test(k)) throw new HttpError(400, `Bad feature name: ${k.slice(0, 20)}`);
                features[k] = on === true;
            }
            if (Object.keys(features).length > 40) throw new HttpError(400, 'Too many features');
            return { appName: pick('appName', 40), overlayName: pick('overlayName', 40), overlayTitle: pick('overlayTitle', 40), motd: pick('motd', 200),
                accent: v.accent === undefined ? cur.accent : color(v.accent, cur.accent), features };
        }
        case 'security': {
            const list = v.allowedCertSha256 === undefined ? cur.allowedCertSha256
                : [...new Set((Array.isArray(v.allowedCertSha256) ? v.allowedCertSha256 : String(v.allowedCertSha256).split(/[\s,]+/)).map(normCert).filter(Boolean))];
            if (list.some(h => h.length !== 64)) throw new HttpError(400, 'Each certificate hash must be 64 hex characters (SHA-256)');
            if (list.length > 10) throw new HttpError(400, 'At most 10 certificate hashes');
            const enforceCert = v.enforceCert === undefined ? cur.enforceCert : v.enforceCert === true;
            if (enforceCert && !list.length) throw new HttpError(400, 'Add at least one certificate hash before enforcing');
            return { enforceCert, allowedCertSha256: list };
        }
        default: throw new HttpError(400, 'Unknown section');
    }
}

const cfgRef = db => db.collection('meta').doc('app_config');
async function getConfig(db) {
    const snap = await cfgRef(db).get(), d = DEFAULTS();
    if (!snap.exists) return d;
    const s = snap.data();
    return { rev: s.rev || 0, updatedAt: s.updatedAt || null,
        gate: { ...d.gate, ...s.gate }, stage1: { ...d.stage1, ...s.stage1 },
        stage2: { ...d.stage2, ...s.stage2, features: { ...d.stage2.features, ...(s.stage2 && s.stage2.features) } },
        security: { ...d.security, ...s.security } };
}
async function saveSection(db, name, body, nowMs = Date.now()) {
    const cur = await getConfig(db), next = { ...cur, [name]: sanitizeSection(name, body, cur[name], nowMs), rev: cur.rev + 1, updatedAt: new Date(nowMs).toISOString() };
    await cfgRef(db).set(next);
    return next;
}

// ── Gate: patch notice / maintenance timer (checked on EVERY app call, so a bypassed UI gets nothing) ──
function evalGate(cfg, versionCode = 0, nowMs = Date.now()) {
    const g = cfg.gate, vc = Number(versionCode) || 0;
    if (g.mode === 'maintenance') {
        const end = g.until ? new Date(g.until).getTime() : null;
        if (end === null || end > nowMs)
            return { blocked: true, type: 'maintenance', title: g.title || 'Under maintenance', message: g.message || 'The app is closed for a while. Please wait.',
                     until: g.until, remainingMs: end === null ? null : end - nowMs, url: '' };
        // timer ran out → app is normal again, no admin action needed
    }
    if (g.mode === 'patch' || (g.minVersionCode > 0 && vc < g.minVersionCode))
        return { blocked: true, type: 'patch', title: g.title || 'Update required', message: g.message || 'This version is patched. Download the new version.', url: g.url, until: null, remainingMs: null };
    if (g.mode === 'notice') return { blocked: false, notice: { title: g.title, message: g.message, url: g.url } };
    return { blocked: false };
}

// ── APK certificate check ("APK modded") ──
function checkCert(cfg, cert) {
    if (!cfg.security.enforceCert) return;
    const c = normCert(cert);
    if (c.length !== 64 || !cfg.security.allowedCertSha256.includes(c)) throw new AppDeny('APK_MODDED', 'APK modified or not the official build');
}
class AppDeny extends Error { constructor(code, message, status = 403) { super(message); this.code = code; this.status = status; } }

// ── Key check that does NOT consume a login (read-only; used by stage 2) ──
async function peekKey(db, rawKey, hwid, nowMs = Date.now()) {
    const key = String(rawKey || '').trim().toUpperCase();
    if (!L.KEY_RE.test(key)) throw new AppDeny('KEY_NOT_FOUND', 'Key not found');
    const snap = await db.collection('keys').doc(key).get();
    if (!snap.exists) throw new AppDeny('KEY_NOT_FOUND', 'Key not found');
    const kd = snap.data();
    if (kd.status === 'revoked') throw new AppDeny('KEY_INVALID', 'Key revoked');
    if (kd.expiresAt && nowMs > new Date(kd.expiresAt).getTime()) throw new AppDeny('KEY_INVALID', 'Key expired');
    if (!kd.hwid || !hwid || kd.hwid !== hwid) throw new AppDeny('KEY_INVALID', 'Key is not bound to this device');
    return kd;
}

// ── Short-lived stage-2 session tokens (HMAC, bound to key + device) ──
function createTokens(secretSource, ttlMs = 10 * 60 * 1000) {
    const secret = crypto.createHmac('sha256', 'srtx-app-session-v1').update(String(secretSource)).digest();
    const mac = b => crypto.createHmac('sha256', secret).update(b).digest('base64url');
    return {
        ttlMs,
        issue(key, hwid, now = Date.now()) {
            const body = Buffer.from(JSON.stringify({ k: key, h: hwid, iat: now, exp: now + ttlMs, n: crypto.randomBytes(6).toString('base64url') })).toString('base64url');
            return { token: `${body}.${mac(body)}`, expiresAt: new Date(now + ttlMs).toISOString() };
        },
        parse(token, now = Date.now()) {
            if (typeof token !== 'string' || token.length > 500) return null;
            const [body, sig, extra] = token.split('.'); if (!body || !sig || extra !== undefined) return null;
            const want = Buffer.from(mac(body)), got = Buffer.from(sig);
            if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
            let p; try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
            return p && p.exp > now ? p : null;
        },
    };
}

// ── Assets ──
const assetsCol = db => db.collection('app_assets');
async function putAsset(db, slot, b64, nowMs = Date.now()) {
    if (!SLOTS[slot]) throw new HttpError(400, 'Unknown asset slot');
    if (typeof b64 !== 'string' || !/^[A-Za-z0-9+/=\s]+$/.test(b64)) throw new HttpError(400, 'File data must be base64');
    const buf = Buffer.from(b64, 'base64');
    if (!buf.length) throw new HttpError(400, 'Empty file');
    if (buf.length > MAX_ASSET) throw new HttpError(413, `File too large (max ${Math.round(MAX_ASSET / 1024)} KB)`);
    const t = sniff(buf);
    if (!t || t.kind !== SLOTS[slot].kind) throw new HttpError(400, `This slot needs ${SLOTS[slot].kind === 'image' ? 'an image (webp, png or jpg)' : 'a sound (mp3 or ogg)'}`);
    const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
    const doc = { slot, stage: SLOTS[slot].stage, mime: t.mime, size: buf.length, sha256, b64: buf.toString('base64'), updatedAt: new Date(nowMs).toISOString() };
    await assetsCol(db).doc(slot).set(doc);
    return { slot, stage: doc.stage, mime: doc.mime, size: doc.size, sha256, updatedAt: doc.updatedAt };
}
async function listAssets(db) {
    const docs = (await assetsCol(db).get()).docs.map(d => d.data());
    const meta = d => ({ slot: d.slot, stage: d.stage, mime: d.mime, size: d.size, sha256: d.sha256, updatedAt: d.updatedAt });
    return Object.keys(SLOTS).map(slot => { const d = docs.find(x => x.slot === slot); return d ? meta(d) : { slot, stage: SLOTS[slot].stage, kind: SLOTS[slot].kind, missing: true }; });
}
async function deleteAsset(db, slot) {
    if (!SLOTS[slot]) throw new HttpError(400, 'Unknown asset slot');
    await assetsCol(db).doc(slot).delete();
}
async function getAssetFile(db, slot) {
    if (!SLOTS[slot]) return null;
    const s = await assetsCol(db).doc(slot).get(); if (!s.exists) return null;
    const d = s.data(); return { mime: d.mime, sha256: d.sha256, buf: Buffer.from(d.b64, 'base64'), stage: SLOTS[slot].stage };
}

// ── Manifests the app downloads ──
async function manifest(db, cfg, stage) {
    const assets = (await listAssets(db)).filter(a => a.stage === stage && !a.missing)
        .map(a => ({ slot: a.slot, sha256: a.sha256, size: a.size, mime: a.mime }));
    return { rev: cfg.rev, config: stage === 1 ? cfg.stage1 : cfg.stage2, assets };
}

module.exports = { SLOTS, FEATURES, MAX_ASSET, DEFAULTS, sniff, sanitizeSection, getConfig, saveSection, evalGate, checkCert, AppDeny, peekKey,
    createTokens, putAsset, listAssets, deleteAsset, getAssetFile, manifest, normCert };
