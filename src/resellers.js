'use strict';
// ═══ Resellers ("user admins") ═══════════════════════════════════════════════════════════════
// The OWNER (existing admin password) creates reseller accounts. Each reseller:
//   • signs in to the SENSI MACRO panel (/panel/) with username + password
//   • has a KEY LIMIT set by the owner (total keys they may ever generate) — enforced in a database transaction
//   • gets keys ONLY through the key-fetch API (1–7 day keys). The panel buttons call it, and so can the reseller's own scripts
//     with their API key (X-Api-Key). The owner can block the whole account, or just the API.
// The app's login / licence system is untouched: reseller keys are ordinary `keys` docs (prefix SENSI) with a `resellerId` field.
const crypto = require('crypto');
const util = require('util');
const L = require('./lib');
const S = require('./service');
const { HttpError } = L;
const scrypt = util.promisify(crypto.scrypt);

const COL = 'resellers';
const USER_RE = /^[a-z0-9_]{3,24}$/;
const RESERVED = new Set(['admin', 'owner', 'root', 'api', 'system', 'support']);
const SITE = 'site2';                       // SENSI  →  "SENSI MACRO"
const MAX_DAYS = 7, MAX_PER_REQUEST = 50, MAX_LIMIT = 1000000;
const FAIL_LIMIT = 5, LOCK_MS = 15 * 60 * 1000, SESSION_MS = 8 * 3600 * 1000;
const rand = n => crypto.randomBytes(n).toString('base64url');
const sha256 = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const col = db => db.collection(COL);
const normUser = u => String(u || '').trim().toLowerCase();

// ── passwords (scrypt, per-user salt) ────────────────────────
async function hashPassword(pw) {
    const salt = crypto.randomBytes(16);
    return { passSalt: salt.toString('base64'), passHash: (await scrypt(pw, salt, 64)).toString('base64') };
}
async function checkPassword(pw, doc) {
    const salt = Buffer.from(doc ? doc.passSalt : 'AAAAAAAAAAAAAAAAAAAAAA==', 'base64');     // dummy work when the user doesn't exist (no timing leak)
    const got = await scrypt(String(pw || ''), salt, 64);
    if (!doc) return false;
    const want = Buffer.from(doc.passHash, 'base64');
    return want.length === got.length && crypto.timingSafeEqual(want, got);
}
function validPassword(pw) {
    if (typeof pw !== 'string' || pw.length < 8 || pw.length > 128) throw new HttpError(400, 'Password must be 8–128 characters');
    return pw;
}

// ── API keys: srtx.<username>.<43 random chars> — only the SHA-256 is stored ──
const API_RE = /^srtx\.([a-z0-9_]{3,24})\.([A-Za-z0-9_-]{43})$/;
const makeApiKey = id => { const key = `srtx.${id}.${rand(32)}`; return { key, hash: sha256(key), hint: key.slice(0, 10) + '…' + key.slice(-4) }; };

// ── what the outside world may see of a reseller ──
const view = r => r && ({
    username: r.username, status: r.status, apiEnabled: r.apiEnabled, keyLimit: r.keyLimit, keysUsed: r.keysUsed || 0,
    keysLeft: Math.max(0, r.keyLimit - (r.keysUsed || 0)), usedByDay: r.usedByDay || {}, note: r.note || '', apiHint: r.apiHint || '',
    createdAt: r.createdAt, lastLoginAt: r.lastLoginAt || null, lastApiAt: r.lastApiAt || null,
});

// ═══ OWNER side ═══════════════════════════════════════════════
async function createReseller(db, o = {}, nowMs = Date.now()) {
    const username = normUser(o.username);
    if (!USER_RE.test(username)) throw new HttpError(400, 'Username: 3–24 characters, a–z, 0–9 and _ only');
    if (RESERVED.has(username)) throw new HttpError(400, 'That username is reserved');
    validPassword(o.password);
    const keyLimit = L.intIn(o.keyLimit, 10, 0, MAX_LIMIT, 'keyLimit');
    const api = makeApiKey(username);
    const doc = { username, ...(await hashPassword(o.password)), status: 'active', apiEnabled: true, keyLimit, keysUsed: 0, usedByDay: {},
        sessVer: 1, failCount: 0, lockUntil: 0, apiKeyHash: api.hash, apiHint: api.hint,
        note: String(o.note || '').slice(0, 200), createdAt: new Date(nowMs).toISOString(), lastLoginAt: null, lastApiAt: null };
    try { await col(db).doc(username).create(doc); }
    catch (e) { if (e && (e.code === 6 || /ALREADY_EXISTS/i.test(e.message || ''))) throw new HttpError(409, 'That username already exists'); throw e; }
    return { reseller: view(doc), apiKey: api.key };                 // the API key is shown ONCE
}
async function listResellers(db) {
    return (await col(db).get()).docs.map(d => view(d.data())).sort((a, b) => a.createdAt < b.createdAt ? 1 : -1);
}
async function loadRaw(db, rawId) {
    const id = normUser(rawId);
    if (!USER_RE.test(id)) throw new HttpError(404, 'Reseller not found');
    const snap = await col(db).doc(id).get();
    if (!snap.exists) throw new HttpError(404, 'Reseller not found');
    return { id, ref: col(db).doc(id), data: snap.data() };
}
async function updateReseller(db, rawId, p = {}) {
    const { ref, data } = await loadRaw(db, rawId), u = {};
    if (p.keyLimit !== undefined) u.keyLimit = L.intIn(p.keyLimit, data.keyLimit, 0, MAX_LIMIT, 'keyLimit');
    if (p.status !== undefined) { if (!['active', 'blocked'].includes(p.status)) throw new HttpError(400, 'status must be active or blocked'); u.status = p.status; if (p.status === 'blocked') u.sessVer = (data.sessVer || 1) + 1; }   // blocked → signed out everywhere
    if (p.apiEnabled !== undefined) u.apiEnabled = p.apiEnabled === true || p.apiEnabled === 'true';
    if (p.note !== undefined) u.note = String(p.note).slice(0, 200);
    if (p.resetUsed === true) { u.keysUsed = 0; u.usedByDay = {}; }
    if (!Object.keys(u).length) throw new HttpError(400, 'Nothing to change');
    await ref.update(u);
    return view({ ...data, ...u });
}
async function setPassword(db, rawId, pw) {
    const { ref } = await loadRaw(db, rawId); validPassword(pw);
    const snap = await ref.get(), d = snap.data();
    await ref.update({ ...(await hashPassword(pw)), sessVer: (d.sessVer || 1) + 1, failCount: 0, lockUntil: 0 });
}
async function regenApiKey(db, rawId) {
    const { id, ref } = await loadRaw(db, rawId), api = makeApiKey(id);
    await ref.update({ apiKeyHash: api.hash, apiHint: api.hint });
    return { apiKey: api.key, apiHint: api.hint };
}
async function deleteReseller(db, rawId, { revokeKeys = false } = {}) {
    const { id, ref } = await loadRaw(db, rawId);
    let revoked = 0;
    if (revokeKeys) { const ids = (await keysOf(db, id)).map(k => k.key); if (ids.length) revoked = (await S.revokeKeys(db, ids, `reseller ${id} deleted`)).processed.length; }
    await ref.delete();
    return { revoked };
}
async function revokeAllKeys(db, rawId, reason) {
    const { id } = await loadRaw(db, rawId), ids = (await keysOf(db, id)).map(k => k.key);
    if (!ids.length) return { processed: 0 };
    const r = await S.revokeKeys(db, ids, reason || `owner revoked all keys of ${id}`);
    return { processed: r.processed.length };
}

// ═══ RESELLER side ═════════════════════════════════════════════
async function keysOf(db, id) { return (await db.collection('keys').where('resellerId', '==', id).limit(5000).get()).docs.map(d => d.data()); }
async function listKeys(db, id, nowMs = Date.now()) {
    return (await keysOf(db, id)).sort((a, b) => a.createdAt < b.createdAt ? 1 : -1).slice(0, 500).map(k => {
        const w = S.withStatus(k, nowMs);
        return { key: k.key, days: k.durationDays, status: w.status, createdAt: k.createdAt, expiresAt: k.expiresAt || null, used: !!k.lastUsedAt, deviceLinked: !!k.hwid, label: k.label || '' };
    });
}

// Login with lockout (5 wrong passwords → 15 min lock for that username, on top of the per-IP limiter)
async function login(db, rawUser, password, nowMs = Date.now()) {
    const id = normUser(rawUser), bad = new HttpError(401, 'Wrong username or password');
    const snap = USER_RE.test(id) ? await col(db).doc(id).get() : { exists: false };
    const d = snap.exists ? snap.data() : null;
    if (d && d.lockUntil > nowMs) throw new HttpError(429, `Too many wrong passwords. Try again in ${Math.ceil((d.lockUntil - nowMs) / 60000)} min`);
    const ok = await checkPassword(password, d);
    if (!ok) {
        if (d) { const f = (d.failCount || 0) + 1; await col(db).doc(id).update(f >= FAIL_LIMIT ? { failCount: 0, lockUntil: nowMs + LOCK_MS } : { failCount: f }); }
        throw bad;
    }
    if (d.status === 'blocked') throw new HttpError(403, 'This account is blocked by the owner');
    await col(db).doc(id).update({ failCount: 0, lockUntil: 0, lastLoginAt: new Date(nowMs).toISOString() });
    return d;
}

// Panel sessions: signed cookie token {rid, sv, csrf, exp}. Every request re-reads the account, so a block / password change /
// logout (sessVer bump) takes effect immediately.
function createSessions(secretSource) {
    const secret = crypto.createHmac('sha256', 'srtx-reseller-session-v1').update(String(secretSource)).digest();
    const mac = b => crypto.createHmac('sha256', secret).update(b).digest('base64url');
    return {
        ttlMs: SESSION_MS,
        issue(r, now = Date.now()) {
            const payload = { rid: r.username, sv: r.sessVer || 1, csrf: rand(18), iat: now, exp: now + SESSION_MS };
            const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
            return { token: `${body}.${mac(body)}`, payload };
        },
        parse(token, now = Date.now()) {
            if (typeof token !== 'string' || token.length > 600) return null;
            const [body, sig, extra] = token.split('.');
            if (!body || !sig || extra !== undefined) return null;
            const want = Buffer.from(mac(body)), got = Buffer.from(sig);
            if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
            let p; try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
            return (p && typeof p.exp === 'number' && p.exp > now && USER_RE.test(p.rid || '')) ? p : null;
        },
    };
}
async function accountForSession(db, p) {
    const snap = await col(db).doc(p.rid).get();
    if (!snap.exists) return null;
    const d = snap.data();
    if (d.status !== 'active' || (d.sessVer || 1) !== p.sv) return null;
    return d;
}
async function logoutEverywhere(db, id) {
    const d = (await col(db).doc(id).get()).data();
    await col(db).doc(id).update({ sessVer: (d.sessVer || 1) + 1 });
}
async function accountForApiKey(db, raw, nowMs = Date.now()) {
    const m = API_RE.exec(String(raw || '').trim());
    if (!m) throw new HttpError(401, 'Invalid API key');
    const snap = await col(db).doc(m[1]).get();
    const d = snap.exists ? snap.data() : null;
    const want = Buffer.from(d ? d.apiKeyHash : sha256('x')), got = Buffer.from(sha256(raw.trim()));
    if (!d || want.length !== got.length || !crypto.timingSafeEqual(want, got)) throw new HttpError(401, 'Invalid API key');
    if (d.status !== 'active') throw new HttpError(403, 'Account blocked by the owner');
    if (!d.apiEnabled) throw new HttpError(403, 'API access is blocked by the owner');
    col(db).doc(m[1]).update({ lastApiAt: new Date(nowMs).toISOString() }).catch(() => {});
    return d;
}
async function ownRegenApiKey(db, id) { return regenApiKey(db, id); }

// ═══ THE KEY-FETCH API (panel buttons and /api/v1 both end here) ═══
// days 1–7, count 1–50. The limit is enforced inside a transaction, so parallel requests can never exceed it.
async function fetchKeys(db, id, { days, count, label } = {}, nowMs = Date.now()) {
    const d = L.intIn(days, 0, 1, MAX_DAYS, 'days');
    if (!d) throw new HttpError(400, 'days must be 1 to 7');
    const n = L.intIn(count, 1, 1, MAX_PER_REQUEST, 'count');
    const lab = String(label || '').replace(/[\u0000-\u001f<>]/g, '').slice(0, 60);
    const ref = col(db).doc(id);
    await db.runTransaction(async tx => {
        const snap = await tx.get(ref);
        if (!snap.exists) throw new HttpError(404, 'Account not found');
        const r = snap.data();
        if (r.status !== 'active') throw new HttpError(403, 'Account blocked by the owner');
        if (!r.apiEnabled) throw new HttpError(403, 'API access is blocked by the owner');
        const left = r.keyLimit - (r.keysUsed || 0);
        if (n > left) throw new HttpError(403, left > 0 ? `Key limit: only ${left} key${left === 1 ? '' : 's'} left` : 'Key limit reached — ask the owner for more');
        const byDay = { ...(r.usedByDay || {}) }; byDay[d] = (byDay[d] || 0) + n;
        tx.update(ref, { keysUsed: (r.keysUsed || 0) + n, usedByDay: byDay });
    });
    let made;
    try {
        made = await S.createKeys(db, { siteId: SITE, count: n, duration: d, loginLimit: 1, label: lab, note: `reseller:${id}`, type: 'standard', extra: { resellerId: id } }, nowMs);
    } catch (e) {                                                    // give the quota back if the keys could not be made
        await db.runTransaction(async tx => {
            const s = await tx.get(ref); if (!s.exists) return;
            const r = s.data(), byDay = { ...(r.usedByDay || {}) }; byDay[d] = Math.max(0, (byDay[d] || 0) - n);
            tx.update(ref, { keysUsed: Math.max(0, (r.keysUsed || 0) - n), usedByDay: byDay });
        });
        throw e;
    }
    const after = (await ref.get()).data();
    return { days: d, count: made.length, keys: made.map(k => k.key), keyLimit: after.keyLimit, keysUsed: after.keysUsed, keysLeft: Math.max(0, after.keyLimit - after.keysUsed) };
}

module.exports = { COL, SITE, MAX_DAYS, MAX_PER_REQUEST, USER_RE, view, createReseller, listResellers, updateReseller, setPassword, regenApiKey, deleteReseller,
    revokeAllKeys, listKeys, keysOf, login, createSessions, accountForSession, logoutEverywhere, accountForApiKey, ownRegenApiKey, fetchKeys, loadRaw };
