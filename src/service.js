'use strict';
const L = require('./lib');
const { HttpError, DAY, KEY_RE, SITE_PREFIXES } = L;

const BULK_MAX = 500;
const ALREADY_EXISTS = e => e && (e.code === 6 || /ALREADY_EXISTS/i.test(e.message || ''));
const normKey = k => String(k || '').trim().toUpperCase();
const keysCol = db => db.collection('keys');

// ═══ PUBLIC: verify (called by the Android app) ═════════════════
// Response shape and messages are unchanged.  Runs in a transaction, so a key that was
// revoked/deleted can never be "refreshed" by a concurrent login, and login limits can't race.
// "Key revoked" deliberately avoids the words expired/hwid/device/limit, so the app's classify()
// maps it to REVOKED (login screen, session wiped).
async function verifyKey(db, rawKey, rawHwid, nowMs = Date.now()) {
    const key = normKey(rawKey);
    const hwid = String(rawHwid || '').trim().slice(0, 128);
    if (!KEY_RE.test(key)) return { body: { valid: false, message: 'Invalid key format' }, fail: true };

    const ref = keysCol(db).doc(key);
    return db.runTransaction(async tx => {
        const snap = await tx.get(ref);
        if (!snap.exists) return { body: { valid: false, message: 'Key not found' }, fail: true };
        const kd = snap.data(), now = new Date(nowMs), updates = {};

        if (kd.status === 'revoked') return { body: { valid: false, message: 'Key revoked' } };

        let expiresAt = kd.expiresAt || null;
        if (!kd.lastUsedAt && !expiresAt) {                          // timer starts on first login
            expiresAt = new Date(nowMs + (kd.durationDays || 7) * DAY).toISOString();
            updates.expiresAt = expiresAt;
        }
        if (expiresAt && now > new Date(expiresAt))
            return { body: { valid: false, message: 'Key expired', expiredAt: expiresAt } };

        const hwidMismatch = kd.hwid && hwid && kd.hwid !== hwid;
        const sameDevice = kd.hwid && hwid && kd.hwid === hwid;
        if (hwidMismatch) return { body: { valid: false, message: 'HWID mismatch — different device' }, fail: true };

        if (!sameDevice) {
            if (kd.loginLimit > 0 && (kd.loginCount || 0) >= kd.loginLimit)
                return { body: { valid: false, message: 'Login limit reached' } };
            if (!kd.hwid && hwid) updates.hwid = hwid;
            updates.loginCount = (kd.loginCount || 0) + 1;
        }
        updates.lastUsedAt = now.toISOString();
        tx.update(ref, updates);

        const msLeft = expiresAt ? new Date(expiresAt) - now : null;
        return { body: {
            valid: true, message: 'Key valid', key: kd.key, prefix: kd.prefix || 'SRT', siteId: kd.siteId || 'site1',
            expiresAt, daysLeft: msLeft ? Math.ceil(msLeft / DAY) : null,
            loginCount: updates.loginCount ?? kd.loginCount, loginLimit: kd.loginLimit,
            type: kd.type, label: kd.label || '',
        } };
    });
}

// ═══ ADMIN: create ═════════════════════════════════════════════
async function createKeys(db, o = {}, nowMs = Date.now()) {
    const siteId = SITE_PREFIXES[o.siteId] ? o.siteId : 'site1';
    const count = L.intIn(o.count, 1, 1, 100, 'count');
    const length = L.intIn(o.length, 8, 6, 32, 'length');
    const durationDays = L.intIn(o.duration ?? o.durationDays, 7, 1, 3650, 'duration');
    const loginLimit = L.intIn(o.loginLimit, 1, 1, 1000, 'loginLimit');
    const custom = o.customKey && String(o.customKey).trim();
    if (custom && count > 1) throw new HttpError(400, 'customKey can only be used with count = 1');
    const fixedExpiry = o.expiresAt ? L.parseFutureDate(o.expiresAt, nowMs) : null;

    const base = key => ({
        key, prefix: key.split('_')[0], siteId: undefined, createdAt: new Date(nowMs).toISOString(),
        expiresAt: fixedExpiry, durationDays, loginLimit, loginCount: 0, type: o.type === 'standard' ? 'standard' : 'custom', status: 'active',
        label: String(o.label || '').slice(0, 60), note: String(o.note || '').slice(0, 200),
        hwid: null, lastUsedAt: null,
    });
    const make = async (build, retries) => {
        for (let i = 0; i < retries; i++) {
            const c = build();
            const data = { ...base(c.key), siteId: c.siteId };
            try { await keysCol(db).doc(c.key).create(data); return data; }       // atomic: fails if it exists
            catch (e) { if (!ALREADY_EXISTS(e)) throw e; }
        }
        return null;
    };

    if (custom) {
        const p = L.parseCustomKey(custom, siteId);
        const data = await make(() => p, 1);
        if (!data) throw new HttpError(400, 'Key already exists');
        return [data];
    }
    const out = [];
    for (let i = 0; i < count; i += 10) {                                         // small parallel chunks
        const n = Math.min(10, count - i);
        const part = await Promise.all(Array.from({ length: n }, () =>
            make(() => ({ key: L.generateKey(SITE_PREFIXES[siteId], length), siteId }), 10)));
        if (part.includes(null)) throw new HttpError(500, 'Could not generate a unique key');
        out.push(...part);
    }
    return out;
}

// ═══ ADMIN: list / search / filter / stats ═════════════════════
const FILTERS = {
    all:     () => true,
    active:  (k, now) => L.deriveStatus(k, now) === 'active',
    expired: (k, now) => L.deriveStatus(k, now) === 'expired',
    revoked: (k, now) => L.deriveStatus(k, now) === 'revoked',
    unused:  (k, now) => L.deriveStatus(k, now) === 'active' && L.isUnused(k),
    full:    (k, now) => L.deriveStatus(k, now) === 'active' && L.isFull(k),
};
const withStatus = (k, now) => ({ ...k, status: L.deriveStatus(k, now), full: L.isFull(k) });

async function allKeys(db) { return (await keysCol(db).get()).docs.map(d => d.data()); }

function filterKeys(list, q = {}, now = Date.now()) {
    const status = FILTERS[q.status] ? q.status : 'all';
    const s = String(q.search || '').trim().toLowerCase().slice(0, 100);
    let out = list.filter(k => FILTERS[status](k, now));
    if (q.site) out = out.filter(k => k.siteId === q.site || k.prefix === SITE_PREFIXES[q.site]);
    if (q.type) out = out.filter(k => k.type === q.type);
    if (q.createdFrom) out = out.filter(k => (k.createdAt || '') >= new Date(q.createdFrom).toISOString());
    if (q.createdTo)   out = out.filter(k => (k.createdAt || '') <= new Date(q.createdTo).toISOString());
    if (s) out = out.filter(k => [k.key, k.label, k.note, k.hwid].some(v => String(v || '').toLowerCase().includes(s)));
    const sortKey = { created: 'createdAt', expires: 'expiresAt', used: 'lastUsedAt', key: 'key' }[q.sort] || 'createdAt';
    const dir = q.order === 'asc' ? 1 : -1;
    return out.sort((a, b) => dir * String(a[sortKey] || '').localeCompare(String(b[sortKey] || '')));
}

async function searchKeys(db, q = {}, now = Date.now()) {
    const rows = filterKeys(await allKeys(db), q, now);
    const limit = Math.min(Math.max(parseInt(q.limit) || 50, 1), 200);
    const offset = Math.max(parseInt(q.offset) || 0, 0);
    return { total: rows.length, limit, offset, items: rows.slice(offset, offset + limit).map(k => withStatus(k, now)) };
}

async function matchingKeyIds(db, q = {}, now = Date.now(), cap = 5000) {
    const rows = filterKeys(await allKeys(db), q, now);
    return { total: rows.length, capped: rows.length > cap, keys: rows.slice(0, cap).map(k => k.key) };
}

async function stats(db, now = Date.now()) {
    const list = await allKeys(db);
    const st = k => L.deriveStatus(k, now);
    const bySite = {};
    for (const [id, prefix] of Object.entries(SITE_PREFIXES))
        bySite[prefix] = list.filter(k => k.siteId === id || k.prefix === prefix).length;
    return {
        total: list.length,
        active:  list.filter(k => st(k) === 'active' && !L.isFull(k)).length,   // keys that can still take a new device
        maxed:   list.filter(k => st(k) === 'active' && L.isFull(k)).length,
        expired: list.filter(k => st(k) === 'expired').length,
        revoked: list.filter(k => st(k) === 'revoked').length,
        unused:  list.filter(k => st(k) === 'active' && L.isUnused(k)).length,
        standard: list.filter(k => k.type === 'standard').length,
        custom:   list.filter(k => k.type === 'custom').length,
        bySite,
    };
}

// ═══ ADMIN: mutations (single + bulk share one path) ═══════════
function cleanKeyList(keys) {
    if (!Array.isArray(keys) || !keys.length) throw new HttpError(400, 'keys must be a non-empty array');
    if (keys.length > BULK_MAX) throw new HttpError(400, `At most ${BULK_MAX} keys per request`);
    const uniq = [...new Set(keys.map(normKey))];
    if (uniq.some(k => !KEY_RE.test(k))) throw new HttpError(400, 'Invalid key format in list');
    return uniq;
}

// fn(kd) -> {update} | {skip:'reason'} | {del:true}
async function applyToKeys(db, keys, fn) {
    const list = cleanKeyList(keys);
    const refs = list.map(k => keysCol(db).doc(k));
    const snaps = await db.getAll(...refs);
    const res = { requested: list.length, processed: [], skipped: [], notFound: [], snapshots: [] };
    const ops = [];
    snaps.forEach((s, i) => {
        if (!s.exists) return res.notFound.push(list[i]);
        const kd = s.data(), r = fn(kd);
        if (r.skip) return res.skipped.push({ key: list[i], reason: r.skip });
        res.processed.push(list[i]);
        if (r.del) { res.snapshots.push(snapshot(kd)); ops.push(b => b.delete(refs[i])); }
        else ops.push(b => b.update(refs[i], r.update));
    });
    for (let i = 0; i < ops.length; i += 400) {                    // Firestore batch limit is 500
        const batch = db.batch();
        ops.slice(i, i + 400).forEach(op => op(batch));
        await batch.commit();
    }
    return res;
}
// What the audit log keeps about a deleted key (no HWID).
const snapshot = kd => ({ key: kd.key, siteId: kd.siteId, type: kd.type, label: kd.label, createdAt: kd.createdAt,
                          expiresAt: kd.expiresAt, status: kd.status || 'active', loginCount: kd.loginCount });

const revokeKeys = (db, keys, reason, now = Date.now()) => applyToKeys(db, keys, kd =>
    kd.status === 'revoked' ? { skip: 'already revoked' }
        : { update: { status: 'revoked', revokedAt: new Date(now).toISOString(), revokeReason: String(reason || '').slice(0, 200) } });

const restoreKeys = (db, keys) => applyToKeys(db, keys, kd =>
    kd.status !== 'revoked' ? { skip: 'not revoked' }
        : { update: { status: 'active', revokedAt: null, revokeReason: null } });

const deleteKeys = (db, keys) => applyToKeys(db, keys, () => ({ del: true }));

// Extend: from the current expiry if still in the future, otherwise from now (so an expired key becomes usable again).
// A never-used key has no running timer, so its duration is extended instead.
async function extendKeys(db, keys, days, now = Date.now()) {
    const d = L.intIn(days, null, 1, 3650, 'days');
    if (d === null) throw new HttpError(400, 'days is required');
    return applyToKeys(db, keys, kd => {
        if (kd.expiresAt) {
            const base = Math.max(now, new Date(kd.expiresAt).getTime());
            return { update: { expiresAt: new Date(base + d * DAY).toISOString() } };
        }
        if (!kd.lastUsedAt) return { update: { durationDays: Math.min((kd.durationDays || 7) + d, 3650) } };
        return { skip: 'no expiry set (lifetime)' };
    });
}

// Set an exact expiry (null = remove expiry).  Existing PATCH semantics kept.
async function setExpiry(db, keys, expiresAt) {
    const val = expiresAt ? new Date(expiresAt).toISOString() : null;
    if (expiresAt && Number.isNaN(new Date(expiresAt).getTime())) throw new HttpError(400, 'expiresAt is not a valid date');
    return applyToKeys(db, keys, () => ({ update: { expiresAt: val } }));
}

async function editKey(db, keyName, body = {}) {
    const ref = keysCol(db).doc(keyName);
    const snap = await ref.get();
    if (!snap.exists) throw new HttpError(404, 'Not found');
    const { expiresAt, durationDays, loginLimit, loginCount, label, note, hwid } = body;
    const u = {};
    if (expiresAt    !== undefined) {
        if (expiresAt && Number.isNaN(new Date(expiresAt).getTime())) throw new HttpError(400, 'expiresAt is not a valid date');
        u.expiresAt = expiresAt ? new Date(expiresAt).toISOString() : null;
    }
    if (durationDays !== undefined) u.durationDays = parseInt(durationDays) || 7;
    if (loginLimit   !== undefined) u.loginLimit   = parseInt(loginLimit) || 1;
    if (loginCount   !== undefined) u.loginCount   = parseInt(loginCount) || 0;
    if (label        !== undefined) u.label        = String(label).slice(0, 60);
    if (note         !== undefined) u.note         = String(note).slice(0, 200);
    if (hwid         !== undefined) u.hwid         = hwid ? String(hwid).slice(0, 128) : null;
    await ref.update(u);
    return { before: snap.data(), after: (await ref.get()).data(), changed: Object.keys(u) };
}

async function resetDeviceAdmin(db, keyName) {
    const ref = keysCol(db).doc(keyName);
    if (!(await ref.get()).exists) throw new HttpError(404, 'Not found');
    await ref.update({ hwid: null, loginCount: 0, lastResetAt: new Date().toISOString() });
}

module.exports = {
    BULK_MAX, normKey, verifyKey, createKeys, searchKeys, matchingKeyIds, allKeys, withStatus, filterKeys, stats,
    revokeKeys, restoreKeys, deleteKeys, extendKeys, setExpiry, editKey, resetDeviceAdmin, applyToKeys,
};
