'use strict';
const crypto = require('crypto');

// ── Constants ────────────────────────────────────────────────────
const SITE_PREFIXES = { site1: 'SRT', site2: 'SAMUEL', site3: 'KALEYYY', site4: 'NK' };
const PREFIX_TO_SITE = Object.fromEntries(Object.entries(SITE_PREFIXES).map(([s, p]) => [p, s]));
const KEY_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
// Suffix 4–32 chars (was fixed 8). Superset of the old format, so every existing key still verifies.
const KEY_RE = /^(SRT|SAMUEL|KALEYYY|NK)_[A-Z0-9]{4,32}$/;
const DAY = 86400000;

class HttpError extends Error {
    constructor(status, message) { super(message); this.status = status; }
}

// ── Safe logger ──────────────────────────────────────────────────
// Never prints secrets, key values, HWIDs or query strings.
const SECRET_FIELD = /pass|token|secret|authorization|cookie|private|credential|hwid|csrf/i;
const KEY_IN_TEXT  = /\b(SRT|SAMUEL|KALEYYY|NK)_([A-Z0-9]{2})[A-Z0-9]{2,30}\b/g;

function maskKey(k) {
    return String(k).replace(KEY_IN_TEXT, (_m, p, head) => `${p}_${head}****`);
}
function scrub(v, depth = 0) {
    if (v == null) return v;
    if (typeof v === 'string') return maskKey(v).slice(0, 300);
    if (typeof v !== 'object' || depth > 3) return typeof v === 'object' ? '[obj]' : v;
    if (Array.isArray(v)) return v.slice(0, 10).map(x => scrub(x, depth + 1));
    const out = {};
    for (const [k, val] of Object.entries(v)) out[k] = SECRET_FIELD.test(k) ? '[redacted]' : scrub(val, depth + 1);
    return out;
}
function makeLogger(sink = console) {
    const emit = (level, msg, ctx) => {
        const line = JSON.stringify({ ts: new Date().toISOString(), level, msg: scrub(String(msg)), ...(ctx ? scrub(ctx) : {}) });
        (level === 'error' ? sink.error : level === 'warn' ? sink.warn : sink.log)(line);
    };
    return {
        info:  (m, c) => emit('info', m, c),
        warn:  (m, c) => emit('warn', m, c),
        error: (m, c) => emit('error', m, c),
        // Errors: message + code only. No stack, no request data.
        err: (m, e, c) => emit('error', m, { ...c, code: e && e.code, reason: e && e.message }),
    };
}

// ── Key helpers ──────────────────────────────────────────────────
function generateKey(prefix, length = 8) {
    let s = '';
    for (let i = 0; i < length; i++) s += KEY_CHARS[crypto.randomInt(KEY_CHARS.length)]; // CSPRNG (was Math.random)
    return `${prefix}_${s}`;
}

function intIn(v, def, min, max, name) {
    if (v === undefined || v === null || v === '') return def;
    const n = Number(v);
    if (!Number.isInteger(n) || n < min || n > max) throw new HttpError(400, `${name} must be an integer ${min}–${max}`);
    return n;
}

// Accepts "SRT_ABCD1234" or just "ABCD1234" (site prefix is added).
function parseCustomKey(input, siteId) {
    let k = String(input).trim().toUpperCase();
    const m = k.match(/^(SRT|SAMUEL|KALEYYY|NK)_(.*)$/);
    let prefix = SITE_PREFIXES[siteId];
    let sid = siteId;
    if (m) { prefix = m[1]; sid = PREFIX_TO_SITE[prefix]; k = m[2]; }
    if (!/^[A-Z0-9]{4,32}$/.test(k)) throw new HttpError(400, 'Custom key must be 4–32 characters, A–Z and 0–9 only');
    return { key: `${prefix}_${k}`, prefix, siteId: sid };
}

function parseFutureDate(v, nowMs, name = 'expiresAt') {
    const t = new Date(v).getTime();
    if (!Number.isFinite(t)) throw new HttpError(400, `${name} is not a valid date`);
    if (t <= nowMs) throw new HttpError(400, `${name} must be in the future`);
    if (t > nowMs + 3650 * DAY) throw new HttpError(400, `${name} is too far in the future (max 10 years)`);
    return new Date(t).toISOString();
}

// revoked > expired > active.  Docs created before v4 have no `status` => active.
function deriveStatus(kd, nowMs) {
    if (kd.status === 'revoked') return 'revoked';
    if (kd.expiresAt && nowMs > new Date(kd.expiresAt).getTime()) return 'expired';
    return 'active';
}
const isFull   = kd => (kd.loginLimit || 0) > 0 && (kd.loginCount || 0) >= kd.loginLimit;
const isUnused = kd => !kd.lastUsedAt;

// ── Admin sessions (stateless HMAC tokens) ───────────────────────
// Token = base64url(payload).HMAC.  Secret derives from ADMIN_PASS unless SESSION_SECRET is set,
// so changing ADMIN_PASS invalidates every session.  The raw password is never used as a token.
function createAuth({ adminPass, sessionSecret, ttlMs = 8 * 3600 * 1000 }) {
    const secret = sessionSecret
        ? Buffer.from(sessionSecret)
        : crypto.createHmac('sha256', 'srtx-admin-session-v1').update(adminPass).digest();
    const sha = s => crypto.createHash('sha256').update(String(s ?? '')).digest();
    const mac = body => crypto.createHmac('sha256', secret).update(body).digest('base64url');
    const revoked = new Map();                       // sid -> exp  (logout; cleared on restart)

    const checkPassword = p => crypto.timingSafeEqual(sha(p), sha(adminPass));   // fixed-length compare

    function issue(now = Date.now()) {
        const payload = {
            sid: crypto.randomBytes(9).toString('base64url'),
            csrf: crypto.randomBytes(18).toString('base64url'),
            iat: now, exp: now + ttlMs,
        };
        const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
        return { token: `${body}.${mac(body)}`, payload };
    }
    function parse(token, now = Date.now()) {
        if (typeof token !== 'string' || token.length > 600) return null;
        const parts = token.split('.');
        if (parts.length !== 2) return null;
        const [body, sig] = parts;
        const want = Buffer.from(mac(body)), got = Buffer.from(sig);
        if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) return null;
        let p; try { p = JSON.parse(Buffer.from(body, 'base64url').toString()); } catch { return null; }
        if (!p || typeof p.exp !== 'number' || p.exp <= now || revoked.has(p.sid)) return null;
        return p;
    }
    function revoke(p, now = Date.now()) {
        revoked.set(p.sid, p.exp);
        for (const [sid, exp] of revoked) if (exp <= now) revoked.delete(sid);   // forget entries whose token is expired anyway
    }
    return { checkPassword, issue, parse, revoke, ttlMs };
}

// ── Audit log: append-only, hash-chained ─────────────────────────
// audit_logs/<seq> + meta/audit_head.  The API exposes no way to edit or delete entries;
// verifyAuditChain() detects edits, removals and tail truncation.
const pad = n => String(n).padStart(10, '0');
function stable(o) {
    if (Array.isArray(o)) return `[${o.map(stable).join(',')}]`;
    if (o && typeof o === 'object') return `{${Object.keys(o).sort().map(k => `${JSON.stringify(k)}:${stable(o[k])}`).join(',')}}`;
    return JSON.stringify(o);
}
const clean = o => JSON.parse(JSON.stringify(o));   // drops undefined (Firestore rejects it)
const sha256 = s => crypto.createHash('sha256').update(s).digest('hex');

async function writeAudit(db, entry) {
    const headRef = db.collection('meta').doc('audit_head');
    return db.runTransaction(async tx => {
        const h = await tx.get(headRef);
        const prev = h.exists ? h.data() : { seq: 0, hash: 'GENESIS' };
        const seq = prev.seq + 1;
        const body = clean({ ...entry, seq, ts: new Date().toISOString(), prevHash: prev.hash });
        const hash = sha256(prev.hash + stable(body));
        tx.set(db.collection('audit_logs').doc(pad(seq)), { ...body, hash });
        tx.set(headRef, { seq, hash });
        return { seq, hash };
    });
}

async function verifyAuditChain(db) {
    const head = await db.collection('meta').doc('audit_head').get();
    if (!head.exists) return { ok: true, checked: 0, headSeq: 0 };
    const { seq: headSeq, hash: headHash } = head.data();
    let prev = 'GENESIS', checked = 0;
    for (let from = 1; from <= headSeq; from += 300) {
        const to = Math.min(from + 299, headSeq);
        const refs = []; for (let i = from; i <= to; i++) refs.push(db.collection('audit_logs').doc(pad(i)));
        const snaps = await db.getAll(...refs);
        for (let i = 0; i < snaps.length; i++) {
            const n = from + i;
            if (!snaps[i].exists) return { ok: false, checked, headSeq, brokenAt: n, reason: 'missing entry' };
            const { hash, ...body } = snaps[i].data();
            if (body.seq !== n || body.prevHash !== prev || sha256(prev + stable(body)) !== hash)
                return { ok: false, checked, headSeq, brokenAt: n, reason: 'entry altered' };
            prev = hash; checked++;
        }
    }
    if (prev !== headHash) return { ok: false, checked, headSeq, brokenAt: headSeq, reason: 'head mismatch' };
    return { ok: true, checked, headSeq };
}

async function listAudit(db, { before, limit = 50, action, key } = {}) {
    const head = await db.collection('meta').doc('audit_head').get();
    const top = head.exists ? head.data().seq : 0;
    const start = Math.min(before ? Number(before) - 1 : top, top);
    const lo = Math.max(1, start - Math.min(limit, 200) + 1);
    if (start < 1) return { items: [], nextBefore: null };
    const refs = []; for (let i = start; i >= lo; i--) refs.push(db.collection('audit_logs').doc(pad(i)));
    let items = (await db.getAll(...refs)).filter(s => s.exists).map(s => s.data());
    if (action) items = items.filter(e => e.action === action);
    if (key) items = items.filter(e => (e.keys || []).includes(String(key).toUpperCase()));
    return { items, nextBefore: lo > 1 ? lo : null };
}

module.exports = {
    SITE_PREFIXES, PREFIX_TO_SITE, KEY_RE, KEY_CHARS, DAY, HttpError,
    makeLogger, maskKey, scrub,
    generateKey, intIn, parseCustomKey, parseFutureDate, deriveStatus, isFull, isUnused,
    createAuth, writeAudit, verifyAuditChain, listAudit, stable,
};
