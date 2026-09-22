// ═══════════════════════════════════════════════════════════════════
//  SRT X CHEATS — SECURE KEY SERVER  v3.0
//  Protected against: DDoS · Brute-force · Injection · Crash exploits
//  Supports: 4-site multi-prefix keys (SRT / SAMUEL / KALEYYY / NK)
// ═══════════════════════════════════════════════════════════════════
'use strict';
require('dotenv').config();

const express     = require('express');
const crypto      = require('crypto');
const admin       = require('firebase-admin');
const rateLimit   = require('express-rate-limit');
const slowDown    = require('express-slow-down');
const helmet      = require('helmet');
const cors        = require('cors');

// ── PROCESS CRASH GUARDS ─────────────────────────────────────────
// These catch any unhandled error so the server NEVER crashes
process.on('uncaughtException', err => {
    console.error('[CRASH GUARD] uncaughtException:', err.message);
    // Log but keep running — don't exit
});
process.on('unhandledRejection', (reason) => {
    console.error('[CRASH GUARD] unhandledRejection:', reason);
    // Log but keep running — don't exit
});
process.on('SIGTERM', () => {
    console.log('[SHUTDOWN] SIGTERM received — closing gracefully');
    process.exit(0);
});

// ── ENVIRONMENT VALIDATION ────────────────────────────────────────
const REQUIRED_ENV = ['ADMIN_PASS', 'URLKING_API', 'SITE_URL', 'FIREBASE_SERVICE_ACCOUNT_KEY'];
const missing = REQUIRED_ENV.filter(k => !process.env[k]);
if (missing.length) {
    console.error('[BOOT FAIL] Missing env vars:', missing.join(', '));
    process.exit(1);
}

const PORT         = parseInt(process.env.PORT)        || 3000;
const ADMIN_PASS   = process.env.ADMIN_PASS;
const URLKING_API  = process.env.URLKING_API;
const SITE_URL     = process.env.SITE_URL;
const FRONTEND_URL = process.env.FRONTEND_URL          || SITE_URL;
const MAX_PAYLOAD  = '10kb';     // reject bodies larger than this

// ── FIREBASE ──────────────────────────────────────────────────────
try {
    admin.initializeApp({
        credential: admin.credential.cert(
            JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY)
        )
    });
    console.log('[FIREBASE] Connected ✓');
} catch (e) {
    console.error('[FIREBASE] Init failed:', e.message);
    process.exit(1);
}
const db = admin.firestore();

// ── MULTI-SITE KEY PREFIXES ───────────────────────────────────────
//   Each site sends its siteId when requesting a key
const SITE_PREFIXES = {
    site1: 'SRT',
    site2: 'SAMUEL',
    site3: 'KALEYYY',
    site4: 'NK',
};

// ── IN-MEMORY SECURITY STATE ──────────────────────────────────────
const bannedIPs      = new Map();  // ip → unban timestamp
const failedAttempts = new Map();  // ip → { count, firstAt }
const FAIL_THRESHOLD = 10;         // bans after N fails in 10 min
const BAN_DURATION   = 30 * 60 * 1000;  // 30-minute ban

function banIP(ip) {
    bannedIPs.set(ip, Date.now() + BAN_DURATION);
    failedAttempts.delete(ip);
    console.warn(`[SECURITY] Banned IP ${ip} for 30 min`);
}

function recordFail(ip) {
    const now  = Date.now();
    const rec  = failedAttempts.get(ip) || { count: 0, firstAt: now };
    if (now - rec.firstAt > 10 * 60 * 1000) {
        // reset window
        failedAttempts.set(ip, { count: 1, firstAt: now });
    } else {
        rec.count++;
        failedAttempts.set(ip, rec);
        if (rec.count >= FAIL_THRESHOLD) banIP(ip);
    }
}

// Clean expired bans every 10 minutes
setInterval(() => {
    const now = Date.now();
    for (const [ip, until] of bannedIPs) {
        if (now >= until) { bannedIPs.delete(ip); console.log(`[SECURITY] Unbanned ${ip}`); }
    }
    // Also clean stale fail records
    for (const [ip, rec] of failedAttempts) {
        if (now - rec.firstAt > 15 * 60 * 1000) failedAttempts.delete(ip);
    }
}, 10 * 60 * 1000);

// Clean expired Firestore sessions every 2 hours
setInterval(async () => {
    try {
        const cutoff  = new Date(Date.now() - 2 * 60 * 60 * 1000);
        const snap    = await db.collection('sessions')
            .where('createdAt', '<', cutoff)
            .limit(100).get();
        const batch   = db.batch();
        snap.docs.forEach(d => batch.delete(d.ref));
        await batch.commit();
        if (snap.size) console.log(`[CLEANUP] Deleted ${snap.size} expired sessions`);
    } catch (e) { console.error('[CLEANUP] Session cleanup error:', e.message); }
}, 2 * 60 * 60 * 1000);

// ── KEY GENERATION ────────────────────────────────────────────────
const KEY_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function generateKey(prefix = 'SRT') {
    const suffix = Array.from({ length: 8 }, () =>
        KEY_CHARS[Math.floor(Math.random() * KEY_CHARS.length)]
    ).join('');
    return `${prefix}_${suffix}`;
}

async function uniqueKey(prefix) {
    let key, attempts = 0;
    do {
        if (++attempts > 20) throw new Error('Key collision loop exceeded');
        key = generateKey(prefix);
    } while ((await db.collection('keys').doc(key).get()).exists);
    return key;
}

// Timing-safe admin password check (prevents timing attacks)
function checkAdminPass(token) {
    try {
        const a = Buffer.from(token     || '');
        const b = Buffer.from(ADMIN_PASS || '');
        return a.length === b.length && crypto.timingSafeEqual(a, b);
    } catch { return false; }
}

// ── INPUT VALIDATION ──────────────────────────────────────────────
const PATTERNS = {
    key:       /^(SRT|SAMUEL|KALEYYY|NK)_[A-Z0-9]{8}$/,
    siteId:    /^site[1-4]$/,
    sessionId: /^[a-f0-9]{32}$/,
    hwid:      /^[A-Za-z0-9_\-]{4,64}$/,
};

function valid(type, value) {
    if (typeof value !== 'string' || !value.trim()) return false;
    return PATTERNS[type]?.test(value.trim()) ?? false;
}

// ── APP SETUP ─────────────────────────────────────────────────────
const app = express();

// Trust Render / Cloudflare proxy for real IP
app.set('trust proxy', 1);

// ── SECURITY HEADERS (helmet) ─────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: false,   // we don't serve HTML pages
    crossOriginEmbedderPolicy: false,
}));

// ── CORS ──────────────────────────────────────────────────────────
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '')
    .split(',').map(o => o.trim()).filter(Boolean);

app.use(cors({
    origin: (origin, cb) => {
        // Allow no-origin (server-to-server, curl) and whitelisted origins
        if (!origin || ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin)) {
            return cb(null, true);
        }
        console.warn(`[CORS] Blocked origin: ${origin}`);
        cb(new Error('CORS: origin not allowed'));
    },
    methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'X-Admin-Token'],
    maxAge: 86400,
}));

// ── BODY PARSING (size-limited) ───────────────────────────────────
app.use(express.json({ limit: MAX_PAYLOAD }));
app.use(express.urlencoded({ extended: false, limit: MAX_PAYLOAD }));

// ── REQUEST TIMEOUT ───────────────────────────────────────────────
// Kill connections that take too long (Slow Loris mitigation)
app.use((req, res, next) => {
    req.setTimeout(15000, () => {
        res.status(408).json({ error: 'Request timeout' });
    });
    next();
});

// ── IP BAN MIDDLEWARE ─────────────────────────────────────────────
app.use((req, res, next) => {
    const ip    = req.ip;
    const until = bannedIPs.get(ip);
    if (until && Date.now() < until) {
        const minLeft = Math.ceil((until - Date.now()) / 60000);
        return res.status(429).json({ error: `Temporarily banned. Try again in ${minLeft} min.` });
    }
    next();
});

// ── GLOBAL RATE LIMITER ───────────────────────────────────────────
// 150 requests per 15 minutes per IP
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 150,
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        recordFail(req.ip);
        res.status(429).json({ error: 'Too many requests. Slow down.' });
    },
}));

// ── SLOW DOWN: repeated requests get delayed ──────────────────────
app.use(slowDown({
    windowMs: 5 * 60 * 1000,
    delayAfter: 60,
    delayMs: (used) => (used - 60) * 50,   // +50ms per extra request
    maxDelayMs: 5000,
}));

// ── HEALTH CHECK (Render uptime ping) ────────────────────────────
app.get('/health', (req, res) => res.json({
    status: 'ok', uptime: Math.floor(process.uptime()),
    memory: Math.round(process.memoryUsage().heapUsed / 1024 / 1024) + 'MB',
}));

// ── SHARED ERROR WRAPPER ──────────────────────────────────────────
// Wraps every handler — if it throws, server does NOT crash
function safe(fn) {
    return async (req, res, next) => {
        try { await fn(req, res, next); }
        catch (err) {
            console.error('[HANDLER ERROR]', err.message);
            if (!res.headersSent)
                res.status(500).json({ error: 'Internal server error' });
        }
    };
}

// ═══════════════════════════════════════════════════════════════════
//  AD FLOW — rate-limited: 3 key requests per hour
// ═══════════════════════════════════════════════════════════════════
const initKeyLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    keyGenerator: (req) => req.ip,
    handler: (req, res) => {
        console.warn(`[RATE] Key init blocked: ${req.ip}`);
        res.status(429).json({ error: 'You can only generate 3 keys per hour. Please wait.' });
    },
});

app.post('/api/init-key-request', initKeyLimiter, safe(async (req, res) => {
    const raw    = req.body?.siteId || 'site1';
    const siteId = valid('siteId', raw) ? raw : 'site1';

    const sessionId = crypto.randomBytes(16).toString('hex');
    await db.collection('sessions').doc(sessionId).set({
        createdAt: admin.firestore.FieldValue.serverTimestamp(),
        completed: false,
        key:       null,
        siteId,
        ip:        req.ip,
    });

    const cbUrl      = encodeURIComponent(`${SITE_URL}/api/ad-callback?session=${sessionId}`);
    const redirectUrl = `https://go.urlking.in/st?api=${URLKING_API}&url=${cbUrl}`;
    res.json({ sessionId, redirectUrl });
}));

app.get('/api/ad-callback', safe(async (req, res) => {
    const sessionId = req.query.session || '';
    if (!valid('sessionId', sessionId))
        return res.redirect(`${FRONTEND_URL}/?error=invalid_session`);

    const ref  = db.collection('sessions').doc(sessionId);
    const snap = await ref.get();
    if (!snap.exists) return res.redirect(`${FRONTEND_URL}/?error=invalid_session`);

    const sess = snap.data();
    if (sess.completed)
        return res.redirect(`${FRONTEND_URL}/?key=${sess.key}`);

    const prefix = SITE_PREFIXES[sess.siteId] || 'SRT';
    const newKey = await uniqueKey(prefix);

    await db.collection('keys').doc(newKey).set({
        key:          newKey,
        prefix,
        siteId:       sess.siteId || 'site1',
        createdAt:    new Date().toISOString(),
        expiresAt:    null,
        durationDays: 7,
        loginLimit:   1,
        loginCount:   0,
        type:         'standard',
        label:        '',
        note:         `Auto via URL King · site=${sess.siteId} · ip=${sess.ip}`,
        hwid:         null,
        lastUsedAt:   null,
    });
    await ref.update({ completed: true, key: newKey });
    res.redirect(`${FRONTEND_URL}/?key=${newKey}`);
}));

// ═══════════════════════════════════════════════════════════════════
//  KEY VERIFICATION — rate-limited: 20 checks per 5 min
// ═══════════════════════════════════════════════════════════════════
const verifyLimiter = rateLimit({
    windowMs: 5 * 60 * 1000,
    max: 20,
    handler: (req, res) => res.status(429).json({ valid: false, message: 'Too many checks. Wait 5 minutes.' }),
});

app.get('/api/verify-key', verifyLimiter, safe(async (req, res) => {
    const key  = (req.query.key  || '').trim().toUpperCase();
    const hwid = (req.query.hwid || '').trim();

    // Validate key format before hitting Firestore
    if (!valid('key', key)) {
        recordFail(req.ip);
        return res.json({ valid: false, message: 'Invalid key format' });
    }

    const keyRef = db.collection('keys').doc(key);
    const doc    = await keyRef.get();
    if (!doc.exists) {
        recordFail(req.ip);
        return res.json({ valid: false, message: 'Key not found' });
    }

    const kd      = doc.data();
    const now     = new Date();
    const updates = {};

    // Start timer on first login
    let expiresAt = kd.expiresAt || null;
    if (!kd.lastUsedAt && !expiresAt) {
        expiresAt        = new Date(now.getTime() + (kd.durationDays || 7) * 86400000).toISOString();
        updates.expiresAt = expiresAt;
    }

    // Check expiry
    if (expiresAt && now > new Date(expiresAt))
        return res.json({ valid: false, message: 'Key expired', expiredAt: expiresAt });

    // HWID check first (before login limit)
    const hwidMismatch = kd.hwid && hwid && kd.hwid !== hwid;
    const sameDevice   = kd.hwid && hwid && kd.hwid === hwid;

    if (hwidMismatch) {
        recordFail(req.ip);
        return res.json({ valid: false, message: 'HWID mismatch — different device' });
    }

    // Login limit — only for new devices
    if (!sameDevice) {
        if (kd.loginLimit > 0 && (kd.loginCount || 0) >= kd.loginLimit)
            return res.json({ valid: false, message: 'Login limit reached' });
        if (!kd.hwid && hwid) updates.hwid = hwid;
        updates.loginCount = (kd.loginCount || 0) + 1;
    }

    updates.lastUsedAt = now.toISOString();
    await keyRef.update(updates);

    const finalExpiry = updates.expiresAt || expiresAt;
    const msLeft      = finalExpiry ? new Date(finalExpiry) - now : null;
    res.json({
        valid:      true,
        message:    'Key valid',
        key:        kd.key,
        prefix:     kd.prefix || 'SRT',
        siteId:     kd.siteId || 'site1',
        expiresAt:  finalExpiry,
        daysLeft:   msLeft ? Math.ceil(msLeft / 86400000) : null,
        loginCount: updates.loginCount ?? kd.loginCount,
        loginLimit: kd.loginLimit,
        type:       kd.type,
        label:      kd.label || '',
    });
}));

// ═══════════════════════════════════════════════════════════════════
//  DEVICE RESET — 3 per hour per IP, 24h cooldown per key
// ═══════════════════════════════════════════════════════════════════
const resetLimiter = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 3,
    handler: (req, res) => {
        recordFail(req.ip);
        res.status(429).json({ success: false, message: 'Too many reset attempts. Try again in 1 hour.' });
    },
});

app.post('/api/reset-device', resetLimiter, safe(async (req, res) => {
    const key = (req.body?.key || '').trim().toUpperCase();
    if (!valid('key', key)) {
        recordFail(req.ip);
        return res.json({ success: false, message: 'Invalid key format' });
    }

    const keyRef = db.collection('keys').doc(key);
    const doc    = await keyRef.get();
    if (!doc.exists) {
        recordFail(req.ip);
        return res.json({ success: false, message: 'Key not found' });
    }

    const kd = doc.data();
    if (kd.expiresAt && new Date() > new Date(kd.expiresAt))
        return res.json({ success: false, message: 'Cannot reset an expired key' });

    // 24-hour cooldown
    if (kd.lastResetAt) {
        const hrs = (Date.now() - new Date(kd.lastResetAt).getTime()) / 3600000;
        if (hrs < 24) {
            const h = Math.ceil(24 - hrs), m = Math.ceil((24 - hrs - Math.floor(24 - hrs)) * 60);
            return res.json({ success: false, message: `Cooldown active — ${h}h ${m}m remaining` });
        }
    }

    await keyRef.update({ hwid: null, loginCount: 0, lastResetAt: new Date().toISOString() });
    res.json({ success: true, message: 'Device unlinked! You can now log in from a new device.' });
}));

// ═══════════════════════════════════════════════════════════════════
//  ADMIN ROUTES — 5 login attempts per 15 min before IP ban
// ═══════════════════════════════════════════════════════════════════
const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 5,
    handler: (req, res) => {
        banIP(req.ip);  // instant ban after 5 wrong password attempts
        res.status(429).json({ error: 'Too many login attempts. IP banned for 30 min.' });
    },
});

function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token || '';
    if (!checkAdminPass(token)) {
        recordFail(req.ip);
        return res.status(401).json({ error: 'Unauthorized' });
    }
    next();
}

app.post('/api/admin/login', adminLoginLimiter, safe((req, res) => {
    const { password } = req.body || {};
    if (checkAdminPass(password)) {
        res.json({ success: true, token: ADMIN_PASS });
    } else {
        recordFail(req.ip);
        res.status(401).json({ success: false, error: 'Wrong password' });
    }
}));

app.get('/api/admin/stats', adminAuth, safe(async (req, res) => {
    const list = (await db.collection('keys').get()).docs.map(d => d.data());
    const now  = new Date();
    const bySite = {};
    for (const [id, prefix] of Object.entries(SITE_PREFIXES)) {
        bySite[prefix] = list.filter(k => k.siteId === id || k.prefix === prefix).length;
    }
    res.json({
        total:    list.length,
        active:   list.filter(k => (!k.expiresAt || new Date(k.expiresAt) > now) && (k.loginCount||0) < (k.loginLimit||1)).length,
        expired:  list.filter(k => k.expiresAt && new Date(k.expiresAt) <= now).length,
        maxed:    list.filter(k => (!k.expiresAt || new Date(k.expiresAt) > now) && (k.loginCount||0) >= (k.loginLimit||1)).length,
        standard: list.filter(k => k.type === 'standard').length,
        custom:   list.filter(k => k.type === 'custom').length,
        bySite,
        bannedIPs:   bannedIPs.size,
        serverUptime: Math.floor(process.uptime()) + 's',
    });
}));

app.get('/api/admin/keys', adminAuth, safe(async (req, res) => {
    const list = (await db.collection('keys').get()).docs.map(d => d.data());
    list.sort((a, b) => new Date(b.createdAt||0) - new Date(a.createdAt||0));
    res.json(list);
}));

app.post('/api/admin/create-key', adminAuth, safe(async (req, res) => {
    const { customKey, duration, loginLimit, label, note, siteId } = req.body || {};
    const sid    = valid('siteId', siteId) ? siteId : 'site1';
    const prefix = SITE_PREFIXES[sid];

    let newKey;
    if (customKey?.trim()) {
        newKey = customKey.trim().toUpperCase();
        if (!newKey.startsWith(prefix + '_')) newKey = prefix + '_' + newKey;
        if ((await db.collection('keys').doc(newKey).get()).exists)
            return res.status(400).json({ error: 'Key already exists' });
    } else {
        newKey = await uniqueKey(prefix);
    }

    const keyData = {
        key: newKey, prefix, siteId: sid,
        createdAt: new Date().toISOString(), expiresAt: null,
        durationDays: parseInt(duration)||7, loginLimit: parseInt(loginLimit)||1,
        loginCount: 0, type: 'custom',
        label: (label||'').slice(0,60), note: (note||'').slice(0,200),
        hwid: null, lastUsedAt: null,
    };
    await db.collection('keys').doc(newKey).set(keyData);
    res.json({ success: true, key: keyData });
}));

app.patch('/api/admin/key/:key', adminAuth, safe(async (req, res) => {
    const keyName = req.params.key.trim().toUpperCase();
    if (!valid('key', keyName)) return res.status(400).json({ error: 'Invalid key format' });

    const ref = db.collection('keys').doc(keyName);
    if (!(await ref.get()).exists) return res.status(404).json({ error: 'Not found' });

    const { expiresAt, durationDays, loginLimit, loginCount, label, note, hwid } = req.body || {};
    const u = {};
    if (expiresAt    !== undefined) u.expiresAt    = expiresAt ? new Date(expiresAt).toISOString() : null;
    if (durationDays !== undefined) u.durationDays = parseInt(durationDays) || 7;
    if (loginLimit   !== undefined) u.loginLimit   = parseInt(loginLimit)   || 1;
    if (loginCount   !== undefined) u.loginCount   = parseInt(loginCount)   || 0;
    if (label        !== undefined) u.label        = String(label).slice(0, 60);
    if (note         !== undefined) u.note         = String(note).slice(0, 200);
    if (hwid         !== undefined) u.hwid         = hwid || null;
    await ref.update(u);
    res.json({ success: true, key: (await ref.get()).data() });
}));

app.delete('/api/admin/key/:key', adminAuth, safe(async (req, res) => {
    const keyName = req.params.key.trim().toUpperCase();
    if (!valid('key', keyName)) return res.status(400).json({ error: 'Invalid key format' });
    const ref = db.collection('keys').doc(keyName);
    if (!(await ref.get()).exists) return res.status(404).json({ error: 'Not found' });
    await ref.delete();
    res.json({ success: true });
}));

app.post('/api/admin/key/:key/reset-device', adminAuth, safe(async (req, res) => {
    const keyName = req.params.key.trim().toUpperCase();
    if (!valid('key', keyName)) return res.status(400).json({ error: 'Invalid key format' });
    const ref = db.collection('keys').doc(keyName);
    if (!(await ref.get()).exists) return res.status(404).json({ error: 'Not found' });
    await ref.update({ hwid: null, loginCount: 0, lastResetAt: new Date().toISOString() });
    res.json({ success: true });
}));

// Admin: list banned IPs / unban
app.get('/api/admin/bans', adminAuth, safe((req, res) => {
    const list = [];
    for (const [ip, until] of bannedIPs) {
        list.push({ ip, minutesLeft: Math.ceil((until - Date.now()) / 60000) });
    }
    res.json(list);
}));

app.delete('/api/admin/ban/:ip', adminAuth, safe((req, res) => {
    const ip = req.params.ip;
    bannedIPs.delete(ip);
    failedAttempts.delete(ip);
    res.json({ success: true, message: `${ip} unbanned` });
}));

// ── 404 CATCH-ALL ─────────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Not found' }));

// ── GLOBAL ERROR HANDLER ──────────────────────────────────────────
// Last-resort — should never reach here due to safe() wrapper
app.use((err, req, res, next) => {  // eslint-disable-line no-unused-vars
    console.error('[EXPRESS ERROR]', err.message);
    if (!res.headersSent) res.status(500).json({ error: 'Server error' });
});

// ── START ─────────────────────────────────────────────────────────
app.listen(PORT, () => {
    console.log('\n  ┌───────────────────────────────────────────┐');
    console.log('  │   SRT X CHEATS  ·  SECURE KEY SERVER  🔐  │');
    console.log('  └───────────────────────────────────────────┘');
    console.log(`  🚀  Port         : ${PORT}`);
    console.log(`  🌐  Backend URL  : ${SITE_URL}`);
    console.log(`  🔑  Key prefixes : ${Object.values(SITE_PREFIXES).join(' / ')}`);
    console.log(`  🛡️   Rate limits  : ON`);
    console.log(`  💣  Crash guards : ON\n`);
});
