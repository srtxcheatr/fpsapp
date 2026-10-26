'use strict';
const path      = require('path');
const crypto    = require('crypto');
const express   = require('express');
const rateLimit = require('express-rate-limit');
const slowDown  = require('express-slow-down');
const helmet    = require('helmet');
const cors      = require('cors');
const L         = require('./lib');
const S         = require('./service');
const { HttpError, SITE_PREFIXES, KEY_RE } = L;

/**
 * deps: { getDb(): Firestore|null, serverTimestamp(), config, log, state }
 *   getDb() returns null while Firebase is unavailable → data routes answer 503 (never a fake "invalid key").
 */
function createApp({ getDb, serverTimestamp, config, log, state }) {
    const app = express();
    const auth = L.createAuth({ adminPass: config.ADMIN_PASS, sessionSecret: config.SESSION_SECRET });
    const startedAt = Date.now();

    // ── In-memory abuse tracking (unchanged behaviour) ──────────
    const bannedIPs = new Map(), failedAttempts = new Map();
    const FAIL_THRESHOLD = 10, BAN_DURATION = 30 * 60 * 1000;
    const banIP = ip => { bannedIPs.set(ip, Date.now() + BAN_DURATION); failedAttempts.delete(ip); log.warn('IP banned for 30 min'); };
    const recordFail = ip => {
        const now = Date.now(), rec = failedAttempts.get(ip);
        if (!rec || now - rec.firstAt > 10 * 60 * 1000) return failedAttempts.set(ip, { count: 1, firstAt: now });
        if (++rec.count >= FAIL_THRESHOLD) banIP(ip);
    };
    const sweep = setInterval(() => {
        const now = Date.now();
        for (const [ip, until] of bannedIPs) if (now >= until) bannedIPs.delete(ip);
        for (const [ip, rec] of failedAttempts) if (now - rec.firstAt > 15 * 60 * 1000) failedAttempts.delete(ip);
    }, 10 * 60 * 1000);
    sweep.unref();

    app.set('trust proxy', config.TRUST_PROXY);   // Render = 1 proxy hop
    app.disable('x-powered-by');

    // ── Secure headers ──────────────────────────────────────────
    // Strict CSP: the only HTML we serve is /admin, and it uses external same-origin JS/CSS (no inline code).
    app.use(helmet({
        contentSecurityPolicy: { useDefaults: false, directives: {
            defaultSrc: ["'none'"], scriptSrc: ["'self'"], styleSrc: ["'self'"], imgSrc: ["'self'", 'data:'],
            connectSrc: ["'self'"], baseUri: ["'none'"], formAction: ["'self'"], frameAncestors: ["'none'"],
        } },
        crossOriginEmbedderPolicy: false,
        referrerPolicy: { policy: 'no-referrer' },
    }));
    app.use((req, res, next) => { res.setHeader('Cache-Control', 'no-store'); next(); });  // verify results must never be cached

    // ── CORS (same allow-list behaviour as before; blocked origins now get 403, not 500) ──
    app.use(cors({
        origin: (origin, cb) => (!origin || !config.ALLOWED_ORIGINS.length || config.ALLOWED_ORIGINS.includes(origin))
            ? cb(null, true) : cb(new HttpError(403, 'CORS: origin not allowed')),
        methods: ['GET', 'POST', 'PATCH', 'DELETE', 'OPTIONS'],
        allowedHeaders: ['Content-Type', 'X-Admin-Token', 'X-CSRF-Token'],
        maxAge: 86400,
    }));

    app.use(express.json({ limit: config.MAX_PAYLOAD }));
    app.use(express.urlencoded({ extended: false, limit: config.MAX_PAYLOAD }));
    app.use((req, res, next) => { req.setTimeout(15000, () => { if (!res.headersSent) res.status(408).json({ error: 'Request timeout' }); }); next(); });

    app.use((req, res, next) => {                                    // IP ban
        const until = bannedIPs.get(req.ip);
        if (until && Date.now() < until)
            return res.status(429).json({ error: `Temporarily banned. Try again in ${Math.ceil((until - Date.now()) / 60000)} min.` });
        next();
    });

    // ── /health ─────────────────────────────────────────────────
    // Liveness only: 200 + status + uptime. No memory, versions, env, Firebase state or counters.
    // Registered BEFORE the global limiter so Render's health checker can't be throttled into a restart loop;
    // it has its own generous limiter instead. Intentionally does NOT touch Firestore.
    app.get('/health', rateLimit({ windowMs: 60 * 1000, limit: 120, standardHeaders: true, legacyHeaders: false,
        handler: (req, res) => res.status(429).json({ status: 'rate_limited' }) }),
        (req, res) => res.status(200).json({ status: 'ok', uptime: Math.floor(process.uptime()) }));

    // ── Request log (path only — never the query string, which carries license keys) ──
    app.use((req, res, next) => {
        const t = Date.now();
        res.on('finish', () => log.info('req', { method: req.method, path: req.path, status: res.statusCode, ms: Date.now() - t }));
        next();
    });

    // ── Global limiter + slow-down (admin has its own limiter below) ──
    const notAdmin = req => req.path.startsWith('/api/admin') || req.path.startsWith('/admin');
    app.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 150, skip: notAdmin, standardHeaders: true, legacyHeaders: false,
        handler: (req, res) => { recordFail(req.ip); res.status(429).json({ error: 'Too many requests. Slow down.' }); } }));
    app.use(slowDown({ windowMs: 5 * 60 * 1000, delayAfter: 60, delayMs: used => (used - 60) * 50, maxDelayMs: 5000, skip: notAdmin }));

    // ── Helpers ─────────────────────────────────────────────────
    const TRANSIENT = new Set([4, 8, 14, 16, 7, 2]);   // DEADLINE, QUOTA, UNAVAILABLE, UNAUTH, PERMISSION, UNKNOWN (gRPC)
    const safe = fn => async (req, res, next) => {
        try { await fn(req, res, next); }
        catch (err) {
            if (res.headersSent) return;
            if (err instanceof HttpError) return res.status(err.status).json({ error: err.message });
            if (TRANSIENT.has(err && err.code)) {
                log.err('Firestore unavailable', err);
                res.set('Retry-After', '30');
                return res.status(503).json({ error: 'Service temporarily unavailable' });
            }
            log.err('Handler error', err, { path: req.path });
            res.status(500).json({ error: 'Internal server error' });
        }
    };
    const needDb = (req, res, next) => {
        req.db = getDb();
        if (!req.db) { res.set('Retry-After', '30'); return res.status(503).json({ error: 'Service temporarily unavailable' }); }
        next();
    };
    const keyParam = req => {
        const k = S.normKey(req.params.key);
        if (!KEY_RE.test(k)) throw new HttpError(400, 'Invalid key format');
        return k;
    };
    // Audit: best-effort write; if it fails the action still stands, but the failure is logged loudly with the entry.
    async function audit(req, action, { keys = [], details = {} } = {}) {
        const entry = { action, actor: 'admin', ip: req.ip, sid: (req.admin && req.admin.sid) || null,
            count: keys.length, keys: keys.slice(0, S.BULK_MAX), details };
        try { const db = getDb(); if (!db) throw new Error('db unavailable'); return await L.writeAudit(db, entry); }
        catch (e) { log.err('AUDIT WRITE FAILED', e, { action, count: keys.length }); return null; }
    }
    const bulkDetails = (r, extra) => ({ ...extra, requested: r.requested, processed: r.processed.length,
        skipped: r.skipped.length, notFound: r.notFound.length, deleted: r.snapshots.length ? r.snapshots : undefined });
    const bulkReply = r => ({ success: true, requested: r.requested, processed: r.processed.length, skipped: r.skipped,
        notFound: r.notFound });

    // ═════════════════ PUBLIC API (contract unchanged) ═════════════════
    const initKeyLimiter = rateLimit({ windowMs: 3600000, limit: 3,
        handler: (req, res) => res.status(429).json({ error: 'You can only generate 3 keys per hour. Please wait.' }) });

    app.post('/api/init-key-request', initKeyLimiter, needDb, safe(async (req, res) => {
        if (!config.URLKING_API) return res.status(503).json({ error: 'Key generation is not configured' });
        const raw = req.body && req.body.siteId;
        const siteId = /^site[1-4]$/.test(raw || '') ? raw : 'site1';
        const sessionId = crypto.randomBytes(16).toString('hex');
        await req.db.collection('sessions').doc(sessionId).set({
            createdAt: serverTimestamp(), completed: false, key: null, siteId, ip: req.ip });
        const cb = encodeURIComponent(`${config.SITE_URL}/api/ad-callback?session=${sessionId}`);
        res.json({ sessionId, redirectUrl: `https://go.urlking.in/st?api=${config.URLKING_API}&url=${cb}` });
    }));

    app.get('/api/ad-callback', needDb, safe(async (req, res) => {
        const sessionId = String(req.query.session || '');
        if (!/^[a-f0-9]{32}$/.test(sessionId)) return res.redirect(`${config.FRONTEND_URL}/?error=invalid_session`);
        const ref = req.db.collection('sessions').doc(sessionId), snap = await ref.get();
        if (!snap.exists) return res.redirect(`${config.FRONTEND_URL}/?error=invalid_session`);
        const sess = snap.data();
        if (sess.completed) return res.redirect(`${config.FRONTEND_URL}/?key=${encodeURIComponent(sess.key)}`);
        const siteId = SITE_PREFIXES[sess.siteId] ? sess.siteId : 'site1';
        // Ad-flow keys keep their historical shape: type 'standard', 7 days from first login, 1 device.
        const [k] = await S.createKeys(req.db, { siteId, count: 1, type: 'standard', note: `Auto via URL King · site=${siteId} · ip=${sess.ip}` });
        await ref.update({ completed: true, key: k.key });
        res.redirect(`${config.FRONTEND_URL}/?key=${encodeURIComponent(k.key)}`);
    }));

    const verifyLimiter = rateLimit({ windowMs: 5 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
        handler: (req, res) => res.status(429).json({ valid: false, message: 'Too many checks. Wait 5 minutes.' }) });

    app.get('/api/verify-key', verifyLimiter, needDb, safe(async (req, res) => {
        const r = await S.verifyKey(req.db, req.query.key, req.query.hwid);
        if (r.fail) recordFail(req.ip);
        res.json(r.body);
    }));

    const resetLimiter = rateLimit({ windowMs: 3600000, limit: 3, standardHeaders: true, legacyHeaders: false,
        handler: (req, res) => { recordFail(req.ip); res.status(429).json({ success: false, message: 'Too many reset attempts. Try again in 1 hour.' }); } });

    app.post('/api/reset-device', resetLimiter, needDb, safe(async (req, res) => {
        const key = S.normKey(req.body && req.body.key);
        if (!KEY_RE.test(key)) { recordFail(req.ip); return res.json({ success: false, message: 'Invalid key format' }); }
        const ref = req.db.collection('keys').doc(key), doc = await ref.get();
        if (!doc.exists) { recordFail(req.ip); return res.json({ success: false, message: 'Key not found' }); }
        const kd = doc.data();
        if (kd.status === 'revoked') return res.json({ success: false, message: 'Key revoked' });
        if (kd.expiresAt && new Date() > new Date(kd.expiresAt)) return res.json({ success: false, message: 'Cannot reset an expired key' });
        if (kd.lastResetAt) {
            const hrs = (Date.now() - new Date(kd.lastResetAt).getTime()) / 3600000;
            if (hrs < 24) {
                const h = Math.ceil(24 - hrs), m = Math.ceil((24 - hrs - Math.floor(24 - hrs)) * 60);
                return res.json({ success: false, message: `Cooldown active — ${h}h ${m}m remaining` });
            }
        }
        await ref.update({ hwid: null, loginCount: 0, lastResetAt: new Date().toISOString() });
        res.json({ success: true, message: 'Device unlinked! You can now log in from a new device.' });
    }));

    // ═════════════════ ADMIN AUTH ═════════════════
    const adminLoginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 5, skipSuccessfulRequests: true, // only FAILED logins count
        handler: (req, res) => { banIP(req.ip); res.status(429).json({ error: 'Too many login attempts. IP banned for 30 min.' }); } });
    const adminLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 600, standardHeaders: true, legacyHeaders: false,
        handler: (req, res) => res.status(429).json({ error: 'Too many requests.' }) });

    const readCookie = (req, name) => {
        const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
        return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
    };
    const COOKIE = 'srtx_admin';
    const setCookie = (req, res, value, maxAgeSec) => res.append('Set-Cookie',
        `${COOKIE}=${encodeURIComponent(value)}; Path=/api/admin; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${req.secure ? '; Secure' : ''}`);
    let legacyWarned = false;

    function adminAuth(req, res, next) {
        // 1) HttpOnly session cookie (admin panel) – state-changing calls also need the CSRF header
        const cookieSess = auth.parse(readCookie(req, COOKIE));
        if (cookieSess) {
            if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
                const sent = Buffer.from(String(req.headers['x-csrf-token'] || '')), want = Buffer.from(cookieSess.csrf);
                if (sent.length !== want.length || !crypto.timingSafeEqual(sent, want))
                    return res.status(403).json({ error: 'CSRF check failed' });
            }
            req.admin = { sid: cookieSess.sid, sess: cookieSess, via: 'cookie' };
            return next();
        }
        // 2) X-Admin-Token: session token from /login, or (legacy) the raw admin password
        const hdr = String(req.headers['x-admin-token'] || (config.ALLOW_QUERY_TOKEN ? req.query.token : '') || '');
        const hdrSess = auth.parse(hdr);
        if (hdrSess) { req.admin = { sid: hdrSess.sid, sess: hdrSess, via: 'token' }; return next(); }
        if (hdr && !config.DISABLE_LEGACY_TOKEN && auth.checkPassword(hdr)) {
            if (!legacyWarned) { legacyWarned = true; log.warn('Legacy raw-password X-Admin-Token in use — switch clients to the session token from /api/admin/login'); }
            req.admin = { sid: 'legacy', via: 'legacy' };
            return next();
        }
        recordFail(req.ip);
        res.status(401).json({ error: 'Unauthorized' });
    }

    app.post('/api/admin/login', adminLoginLimiter, safe(async (req, res) => {
        const { password } = req.body || {};
        if (typeof password !== 'string' || !auth.checkPassword(password)) {
            recordFail(req.ip); log.warn('Admin login failed');
            return res.status(401).json({ success: false, error: 'Wrong password' });
        }
        const { token, payload } = auth.issue();
        setCookie(req, res, token, Math.floor(auth.ttlMs / 1000));
        req.admin = { sid: payload.sid };
        await audit(req, 'admin.login');
        // `token` stays in the body for older clients (send it as X-Admin-Token). It is a session token, not the password.
        res.json({ success: true, token, csrfToken: payload.csrf, expiresAt: new Date(payload.exp).toISOString() });
    }));

    app.use('/api/admin', adminLimiter);

    app.post('/api/admin/logout', adminAuth, safe(async (req, res) => {
        if (req.admin.sess) auth.revoke(req.admin.sess);
        setCookie(req, res, '', 0);
        await audit(req, 'admin.logout');
        res.json({ success: true });
    }));

    app.get('/api/admin/session', adminAuth, (req, res) => {
        if (!req.admin.sess) return res.json({ authenticated: true, legacy: true });
        res.json({ authenticated: true, csrfToken: req.admin.sess.csrf, expiresAt: new Date(req.admin.sess.exp).toISOString() });
    });

    // Admin-only diagnostics (the public /health deliberately shows none of this)
    app.get('/api/admin/system', adminAuth, (req, res) => res.json({
        firebase: state.firebase, uptime: Math.floor((Date.now() - startedAt) / 1000), bannedIPs: bannedIPs.size,
        node: process.version, urlKingConfigured: !!config.URLKING_API,
    }));

    // ═════════════════ ADMIN KEYS ═════════════════
    const admin = [adminAuth, needDb];

    app.get('/api/admin/stats', ...admin, safe(async (req, res) => {
        res.json({ ...(await S.stats(req.db)), bannedIPs: bannedIPs.size, serverUptime: Math.floor(process.uptime()) + 's' });
    }));

    // Legacy: full array (now with derived `status`)
    app.get('/api/admin/keys', ...admin, safe(async (req, res) => {
        const now = Date.now();
        res.json(S.filterKeys(await S.allKeys(req.db), {}, now).map(k => S.withStatus(k, now)));
    }));
    // New: search / filter / sort / paginate
    app.get('/api/admin/keys/search', ...admin, safe(async (req, res) => res.json(await S.searchKeys(req.db, req.query))));
    app.get('/api/admin/keys/ids', ...admin, safe(async (req, res) => res.json(await S.matchingKeyIds(req.db, req.query))));

    app.post('/api/admin/create-key', ...admin, safe(async (req, res) => {
        const keys = await S.createKeys(req.db, req.body || {});
        await audit(req, 'key.create', { keys: keys.map(k => k.key), details: {
            count: keys.length, site: keys[0].siteId, custom: !!(req.body && req.body.customKey),
            expiresAt: keys[0].expiresAt, durationDays: keys[0].durationDays, loginLimit: keys[0].loginLimit } });
        res.json({ success: true, key: keys[0], keys });       // `key` kept for the old panel
    }));

    app.patch('/api/admin/key/:key', ...admin, safe(async (req, res) => {
        const k = keyParam(req);
        const r = await S.editKey(req.db, k, req.body);
        const pick = o => Object.fromEntries(r.changed.map(f => [f, f === 'hwid' ? (o[f] ? 'set' : null) : o[f]]));
        await audit(req, 'key.edit', { keys: [k], details: { before: pick(r.before), after: pick(r.after) } });
        res.json({ success: true, key: S.withStatus(r.after, Date.now()) });
    }));

    app.delete('/api/admin/key/:key', ...admin, safe(async (req, res) => {
        const k = keyParam(req);
        const r = await S.deleteKeys(req.db, [k]);
        if (r.notFound.length) throw new HttpError(404, 'Not found');
        await audit(req, 'key.delete', { keys: [k], details: bulkDetails(r) });
        res.json({ success: true });
    }));

    app.post('/api/admin/key/:key/reset-device', ...admin, safe(async (req, res) => {
        const k = keyParam(req);
        await S.resetDeviceAdmin(req.db, k);
        await audit(req, 'key.reset_device', { keys: [k] });
        res.json({ success: true });
    }));

    const single = (action, run, extra = () => ({})) => safe(async (req, res) => {
        const k = keyParam(req);
        const r = await run(req.db, [k], req.body || {});
        if (r.notFound.length) throw new HttpError(404, 'Not found');
        if (r.skipped.length) return res.status(409).json({ success: false, error: r.skipped[0].reason });
        await audit(req, action, { keys: [k], details: bulkDetails(r, extra(req.body || {})) });
        res.json({ success: true, key: S.withStatus((await req.db.collection('keys').doc(k).get()).data(), Date.now()) });
    });
    app.post('/api/admin/key/:key/revoke',  ...admin, single('key.revoke',  (db, k, b) => S.revokeKeys(db, k, b.reason), b => ({ reason: String(b.reason || '').slice(0, 200) })));
    app.post('/api/admin/key/:key/restore', ...admin, single('key.restore', (db, k) => S.restoreKeys(db, k)));
    app.post('/api/admin/key/:key/extend',  ...admin, single('key.extend',  (db, k, b) => S.extendKeys(db, k, b.days), b => ({ days: b.days })));
    app.post('/api/admin/key/:key/expiry',  ...admin, single('key.set_expiry', (db, k, b) => S.setExpiry(db, k, b.expiresAt), b => ({ expiresAt: b.expiresAt || null })));

    // Bulk: { action: revoke|restore|delete|extend, keys:[…≤500], days?, reason?, confirm? (required for delete) }
    app.post('/api/admin/keys/bulk', ...admin, safe(async (req, res) => {
        const { action, keys, days, reason, confirm } = req.body || {};
        let r, extra = {};
        switch (action) {
            case 'revoke':  r = await S.revokeKeys(req.db, keys, reason); extra = { reason: String(reason || '').slice(0, 200) }; break;
            case 'restore': r = await S.restoreKeys(req.db, keys); break;
            case 'extend':  r = await S.extendKeys(req.db, keys, days); extra = { days }; break;
            case 'delete':
                if (confirm !== true) throw new HttpError(400, 'Bulk delete requires "confirm": true');
                r = await S.deleteKeys(req.db, keys); break;
            default: throw new HttpError(400, 'action must be revoke, restore, extend or delete');
        }
        await audit(req, `key.bulk_${action}`, { keys: r.processed, details: bulkDetails(r, extra) });
        res.json(bulkReply(r));
    }));

    // ═════════════════ AUDIT (read-only) ═════════════════
    app.get('/api/admin/audit', ...admin, safe(async (req, res) =>
        res.json(await L.listAudit(req.db, { before: req.query.before, limit: parseInt(req.query.limit) || 50,
            action: req.query.action, key: req.query.key }))));
    app.get('/api/admin/audit/verify', ...admin, safe(async (req, res) => res.json(await L.verifyAuditChain(req.db))));

    // ═════════════════ BANS ═════════════════
    app.get('/api/admin/bans', adminAuth, (req, res) =>
        res.json([...bannedIPs].map(([ip, until]) => ({ ip, minutesLeft: Math.ceil((until - Date.now()) / 60000) }))));
    app.delete('/api/admin/ban/:ip', adminAuth, safe(async (req, res) => {
        bannedIPs.delete(req.params.ip); failedAttempts.delete(req.params.ip);
        await audit(req, 'ban.remove', { details: { ip: req.params.ip } });
        res.json({ success: true, message: `${req.params.ip} unbanned` });
    }));

    // ═════════════════ ADMIN PANEL (static) ═════════════════
    app.get('/admin', (req, res) => res.redirect(301, '/admin/'));
    app.use('/admin', adminLimiter, express.static(path.join(__dirname, '..', 'public', 'admin'), { index: 'index.html', dotfiles: 'ignore', maxAge: 0 }));

    // ── 404 + error handler ─────────────────────────────────────
    app.use((req, res) => res.status(404).json({ error: 'Not found' }));
    app.use((err, req, res, next) => {  // eslint-disable-line no-unused-vars
        if (res.headersSent) return;
        const status = err instanceof HttpError ? err.status : (err.status >= 400 && err.status < 500 ? err.status : 500);
        if (status === 500) log.err('Express error', err);
        res.status(status).json({ error: status === 500 ? 'Server error' : (err instanceof HttpError ? err.message : 'Bad request') });
    });

    app.locals.cleanup = () => clearInterval(sweep);
    return app;
}

module.exports = { createApp };
