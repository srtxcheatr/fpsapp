'use strict';
// Routes for the server-driven app: /api/app/* (public + session-gated) and /api/admin/app/* (admin).
//
//   PUBLIC (no key)        GET  /boot · GET /asset/:slot (stage-1 slots)
//   LOGIN                  POST /login                       → creates a server-side session {sid, secret}
//   SIGNED SESSION CALLS   GET  /stage2 · GET /asset/:slot (stage-2 slots)
//                          POST /session/feature             → silent per-feature licence check
//                          POST /session/heartbeat           → the 10-minute "are you still licensed" ping
//                          POST /session/push-token          → Firebase token for the server's 8-minute FORCE_CLOSE push
//                          POST /session/logout
// Every signed call: key re-read from the database + session checked + HMAC signature + counter (see appSession.js).
const express   = require('express');
const rateLimit = require('express-rate-limit');
const AC = require('./appctl');
const SS = require('./appSession');
const S  = require('./service');
const L  = require('./lib');
const { HttpError } = L;

const FEATURE_RE = /^[A-Za-z][A-Za-z0-9_]{0,31}$/;

function mountAppRoutes(app, { needDb, safe, adminAuth, audit, recordFail, config, log }) {
    const idleMin      = Number(config.SESSION_IDLE_MIN) > 0 ? Number(config.SESSION_IDLE_MIN) : 13;   // must be > heartbeat interval
    const heartbeatSec = Number(config.HEARTBEAT_SEC) > 0 ? Number(config.HEARTBEAT_SEC) : 600;        // app pings every 10 min
    const sessions = SS.createSessions({ idleMs: idleMin * 60000 });
    const signer = SS.createSigner(config.RESPONSE_SIGNING_KEY);
    if (!signer.enabled && log) log.warn('RESPONSE_SIGNING_KEY not set — responses are NOT signed (a fake server could fool the app). Run: npm run gen-signing-key');
    app.locals.sessions = sessions;                                   // server.js housekeeping + 8-minute sweep
    app.locals.signer = signer;
    const hdr = (req, n) => String(req.headers[n] || '').slice(0, 200);

    // AppDeny → JSON { ok:false, code, action, message }.  GATE → 423 (the app shows the patch / maintenance dialog).
    const guard = fn => safe(async (req, res, next) => {
        try { await fn(req, res, next); }
        catch (e) {
            if (!(e instanceof AC.AppDeny)) throw e;
            if (['KEY_NOT_FOUND', 'APK_MODDED', 'NO_SESSION', 'BAD_SIG', 'REPLAY'].includes(e.code)) recordFail(req.ip);
            res.status(e.status).json({ ok: false, code: e.code, action: SS.actionFor(e.code, req.path === '/login'), message: e.message, ...(e.extra || {}) });
        }
    });
    const gateOrThrow = (cfg, vc, res) => {
        const g = AC.evalGate(cfg, vc);
        if (g.blocked) { res.status(423).json({ ok: false, code: 'GATE', action: 'GATE', gate: g }); return g; }
        return g;
    };
    // Verifies APK cert + signed session + key. Returns { sid, key, hwid, keyData, expiresAt }.
    const session = async (req, cfg) => {
        AC.checkCert(cfg, hdr(req, 'x-app-cert'));
        return sessions.verify(req.db, req);
    };
    const sessionInfo = s => ({ serverTime: new Date().toISOString(), sessionExpiresAt: s.expiresAt, nextInSec: heartbeatSec });

    // ── Public API ───────────────────────────────────────────────
    const pub = express.Router();

    // Sign every JSON answer (success AND errors) so the app can tell a real server from a fake one.
    // Signed text = `${nonce}.${timestamp}.${httpStatus}.${rawBody}` — bound to the request's X-Nonce, so it can't be replayed.
    pub.use((req, res, next) => {
        const nonce = hdr(req, 'x-nonce');
        if (signer.enabled && SS.NONCE_RE.test(nonce)) {
            res.json = body => {
                const text = JSON.stringify(body), ts = String(Date.now());
                res.set({ 'X-Resp-Ts': ts, 'X-Resp-Sig': signer.sign(`${nonce}.${ts}.${res.statusCode}.${text}`) });
                return res.type('application/json').send(text);
            };
        }
        next();
    });
    pub.use(rateLimit({ windowMs: 10 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false,
        handler: (req, res) => res.status(429).json({ ok: false, code: 'RATE', action: 'NONE', message: 'Too many requests. Wait a few minutes.' }) }));
    pub.use(needDb);

    // Step 1 — "Downloading necessary files": login page config + assets. No key needed, nothing sensitive in it.
    pub.get('/boot', guard(async (req, res) => {
        const cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, req.query.vc, res); if (g.blocked) return;
        AC.checkCert(cfg, req.query.cert);
        res.json({ ok: true, stage: 1, gate: g, serverTime: new Date().toISOString(), ...(await AC.manifest(req.db, cfg, 1)) });
    }));

    // Login = key check (HWID binding, expiry, device limit) + a NEW server-side session. The `secret` is shown once, here.
    const loginLimiter = rateLimit({ windowMs: 5 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
        handler: (req, res) => res.status(429).json({ ok: false, code: 'RATE', action: 'NONE', message: 'Too many checks. Wait 5 minutes.' }) });
    pub.post('/login', loginLimiter, guard(async (req, res) => {
        const b = req.body || {}, cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, b.vc, res); if (g.blocked) return;
        AC.checkCert(cfg, b.cert);
        const r = await S.verifyKey(req.db, b.key, b.hwid);
        if (r.fail) recordFail(req.ip);
        if (!r.body.valid) {
            const code = /not found|invalid key format/i.test(r.body.message) ? 'KEY_NOT_FOUND' : 'KEY_INVALID';
            return res.status(403).json({ ok: false, code, action: SS.actionFor(code, true), message: r.body.message });
        }
        const hwid = String(b.hwid || '').trim().slice(0, 128);
        const s = await sessions.create(req.db, { key: r.body.key, hwid, ip: req.ip, vc: b.vc, fcm: b.fcm });
        res.json({ ok: true, sid: s.sid, secret: s.secret, sessionExpiresAt: s.expiresAt, nextInSec: heartbeatSec,
            serverTime: new Date().toISOString(), ...r.body });
    }));

    // Step 2 — after login: overlay menu, names, logos, sounds, feature toggles. Signed + key re-checked every time.
    pub.get('/stage2', guard(async (req, res) => {
        const cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, hdr(req, 'x-app-vc'), res); if (g.blocked) return;
        const s = await session(req, cfg);
        res.json({ ok: true, stage: 2, gate: g, ...sessionInfo(s), ...(await AC.manifest(req.db, cfg, 2)) });
    }));

    // The silent per-feature check: the app calls this in the background BEFORE switching a feature on.
    pub.post('/session/feature', guard(async (req, res) => {
        const cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, hdr(req, 'x-app-vc'), res); if (g.blocked) return;
        const s = await session(req, cfg);
        const name = String((req.body || {}).feature || '');
        if (!FEATURE_RE.test(name)) throw new HttpError(400, 'Bad feature name');
        const known = Object.prototype.hasOwnProperty.call(cfg.stage2.features, name);
        const allowed = known && cfg.stage2.features[name] === true;
        res.json({ ok: true, feature: name, allowed, reason: allowed ? undefined : (known ? 'DISABLED' : 'UNKNOWN'),
            grantExpiresAt: new Date(Date.now() + 60000).toISOString(), daysLeft: s.keyData.expiresAt ? Math.ceil((new Date(s.keyData.expiresAt) - Date.now()) / 86400000) : null,
            ...sessionInfo(s) });
    }));

    // The 10-minute licence ping. Any failure code (see ACTION in appSession.js) tells the app to crash.
    pub.post('/session/heartbeat', guard(async (req, res) => {
        const cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, hdr(req, 'x-app-vc'), res); if (g.blocked) return;
        const s = await session(req, cfg);
        res.json({ ok: true, gate: g, rev: cfg.rev, daysLeft: s.keyData.expiresAt ? Math.ceil((new Date(s.keyData.expiresAt) - Date.now()) / 86400000) : null, ...sessionInfo(s) });
    }));

    // Firebase push token (sent at login too; call this when the token refreshes). Needed for the server's 8-minute FORCE_CLOSE push.
    pub.post('/session/push-token', guard(async (req, res) => {
        const cfg = await AC.getConfig(req.db);
        const s = await session(req, cfg);
        await sessions.setPushToken(req.db, s.sid, (req.body || {}).fcm);
        res.json({ ok: true, ...sessionInfo(s) });
    }));

    pub.post('/session/logout', guard(async (req, res) => {
        const cfg = await AC.getConfig(req.db);
        const s = await session(req, cfg);
        await sessions.destroy(req.db, s.sid);
        res.json({ ok: true, serverTime: new Date().toISOString() });
    }));

    // Asset bytes. Stage-1 slots are public; stage-2 slots need a valid signed session + key + APK.
    pub.get('/asset/:slot', guard(async (req, res) => {
        const slot = req.params.slot;
        if (!AC.SLOTS[slot]) return res.status(404).json({ ok: false, code: 'NOT_FOUND', action: 'NONE', message: 'No such file' });
        const cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, hdr(req, 'x-app-vc'), res); if (g.blocked) return;
        if (AC.SLOTS[slot].stage === 2) await session(req, cfg); else AC.checkCert(cfg, hdr(req, 'x-app-cert'));
        const f = await AC.getAssetFile(req.db, slot);
        if (!f) return res.status(404).json({ ok: false, code: 'NOT_FOUND', action: 'NONE', message: 'No such file' });
        if (req.headers['if-none-match'] === `"${f.sha256}"`) return res.status(304).end();
        res.set({ 'Content-Type': f.mime, 'ETag': `"${f.sha256}"`, 'X-Content-Type-Options': 'nosniff', 'Content-Length': String(f.buf.length) });
        res.end(f.buf);
    }));
    app.use('/api/app', pub);

    // ── Admin API ────────────────────────────────────────────────
    const adm = express.Router();
    adm.use(adminAuth, needDb);
    adm.get('/config', safe(async (req, res) => res.json({ config: await AC.getConfig(req.db), assets: await AC.listAssets(req.db), features: AC.FEATURES })));
    adm.put('/config/:section', safe(async (req, res) => {
        const section = req.params.section, before = (await AC.getConfig(req.db))[section];
        const next = await AC.saveSection(req.db, section, req.body);
        const changed = Object.keys(next[section] || {}).filter(k => JSON.stringify(next[section][k]) !== JSON.stringify((before || {})[k]));
        await audit(req, 'app.config', { details: { section, changed, mode: section === 'gate' ? next.gate.mode : undefined } });
        res.json({ success: true, config: next });
    }));
    adm.post('/assets', express.json({ limit: '1100kb' }), safe(async (req, res) => {
        const r = await AC.putAsset(req.db, req.body && req.body.slot, req.body && req.body.data);
        await audit(req, 'app.asset_put', { details: { slot: r.slot, size: r.size, mime: r.mime } });
        res.json({ success: true, asset: r });
    }));
    adm.delete('/assets/:slot', safe(async (req, res) => {
        await AC.deleteAsset(req.db, req.params.slot);
        await audit(req, 'app.asset_delete', { details: { slot: req.params.slot } });
        res.json({ success: true });
    }));
    app.use('/api/admin/app', adm);
}
module.exports = { mountAppRoutes };
