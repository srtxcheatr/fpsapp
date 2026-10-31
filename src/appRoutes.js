'use strict';
// Routes for the server-driven app: /api/app/* (public + key-gated) and /api/admin/app/* (admin).
const express   = require('express');
const rateLimit = require('express-rate-limit');
const AC = require('./appctl');
const S  = require('./service');
const L  = require('./lib');
const { HttpError } = L;

function mountAppRoutes(app, { needDb, safe, adminAuth, audit, recordFail, config }) {
    const tokens = AC.createTokens(config.SESSION_SECRET || config.ADMIN_PASS);
    const hdr = (req, n) => String(req.headers[n] || '').slice(0, 200);

    // AppDeny → JSON { ok:false, code, message }.  GATE → 423 (the app shows the patch / maintenance dialog).
    const guard = fn => safe(async (req, res, next) => {
        try { await fn(req, res, next); }
        catch (e) {
            if (!(e instanceof AC.AppDeny)) throw e;
            if (['KEY_NOT_FOUND', 'APK_MODDED', 'TOKEN_EXPIRED'].includes(e.code)) recordFail(req.ip);
            res.status(e.status).json({ ok: false, code: e.code, message: e.message });
        }
    });
    const gateOrThrow = (cfg, vc, res) => {
        const g = AC.evalGate(cfg, vc);
        if (g.blocked) { res.status(423).json({ ok: false, code: 'GATE', gate: g }); return g; }
        return g;
    };
    const bearer = req => (/^Bearer ([A-Za-z0-9_\-.]+)$/.exec(hdr(req, 'authorization')) || [])[1] || '';
    const session = async (req, cfg) => {
        const p = tokens.parse(bearer(req));
        if (!p) throw new AC.AppDeny('TOKEN_EXPIRED', 'Session expired — log in again', 401);
        AC.checkCert(cfg, hdr(req, 'x-app-cert'));
        await AC.peekKey(req.db, p.k, p.h);              // key must STILL be valid in the database
        return p;
    };

    // ── Public API ───────────────────────────────────────────────
    const pub = express.Router();
    pub.use(rateLimit({ windowMs: 10 * 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false,
        handler: (req, res) => res.status(429).json({ ok: false, code: 'RATE', message: 'Too many requests. Wait a few minutes.' }) }));
    pub.use(needDb);

    // Step 1 — "Downloading necessary files": login page config + assets. No key needed, nothing sensitive in it.
    pub.get('/boot', guard(async (req, res) => {
        const cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, req.query.vc, res); if (g.blocked) return;
        AC.checkCert(cfg, req.query.cert);
        res.json({ ok: true, stage: 1, gate: g, serverTime: new Date().toISOString(), ...(await AC.manifest(req.db, cfg, 1)) });
    }));

    // Login = key check (HWID binding, expiry, device limit) + a short-lived session token.
    const loginLimiter = rateLimit({ windowMs: 5 * 60 * 1000, limit: 20, standardHeaders: true, legacyHeaders: false,
        handler: (req, res) => res.status(429).json({ ok: false, code: 'RATE', message: 'Too many checks. Wait 5 minutes.' }) });
    pub.post('/login', loginLimiter, guard(async (req, res) => {
        const b = req.body || {}, cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, b.vc, res); if (g.blocked) return;
        AC.checkCert(cfg, b.cert);
        const r = await S.verifyKey(req.db, b.key, b.hwid);
        if (r.fail) recordFail(req.ip);
        if (!r.body.valid) {
            const code = /not found|invalid key format/i.test(r.body.message) ? 'KEY_NOT_FOUND' : 'KEY_INVALID';
            return res.status(403).json({ ok: false, code, message: r.body.message });
        }
        const hwid = String(b.hwid || '').trim().slice(0, 128);
        const t = tokens.issue(r.body.key, hwid);
        res.json({ ok: true, token: t.token, tokenExpiresAt: t.expiresAt, ...r.body });
    }));

    // Step 2 — after login: overlay menu, names, logos, sounds, feature toggles. Re-checks key + APK every time.
    pub.get('/stage2', guard(async (req, res) => {
        const cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, hdr(req, 'x-app-vc'), res); if (g.blocked) return;
        const p = await session(req, cfg);
        const t = tokens.issue(p.k, p.h);                // rolling renewal: the app calls this again before expiry
        res.json({ ok: true, stage: 2, gate: g, token: t.token, tokenExpiresAt: t.expiresAt, serverTime: new Date().toISOString(), ...(await AC.manifest(req.db, cfg, 2)) });
    }));

    // Asset bytes. Stage-1 slots are public; stage-2 slots need the session token + valid key + valid APK.
    pub.get('/asset/:slot', guard(async (req, res) => {
        const slot = req.params.slot;
        if (!AC.SLOTS[slot]) return res.status(404).json({ ok: false, code: 'NOT_FOUND', message: 'No such file' });
        const cfg = await AC.getConfig(req.db);
        const g = gateOrThrow(cfg, hdr(req, 'x-app-vc'), res); if (g.blocked) return;
        if (AC.SLOTS[slot].stage === 2) await session(req, cfg); else AC.checkCert(cfg, hdr(req, 'x-app-cert'));
        const f = await AC.getAssetFile(req.db, slot);
        if (!f) return res.status(404).json({ ok: false, code: 'NOT_FOUND', message: 'No such file' });
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
