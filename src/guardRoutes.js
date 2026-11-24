'use strict';
// ═══ Worker gateway: /api/internal/guard/*  (called ONLY by your 5 Cloudflare Workers) ═══
// Auth = HMAC(WORKER_SECRET, ts.METHOD.path.sha256(body)) with a 60 s clock window + replay cache.
// The Android app never talks to these routes; it talks to the Workers, which sign their verdicts.
const crypto = require('crypto');
const express = require('express');
const AC = require('./appctl');
const S = require('./service');
const L = require('./lib');
const { HttpError } = L;

const sha256 = b => crypto.createHash('sha256').update(b).digest('hex');

function createWorkerAuth(secret, { windowMs = 60000 } = {}) {
    const seen = new Map();                                   // nonce -> expiry (replay cache)
    const sweep = setInterval(() => { const n = Date.now(); for (const [k, v] of seen) if (v < n) seen.delete(k); }, 60000);
    sweep.unref();
    return {
        cleanup: () => clearInterval(sweep),
        middleware(req, res, next) {
            const deny = () => res.status(401).json({ ok: false, code: 'WORKER_AUTH' });
            if (!secret || secret.length < 32) return res.status(503).json({ ok: false, code: 'GUARD_DISABLED' });
            const [ts, nonce, sig] = String(req.headers['x-guard-auth'] || '').split('.');
            const t = Number(ts);
            if (!ts || !nonce || !sig || !Number.isFinite(t) || Math.abs(Date.now() - t) > windowMs || nonce.length > 40) return deny();
            const body = JSON.stringify(req.body || {});
            const want = crypto.createHmac('sha256', secret).update(`${ts}.${nonce}.${req.method}.${req.originalUrl.split('?')[0]}.${sha256(body)}`).digest('hex');
            const a = Buffer.from(want), b = Buffer.from(sig);
            if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return deny();
            if (seen.has(nonce)) return deny();
            seen.set(nonce, Date.now() + windowMs * 2);
            next();
        },
    };
}

// Reason a key is not usable right now (read-only, never consumes a login).
async function keyState(db, cfg, { key, hwid, vc, cert }) {
    const g = AC.evalGate(cfg, vc);
    if (g.blocked) return { ok: false, code: 'GATE', message: g.message, gate: g };
    try { AC.checkCert(cfg, cert); } catch (e) { return { ok: false, code: e.code, message: e.message }; }
    try {
        const kd = await AC.peekKey(db, key, hwid);
        return { ok: true, key: kd.key, expiresAt: kd.expiresAt || null, type: kd.type };
    } catch (e) {
        if (!(e instanceof AC.AppDeny)) throw e;
        const m = e.message.toLowerCase();
        const code = e.code === 'KEY_NOT_FOUND' ? 'KEY_NOT_FOUND' : m.includes('expired') ? 'KEY_EXPIRED' : m.includes('revoked') ? 'KEY_REVOKED' : 'KEY_DEVICE';
        return { ok: false, code, message: e.message };
    }
}

function mountGuardRoutes(app, { needDb, safe, adminAuth, recordFail, config }) {
    const auth = createWorkerAuth(config.WORKER_SECRET);
    const r = express.Router();
    r.use(auth.middleware, needDb);

    // 1) Login (consumes a login slot, binds HWID, logs activity). Used by the LOGIN worker.
    r.post('/login', safe(async (req, res) => {
        const b = req.body || {}, cfg = await AC.getConfig(req.db);
        const g = AC.evalGate(cfg, b.vc);
        const log = async (result, code) => { try { await req.db.collection('login_activity').add({ at: new Date().toISOString(), ip: String(b.ip || '').slice(0, 64), country: String(b.country || '').slice(0, 4),
            key: S.normKey(b.key).slice(0, 64), hwid: String(b.hwid || '').slice(0, 16), model: String((b.device && b.device.model) || '').slice(0, 40), vc: Number(b.vc) || 0, result, code }); } catch { /* best effort */ } };
        if (g.blocked) { await log('deny', 'GATE'); return res.json({ ok: false, code: 'GATE', message: g.message, gate: g }); }
        try { AC.checkCert(cfg, b.cert); } catch (e) { await log('deny', e.code); return res.json({ ok: false, code: e.code, message: e.message }); }
        const v = await S.verifyKey(req.db, b.key, b.hwid, Date.now(), { device: b.device, rebindMax: config.AUTO_REBIND_MAX });
        if (!v.body.valid) {
            const code = /not found|invalid key format/i.test(v.body.message) ? 'KEY_NOT_FOUND' : /expired/i.test(v.body.message) ? 'KEY_EXPIRED'
                : /revoked/i.test(v.body.message) ? 'KEY_REVOKED' : 'KEY_DEVICE';
            await log('deny', code);
            return res.json({ ok: false, code, message: v.body.message });
        }
        await log('ok', 'OK');
        res.json({ ok: true, ...v.body });
    }));

    // 2) Read-only state check (launch / heartbeat / feature workers).
    r.post('/state', safe(async (req, res) => {
        const b = req.body || {}, cfg = await AC.getConfig(req.db);
        const st = await keyState(req.db, cfg, b);
        const out = { ...st, serverTime: new Date().toISOString() };
        if (st.ok) {
            out.menuName = cfg.stage2.overlayName;
            out.appName = cfg.stage2.appName;
            if (b.feature) out.featureOn = cfg.stage2.features[String(b.feature).slice(0, 32)] === true;
        }
        res.json(out);
    }));

    app.use('/api/internal/guard', r);

    // Admin: recent login activity (newest first, max 200)
    app.get('/api/admin/login-activity', adminAuth, needDb, safe(async (req, res) => {
        const docs = (await req.db.collection('login_activity').get()).docs.map(d => d.data());
        docs.sort((a, b) => String(b.at).localeCompare(String(a.at)));
        res.json({ total: docs.length, items: docs.slice(0, Math.min(parseInt(req.query.limit) || 100, 200)) });
    }));
    return auth;
}
module.exports = { mountGuardRoutes, createWorkerAuth, keyState };
