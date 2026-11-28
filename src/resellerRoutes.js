'use strict';
// Routes for resellers.
//   OWNER (existing admin login)   /api/admin/resellers/*     create / limit / block / block API / reset password / regenerate API key / delete
//   RESELLER PANEL (cookie login)  /api/reseller/*            login, me, keys/generate (1–7 days), keys, api-key
//   KEY-FETCH API (X-Api-Key)      /api/v1/me · /api/v1/keys  the same fetch function the panel uses
const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const L = require('./lib');
const R = require('./resellers');
const { HttpError } = L;

function mountResellerRoutes(app, { needDb, safe, adminAuth, audit, recordFail, config, getDb, log }) {
    const sessions = R.createSessions(config.SESSION_SECRET || config.ADMIN_PASS);
    const COOKIE = 'srtx_reseller';
    const readCookie = (req, name) => {
        const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith(name + '='));
        return m ? decodeURIComponent(m.slice(name.length + 1)) : '';
    };
    const setCookie = (req, res, value, maxAgeSec) => res.append('Set-Cookie',
        `${COOKIE}=${encodeURIComponent(value)}; Path=/api/reseller; HttpOnly; SameSite=Strict; Max-Age=${maxAgeSec}${req.secure ? '; Secure' : ''}`);
    const tooMany = (msg = 'Too many requests. Wait a few minutes.') => (req, res) => res.status(429).json({ error: msg });

    // Audit as the reseller (hash-chained, same log the owner reads)
    async function auditAs(req, actor, action, { keys = [], details = {} } = {}) {
        try { const db = getDb(); if (!db) throw new Error('db unavailable'); return await L.writeAudit(db, { action, actor, ip: req.ip, sid: null, count: keys.length, keys: keys.slice(0, 500), details }); }
        catch (e) { log.err('AUDIT WRITE FAILED', e, { action }); return null; }
    }
    const csrfOk = (req, want) => { const sent = Buffer.from(String(req.headers['x-csrf-token'] || '')), w = Buffer.from(want); return sent.length === w.length && crypto.timingSafeEqual(sent, w); };

    // ═════════ OWNER: manage resellers ═════════
    const owner = express.Router();
    owner.use(adminAuth, needDb);

    owner.get('/', safe(async (req, res) => res.json({ items: await R.listResellers(req.db), maxDays: R.MAX_DAYS })));
    owner.post('/', safe(async (req, res) => {
        const b = req.body || {}, r = await R.createReseller(req.db, b);
        await audit(req, 'reseller.create', { details: { username: r.reseller.username, keyLimit: r.reseller.keyLimit } });
        res.status(201).json({ success: true, ...r });
    }));
    owner.patch('/:id', safe(async (req, res) => {
        const b = req.body || {}, r = await R.updateReseller(req.db, req.params.id, b);
        await audit(req, 'reseller.update', { details: { username: r.username, ...Object.fromEntries(['keyLimit', 'status', 'apiEnabled', 'note', 'resetUsed'].filter(k => b[k] !== undefined).map(k => [k, k === 'note' ? '(changed)' : b[k]])) } });
        res.json({ success: true, reseller: r });
    }));
    owner.post('/:id/password', safe(async (req, res) => {
        await R.setPassword(req.db, req.params.id, (req.body || {}).password);
        await audit(req, 'reseller.password', { details: { username: String(req.params.id).toLowerCase() } });
        res.json({ success: true });
    }));
    owner.post('/:id/api-key', safe(async (req, res) => {
        const r = await R.regenApiKey(req.db, req.params.id);
        await audit(req, 'reseller.api_key', { details: { username: String(req.params.id).toLowerCase() } });
        res.json({ success: true, ...r });
    }));
    owner.get('/:id/keys', safe(async (req, res) => {
        const { id } = await R.loadRaw(req.db, req.params.id);
        res.json({ items: await R.listKeys(req.db, id) });
    }));
    owner.post('/:id/revoke-keys', safe(async (req, res) => {
        if ((req.body || {}).confirm !== true) throw new HttpError(400, 'Send {"confirm": true}');
        const r = await R.revokeAllKeys(req.db, req.params.id, (req.body || {}).reason);
        await audit(req, 'reseller.revoke_all', { details: { username: String(req.params.id).toLowerCase(), processed: r.processed } });
        res.json({ success: true, ...r });
    }));
    owner.delete('/:id', safe(async (req, res) => {
        if ((req.body || {}).confirm !== true) throw new HttpError(400, 'Send {"confirm": true}');
        const r = await R.deleteReseller(req.db, req.params.id, { revokeKeys: (req.body || {}).revokeKeys === true });
        await audit(req, 'reseller.delete', { details: { username: String(req.params.id).toLowerCase(), revokedKeys: r.revoked } });
        res.json({ success: true, ...r });
    }));
    app.use('/api/admin/resellers', owner);

    // ═════════ RESELLER PANEL (cookie session) ═════════
    const panel = express.Router();
    panel.use(rateLimit({ windowMs: 15 * 60 * 1000, limit: 400, standardHeaders: true, legacyHeaders: false, handler: tooMany() }));
    const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, skipSuccessfulRequests: true,
        handler: (req, res) => { recordFail(req.ip); res.status(429).json({ error: 'Too many login attempts. Wait 15 minutes.' }); } });

    async function resellerAuth(req, res, next) {
        try {
            const p = sessions.parse(readCookie(req, COOKIE));
            if (!p) return res.status(401).json({ error: 'Please sign in' });
            if (!['GET', 'HEAD', 'OPTIONS'].includes(req.method) && !csrfOk(req, p.csrf)) return res.status(403).json({ error: 'CSRF check failed' });
            const acct = await R.accountForSession(req.db, p);
            if (!acct) { setCookie(req, res, '', 0); return res.status(401).json({ error: 'Session ended — sign in again' }); }
            req.reseller = acct; req.rsess = p; next();
        } catch (e) { next(e); }
    }
    const rs = [needDb, resellerAuth];

    panel.post('/login', loginLimiter, needDb, safe(async (req, res) => {
        const b = req.body || {};
        let acct;
        try { acct = await R.login(req.db, b.username, b.password); }
        catch (e) { if (e instanceof HttpError && e.status === 401) recordFail(req.ip); throw e; }
        const { token, payload } = sessions.issue(acct);
        setCookie(req, res, token, Math.floor(sessions.ttlMs / 1000));
        await auditAs(req, `reseller:${acct.username}`, 'reseller.login');
        res.json({ success: true, csrfToken: payload.csrf, reseller: R.view(acct), expiresAt: new Date(payload.exp).toISOString() });
    }));
    panel.get('/session', ...rs, (req, res) => res.json({ authenticated: true, csrfToken: req.rsess.csrf, reseller: R.view(req.reseller) }));
    panel.post('/logout', ...rs, safe(async (req, res) => {
        await R.logoutEverywhere(req.db, req.reseller.username); setCookie(req, res, '', 0); res.json({ success: true });
    }));
    panel.get('/keys', ...rs, safe(async (req, res) => res.json({ items: await R.listKeys(req.db, req.reseller.username), reseller: R.view(await R.accountForSession(req.db, req.rsess) || req.reseller) })));
    // The panel's day buttons call this: it is the same key-fetch function the public API uses.
    panel.post('/keys/generate', ...rs, safe(async (req, res) => {
        const b = req.body || {}, r = await R.fetchKeys(req.db, req.reseller.username, b);
        await auditAs(req, `reseller:${req.reseller.username}`, 'reseller.keys', { keys: r.keys, details: { days: r.days, via: 'panel' } });
        res.json({ success: true, ...r });
    }));
    panel.post('/api-key', ...rs, safe(async (req, res) => {
        const r = await R.ownRegenApiKey(req.db, req.reseller.username);
        await auditAs(req, `reseller:${req.reseller.username}`, 'reseller.api_key', {});
        res.json({ success: true, ...r });
    }));
    app.use('/api/reseller', panel);

    // ═════════ KEY-FETCH API (for the reseller's own scripts / bots) ═════════
    const v1 = express.Router();
    v1.use(rateLimit({ windowMs: 60 * 1000, limit: 60, standardHeaders: true, legacyHeaders: false, handler: tooMany('Rate limit: 60 requests per minute.') }));
    v1.use(needDb);
    v1.use(safe(async (req, res, next) => {
        const raw = String(req.headers['x-api-key'] || (/^Bearer (.+)$/.exec(req.headers.authorization || '') || [])[1] || '');   // never from the URL (it would end up in logs)
        try { req.reseller = await R.accountForApiKey(req.db, raw); }
        catch (e) { if (e instanceof HttpError && e.status === 401) recordFail(req.ip); throw e; }
        next();
    }));
    v1.get('/me', (req, res) => res.json({ success: true, reseller: R.view(req.reseller), site: 'SENSI MACRO', days: [1, 2, 3, 4, 5, 6, 7], maxPerRequest: R.MAX_PER_REQUEST }));
    v1.get('/keys', safe(async (req, res) => res.json({ success: true, items: await R.listKeys(req.db, req.reseller.username) })));
    v1.post('/keys', safe(async (req, res) => {
        const r = await R.fetchKeys(req.db, req.reseller.username, req.body || {});
        await auditAs(req, `reseller:${req.reseller.username}`, 'reseller.keys', { keys: r.keys, details: { days: r.days, via: 'api' } });
        res.status(201).json({ success: true, ...r });
    }));
    v1.use((req, res) => res.status(404).json({ error: 'Not found' }));
    app.use('/api/v1', v1);
}

module.exports = { mountResellerRoutes };
