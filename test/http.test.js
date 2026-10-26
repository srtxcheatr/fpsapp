'use strict';
// HTTP-level tests (real Express, fake Firestore, Node's built-in fetch).
// Needs `npm install` first; if Express isn't installed the whole file is SKIPPED (not failed).
const test = require('node:test');
const assert = require('node:assert/strict');
let createApp; try { ({ createApp } = require('../src/app')); } catch (e) { createApp = null; var whyNot = e.message.split('\n')[0]; }
const L = require('../src/lib');
const S = require('../src/service');
const { makeFakeDb } = require('./fakeFirestore');

const PASS = 'test-admin-password-123';
const opts = { skip: createApp ? false : `dependencies not installed (${typeof whyNot === 'string' ? whyNot : ''})` };

async function boot({ dbUp = true, origins = [] } = {}) {
    const db = makeFakeDb(), logs = [];
    const sink = { log: l => logs.push(l), warn: l => logs.push(l), error: l => logs.push(l) };
    const config = { ADMIN_PASS: PASS, SESSION_SECRET: '', URLKING_API: 'x', SITE_URL: 'http://x', FRONTEND_URL: 'http://x',
        ALLOWED_ORIGINS: origins, MAX_PAYLOAD: '10kb', TRUST_PROXY: 1, ALLOW_QUERY_TOKEN: false, DISABLE_LEGACY_TOKEN: false };
    const app = createApp({ getDb: () => (dbUp ? db : null), serverTimestamp: () => new Date(), config, log: L.makeLogger(sink), state: { firebase: { status: 'ready' } } });
    const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const close = () => { app.locals.cleanup(); return new Promise(r => server.close(r)); };
    const call = async (method, path, { body, headers = {}, cookie, csrf } = {}) => {
        const res = await fetch(base + path, { method, redirect: 'manual', body: body ? JSON.stringify(body) : undefined,
            headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...(csrf ? { 'X-CSRF-Token': csrf } : {}), ...headers } });
        const text = await res.text(); let json; try { json = JSON.parse(text); } catch {}
        return { status: res.status, headers: res.headers, json, text };
    };
    const login = async () => {
        const r = await call('POST', '/api/admin/login', { body: { password: PASS } });
        return { r, cookie: (r.headers.get('set-cookie') || '').split(';')[0], csrf: r.json && r.json.csrfToken, token: r.json && r.json.token };
    };
    return { db, logs, call, login, close, base };
}

test('GET /health: 200, only status+uptime, works with Firebase down, no sensitive headers', opts, async () => {
    const t = await boot({ dbUp: false });
    try {
        const r = await t.call('GET', '/health');
        assert.equal(r.status, 200);
        assert.deepEqual(Object.keys(r.json).sort(), ['status', 'uptime']);
        assert.equal(r.json.status, 'ok'); assert.ok(Number.isInteger(r.json.uptime) && r.json.uptime >= 0);
        assert.equal((await t.call('HEAD', '/health')).status, 200);
        assert.equal(r.headers.get('x-powered-by'), null);
    } finally { await t.close(); }
});

test('secure headers present on API and admin pages', opts, async () => {
    const t = await boot();
    try {
        const r = await t.call('GET', '/api/verify-key?key=SRT_NOPE2345&hwid=abcd1234');
        assert.equal(r.headers.get('x-content-type-options'), 'nosniff');
        assert.match(r.headers.get('cache-control'), /no-store/);
        assert.match(r.headers.get('content-security-policy'), /default-src 'none'/);
        assert.equal(r.headers.get('x-powered-by'), null);
        const page = await t.call('GET', '/admin/');
        assert.equal(page.status, 200); assert.match(page.text, /Key Admin/);
        assert.match(page.headers.get('content-security-policy'), /script-src 'self'/);
        assert.doesNotMatch(page.headers.get('content-security-policy'), /unsafe-inline/);
        assert.equal((await t.call('GET', '/admin')).status, 301);
        assert.equal((await t.call('GET', '/admin/../server.js')).status, 404);
    } finally { await t.close(); }
});

test('Firebase down → verify-key answers 503 (app treats as offline), never valid:false', opts, async () => {
    const t = await boot({ dbUp: false });
    try {
        const r = await t.call('GET', '/api/verify-key?key=SRT_ABCD2345&hwid=abcd1234');
        assert.equal(r.status, 503); assert.equal(r.headers.get('retry-after'), '30'); assert.equal(r.json.valid, undefined);
        assert.equal((await t.call('POST', '/api/admin/login', { body: { password: PASS } })).status, 200);   // login doesn't need Firestore
    } finally { await t.close(); }
});

test('verify-key contract + revoke/expire/delete take effect on the very next call', opts, async () => {
    const t = await boot();
    try {
        const { cookie, csrf } = await t.login();
        const made = await t.call('POST', '/api/admin/create-key', { cookie, csrf, body: { customKey: 'HTTPKEY1', duration: 3, loginLimit: 1 } });
        assert.equal(made.status, 200); assert.equal(made.json.key.key, 'SRT_HTTPKEY1');
        const v = () => t.call('GET', '/api/verify-key?key=SRT_HTTPKEY1&hwid=DEVICE-HTTP-01');
        const ok = await v();
        assert.equal(ok.status, 200); assert.equal(ok.json.valid, true); assert.equal(ok.json.daysLeft, 3);
        assert.equal((await t.call('POST', '/api/admin/key/SRT_HTTPKEY1/revoke', { cookie, csrf, body: { reason: 'test' } })).status, 200);
        assert.deepEqual((await v()).json, { valid: false, message: 'Key revoked' });
        assert.equal((await t.call('POST', '/api/admin/key/SRT_HTTPKEY1/restore', { cookie, csrf, body: {} })).status, 200);
        assert.equal((await v()).json.valid, true);
        await t.call('POST', '/api/admin/key/SRT_HTTPKEY1/expiry', { cookie, csrf, body: { expiresAt: new Date(Date.now() - 1000).toISOString() } });
        assert.match((await v()).json.message, /expired/i);
        await t.call('POST', '/api/admin/key/SRT_HTTPKEY1/extend', { cookie, csrf, body: { days: 2 } });
        assert.equal((await v()).json.valid, true);
        assert.equal((await t.call('DELETE', '/api/admin/key/SRT_HTTPKEY1', { cookie, csrf })).status, 200);
        assert.equal((await v()).json.message, 'Key not found');
    } finally { await t.close(); }
});

test('admin auth: 401 without credentials, CSRF enforced for cookie sessions, session/legacy tokens work', opts, async () => {
    const t = await boot();
    try {
        assert.equal((await t.call('GET', '/api/admin/stats')).status, 401);
        assert.equal((await t.call('GET', '/api/admin/stats', { headers: { 'X-Admin-Token': 'wrong' } })).status, 401);
        assert.equal((await t.call('GET', `/api/admin/stats?token=${PASS}`)).status, 401);                  // query token off by default
        const bad = await t.call('POST', '/api/admin/login', { body: { password: 'nope' } });
        assert.equal(bad.status, 401); assert.equal(bad.headers.get('set-cookie'), null);

        const { r, cookie, csrf, token } = await t.login();
        const sc = r.headers.get('set-cookie');
        assert.match(sc, /HttpOnly/); assert.match(sc, /SameSite=Strict/); assert.match(sc, /Path=\/api\/admin/);
        assert.notEqual(token, PASS);
        assert.equal((await t.call('GET', '/api/admin/stats', { cookie })).status, 200);                    // reads don't need CSRF
        const noCsrf = await t.call('POST', '/api/admin/create-key', { cookie, body: { count: 1 } });
        assert.equal(noCsrf.status, 403);
        assert.equal((await t.call('POST', '/api/admin/create-key', { cookie, csrf: 'x'.repeat(24), body: {} })).status, 403);
        assert.equal((await t.call('POST', '/api/admin/create-key', { cookie, csrf, body: {} })).status, 200);
        assert.equal((await t.call('GET', '/api/admin/stats', { headers: { 'X-Admin-Token': token } })).status, 200);   // new-style token
        assert.equal((await t.call('POST', '/api/admin/create-key', { headers: { 'X-Admin-Token': PASS }, body: {} })).status, 200); // legacy

        assert.equal((await t.call('POST', '/api/admin/logout', { cookie, csrf, body: {} })).status, 200);
        assert.equal((await t.call('GET', '/api/admin/stats', { cookie })).status, 401);                     // session revoked
    } finally { await t.close(); }
});

test('bulk API: generate, search/filter, bulk revoke, delete needs confirm, audit chain intact', opts, async () => {
    const t = await boot();
    try {
        const { cookie, csrf } = await t.login();
        const gen = await t.call('POST', '/api/admin/create-key', { cookie, csrf, body: { count: 12, length: 10, siteId: 'site2', label: 'promo' } });
        const keys = gen.json.keys.map(k => k.key);
        assert.equal(keys.length, 12); assert.ok(keys.every(k => k.startsWith('SAMUEL_') && k.length === 7 + 10));
        const search = await t.call('GET', '/api/admin/keys/search?search=promo&status=active&limit=5', { cookie });
        assert.equal(search.json.total, 12); assert.equal(search.json.items.length, 5);
        const rev = await t.call('POST', '/api/admin/keys/bulk', { cookie, csrf, body: { action: 'revoke', keys: keys.slice(0, 8), reason: 'bulk' } });
        assert.equal(rev.json.processed, 8);
        assert.equal((await t.call('GET', '/api/admin/keys/search?status=revoked', { cookie })).json.total, 8);
        assert.equal((await t.call('POST', '/api/admin/keys/bulk', { cookie, csrf, body: { action: 'delete', keys } })).status, 400);
        const del = await t.call('POST', '/api/admin/keys/bulk', { cookie, csrf, body: { action: 'delete', keys, confirm: true } });
        assert.equal(del.json.processed, 12);
        assert.equal((await t.call('POST', '/api/admin/keys/bulk', { cookie, csrf, body: { action: 'nuke', keys } })).status, 400);
        const audit = await t.call('GET', '/api/admin/audit?limit=50', { cookie });
        assert.deepEqual(audit.json.items.map(e => e.action).reverse(), ['admin.login', 'key.create', 'key.bulk_revoke', 'key.bulk_delete']);
        assert.deepEqual((await t.call('GET', '/api/admin/audit/verify', { cookie })).json, { ok: true, checked: 4, headSeq: 4 });
        assert.equal(S.BULK_MAX, 500);
    } finally { await t.close(); }
});

test('logs never contain keys, passwords, tokens or query strings', opts, async () => {
    const t = await boot();
    try {
        const { cookie, csrf, token } = await t.login();
        await t.call('POST', '/api/admin/create-key', { cookie, csrf, body: { customKey: 'LOGCHECK9' } });
        await t.call('GET', '/api/verify-key?key=SRT_LOGCHECK9&hwid=SECRETHWID-123');
        await t.call('POST', '/api/admin/login', { body: { password: 'wrong-password-xyz' } });
        const all = t.logs.join('\n');
        for (const s of ['LOGCHECK9', 'SECRETHWID', PASS, 'wrong-password-xyz', token, csrf, '?key=']) assert.ok(!all.includes(s), `log leaked: ${s}`);
        assert.ok(all.includes('/api/verify-key'));
    } finally { await t.close(); }
});

test('errors: bad JSON → 400, oversize → 413, unknown route → 404, CORS-blocked origin → 403', opts, async () => {
    const t = await boot({ origins: ['https://panel.example'] });
    try {
        const post = (body, headers = {}) => fetch(t.base + '/api/admin/login', { method: 'POST', body, headers: { 'Content-Type': 'application/json', ...headers } });
        assert.equal((await post('{not json')).status, 400);
        assert.equal((await post(JSON.stringify({ password: 'x'.repeat(20000) }))).status, 413);
        assert.equal((await t.call('GET', '/nope')).status, 404);
        assert.equal((await t.call('GET', '/health', { headers: { Origin: 'https://evil.example' } })).status, 403);
        assert.equal((await t.call('GET', '/health', { headers: { Origin: 'https://panel.example' } })).status, 200);
    } finally { await t.close(); }
});
