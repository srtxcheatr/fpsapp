'use strict';
// Owner panel ⇄ reseller accounts ⇄ key-fetch API (1–7 day SENSI MACRO keys), limits, blocking.
const test = require('node:test');
const assert = require('node:assert/strict');
let createApp; try { ({ createApp } = require('../src/app')); } catch (e) { createApp = null; }
const L = require('../src/lib');
const S = require('../src/service');
const { makeFakeDb } = require('./fakeFirestore');
const opts = { skip: createApp ? false : 'dependencies not installed' };
const PASS = 'test-admin-password-123';

async function boot() {
    const db = makeFakeDb(), sink = { log() {}, warn() {}, error() {} };
    const config = { ADMIN_PASS: PASS, SESSION_SECRET: '', URLKING_API: '', SITE_URL: 'http://x', FRONTEND_URL: 'http://x', ALLOWED_ORIGINS: [], MAX_PAYLOAD: '10kb', TRUST_PROXY: 1, ALLOW_QUERY_TOKEN: false, DISABLE_LEGACY_TOKEN: false };
    const app = createApp({ getDb: () => db, serverTimestamp: () => new Date(), config, log: L.makeLogger(sink), state: { firebase: { status: 'ready' } } });
    const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const call = async (method, path, { body, headers = {}, cookie } = {}) => {
        const res = await fetch(base + path, { method, redirect: 'manual', body: body === undefined ? undefined : JSON.stringify(body),
            headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...(cookie ? { Cookie: cookie } : {}), ...headers } });
        const text = await res.text(); let json; try { json = JSON.parse(text); } catch {}
        return { status: res.status, json, text, headers: res.headers, cookie: (res.headers.getSetCookie?.()[0] || '').split(';')[0] };
    };
    const lg = await call('POST', '/api/admin/login', { body: { password: PASS } });
    const ownerH = { 'X-Admin-Token': lg.json.token };
    const owner = (m, p, body) => call(m, '/api/admin/resellers' + p, { body, headers: ownerH });
    const panelLogin = async (username, password) => {
        const r = await call('POST', '/api/reseller/login', { body: { username, password } });
        return { ...r, as: (m, p, body) => call(m, '/api/reseller' + p, { body, cookie: r.cookie, headers: { 'X-CSRF-Token': r.json && r.json.csrfToken || '' } }) };
    };
    const api = (key, m, p, body) => call(m, '/api/v1' + p, { body, headers: { 'X-Api-Key': key } });
    return { db, call, owner, panelLogin, api, close: () => { app.locals.cleanup(); return new Promise(r => server.close(r)); } };
}
const mk = (t, o = {}) => t.owner('POST', '', { username: 'rahul', password: 'Strong#Pass1', keyLimit: 10, ...o });

test('owner creates a reseller: validation, one-time API key, no secrets in listings', opts, async () => {
    const t = await boot();
    try {
        assert.equal((await t.call('GET', '/api/admin/resellers')).status, 401);                     // owner only
        const c = await mk(t); assert.equal(c.status, 201);
        assert.match(c.json.apiKey, /^srtx\.rahul\.[A-Za-z0-9_-]{43}$/); assert.equal(c.json.reseller.keyLimit, 10);
        assert.equal((await mk(t)).status, 409);
        assert.equal((await mk(t, { username: 'Bad Name!' })).status, 400);
        assert.equal((await mk(t, { username: 'admin' })).status, 400);
        assert.equal((await mk(t, { username: 'shorty', password: '123' })).status, 400);
        const list = await t.owner('GET', '');
        assert.equal(list.json.items.length, 1);
        assert.ok(!/passHash|passSalt|apiKeyHash|srtx\.rahul\./.test(list.text), 'listing must never contain hashes or the API key');
        const raw = t.db._store.get('resellers/rahul'); assert.ok(!raw.passHash.includes('Strong') && raw.apiKeyHash.length === 64);
    } finally { await t.close(); }
});

test('panel login + 1–7 day keys through the fetch API; keys work in the app login (unchanged)', opts, async () => {
    const t = await boot();
    try {
        await mk(t);
        assert.equal((await t.panelLogin('rahul', 'wrong-password')).status, 401);
        assert.equal((await t.panelLogin('nobody', 'Strong#Pass1')).status, 401);
        const p = await t.panelLogin('rahul', 'Strong#Pass1'); assert.equal(p.status, 200); assert.ok(p.cookie.startsWith('srtx_reseller='));
        assert.equal((await t.call('POST', '/api/reseller/keys/generate', { body: { days: 3 }, cookie: p.cookie })).status, 403);   // no CSRF header
        const g = await p.as('POST', '/keys/generate', { days: 3, count: 2, label: 'Aman <b>' });
        assert.equal(g.status, 200); assert.equal(g.json.count, 2); assert.equal(g.json.keysLeft, 8);
        const kd = t.db._store.get(`keys/${g.json.keys[0]}`);
        assert.match(kd.key, /^SENSI_/); assert.equal(kd.durationDays, 3); assert.equal(kd.resellerId, 'rahul'); assert.equal(kd.loginLimit, 1); assert.ok(!kd.label.includes('<'));
        const v = await S.verifyKey(t.db, g.json.keys[0], 'device-1');                                  // the app's own login path
        assert.equal(v.body.valid, true); assert.equal(v.body.daysLeft, 3);
        for (const bad of [0, 8, -1, 'x', 2.5, null]) assert.equal((await p.as('POST', '/keys/generate', { days: bad })).status, 400, `days=${bad}`);
        assert.equal((await p.as('POST', '/keys/generate', { days: 1, count: 51 })).status, 400);
        const list = await p.as('GET', '/keys'); assert.equal(list.json.items.length, 2); assert.equal(list.json.items[0].days, 3);
        const me = await p.as('GET', '/session'); assert.equal(me.json.reseller.keysUsed, 2); assert.equal(me.json.reseller.usedByDay['3'], 2);
        assert.equal((await t.call('GET', '/api/admin/stats', { cookie: p.cookie })).status, 401);        // reseller session is useless on owner routes
    } finally { await t.close(); }
});

test('key limit is exact — even with parallel requests', opts, async () => {
    const t = await boot();
    try {
        await mk(t, { keyLimit: 3 });
        const p = await t.panelLogin('rahul', 'Strong#Pass1');
        const rs = await Promise.all(Array.from({ length: 6 }, () => p.as('POST', '/keys/generate', { days: 1 })));
        assert.equal(rs.filter(r => r.status === 200).length, 3); assert.equal(rs.filter(r => r.status === 403).length, 3);
        assert.equal((await p.as('POST', '/keys/generate', { days: 1 })).json.error.includes('limit'), true);
        assert.equal([...t.db._store.keys()].filter(k => k.startsWith('keys/')).length, 3);
        await t.owner('PATCH', '/rahul', { keyLimit: 5 });                                                // owner raises the limit
        assert.equal((await p.as('POST', '/keys/generate', { days: 2, count: 2 })).status, 200);
        assert.equal((await p.as('POST', '/keys/generate', { days: 2, count: 1 })).status, 403);
        await t.owner('PATCH', '/rahul', { resetUsed: true });
        assert.equal((await p.as('POST', '/keys/generate', { days: 2, count: 5 })).status, 200);
    } finally { await t.close(); }
});

test('API with X-Api-Key; owner can block the API (panel fetch too) or the whole account', opts, async () => {
    const t = await boot();
    try {
        const { json: { apiKey } } = await mk(t);
        assert.equal((await t.call('GET', '/api/v1/me')).status, 401);
        assert.equal((await t.api('srtx.rahul.' + 'A'.repeat(43), 'GET', '/me')).status, 401);
        assert.equal((await t.call('GET', '/api/v1/me?apiKey=' + apiKey)).status, 401);                // keys in the URL are ignored
        const me = await t.api(apiKey, 'GET', '/me'); assert.equal(me.status, 200); assert.deepEqual(me.json.days, [1, 2, 3, 4, 5, 6, 7]); assert.equal(me.json.site, 'SENSI MACRO');
        const k = await t.api(apiKey, 'POST', '/keys', { days: 7, count: 3 });
        assert.equal(k.status, 201); assert.equal(k.json.keys.length, 3); assert.equal(k.json.keysLeft, 7);
        assert.equal((await t.api(apiKey, 'GET', '/keys')).json.items.length, 3);

        const p = await t.panelLogin('rahul', 'Strong#Pass1');
        await t.owner('PATCH', '/rahul', { apiEnabled: false });                                        // BLOCK API
        const a = await t.api(apiKey, 'POST', '/keys', { days: 1 }); assert.equal(a.status, 403); assert.match(a.json.error, /API/);
        assert.equal((await p.as('POST', '/keys/generate', { days: 1 })).status, 403);                  // panel uses the same fetch system → blocked too
        assert.equal((await p.as('GET', '/keys')).status, 200);                                         // …but they can still see their keys
        await t.owner('PATCH', '/rahul', { apiEnabled: true });
        assert.equal((await t.api(apiKey, 'POST', '/keys', { days: 1 })).status, 201);

        await t.owner('PATCH', '/rahul', { status: 'blocked' });                                        // BLOCK ACCOUNT
        assert.equal((await p.as('GET', '/session')).status, 401);                                      // signed out immediately
        assert.equal((await t.panelLogin('rahul', 'Strong#Pass1')).status, 403);
        assert.equal((await t.api(apiKey, 'GET', '/me')).status, 403);
        await t.owner('PATCH', '/rahul', { status: 'active' });
        assert.equal((await t.panelLogin('rahul', 'Strong#Pass1')).status, 200);
    } finally { await t.close(); }
});

test('password reset kills sessions; new API key kills the old one; logout works; lockout after 5 wrong passwords', opts, async () => {
    const t = await boot();
    try {
        const { json: { apiKey } } = await mk(t);
        const p = await t.panelLogin('rahul', 'Strong#Pass1');
        assert.equal((await t.owner('POST', '/rahul/password', { password: 'short' })).status, 400);
        assert.equal((await t.owner('POST', '/rahul/password', { password: 'Brand#New99' })).status, 200);
        assert.equal((await p.as('GET', '/session')).status, 401);
        assert.equal((await t.panelLogin('rahul', 'Strong#Pass1')).status, 401);
        const p2 = await t.panelLogin('rahul', 'Brand#New99'); assert.equal(p2.status, 200);
        const rk = await t.owner('POST', '/rahul/api-key'); assert.equal(rk.status, 200);
        assert.equal((await t.api(apiKey, 'GET', '/me')).status, 401);
        assert.equal((await t.api(rk.json.apiKey, 'GET', '/me')).status, 200);
        const own = await p2.as('POST', '/api-key'); assert.equal(own.status, 200);                      // reseller can rotate their own key
        assert.equal((await t.api(rk.json.apiKey, 'GET', '/me')).status, 401);
        assert.equal((await p2.as('POST', '/logout')).status, 200); assert.equal((await p2.as('GET', '/session')).status, 401);
        for (let i = 0; i < 5; i++) await t.panelLogin('rahul', 'nope-nope-' + i);
        const locked = await t.panelLogin('rahul', 'Brand#New99'); assert.equal(locked.status, 429);   // locked even with the right password
    } finally { await t.close(); }
});

test('owner: revoke all keys of a reseller, view their keys, delete (confirm required), audit trail', opts, async () => {
    const t = await boot();
    try {
        const { json: { apiKey } } = await mk(t);
        const made = (await t.api(apiKey, 'POST', '/keys', { days: 2, count: 3 })).json.keys;
        assert.equal((await t.owner('GET', '/rahul/keys')).json.items.length, 3);
        assert.equal((await t.owner('POST', '/rahul/revoke-keys', {})).status, 400);
        const rv = await t.owner('POST', '/rahul/revoke-keys', { confirm: true }); assert.equal(rv.json.processed, 3);
        assert.equal((await S.verifyKey(t.db, made[0], 'dev')).body.message, 'Key revoked');
        assert.equal((await t.owner('DELETE', '/rahul', {})).status, 400);
        assert.equal((await t.owner('DELETE', '/rahul', { confirm: true })).status, 200);
        assert.equal((await t.owner('GET', '')).json.items.length, 0);
        assert.equal((await t.api(apiKey, 'GET', '/me')).status, 401);
        assert.ok(t.db._store.has(`keys/${made[1]}`), 'deleting a reseller keeps their keys (unless revokeKeys)');
        const log = [...t.db._store.entries()].filter(([k]) => k.startsWith('audit_logs/')).map(([, v]) => v);
        assert.ok(log.some(e => e.action === 'reseller.create' && e.actor === 'admin'));
        assert.ok(log.some(e => e.action === 'reseller.keys' && e.actor === 'reseller:rahul' && e.details.via === 'api' && e.count === 3));
        assert.equal((await L.verifyAuditChain(t.db)).ok, true);
    } finally { await t.close(); }
});

test('panel + owner pages are served; /owner → /admin/', opts, async () => {
    const t = await boot();
    try {
        const pg = await t.call('GET', '/panel/'); assert.equal(pg.status, 200); assert.match(pg.text, /SENSI MACRO/);
        assert.equal((await t.call('GET', '/panel')).status, 301); assert.equal((await t.call('GET', '/owner')).status, 301);
        const csp = pg.headers.get('content-security-policy'); assert.match(csp, /script-src 'self'/);
    } finally { await t.close(); }
});
