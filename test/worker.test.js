'use strict';
// End-to-end: Cloudflare Worker (worker/worker.js) → real Express app with ORIGIN_SECRET → fake Firestore.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
let createApp; try { ({ createApp } = require('../src/app')); } catch (e) { createApp = null; }
const L = require('../src/lib');
const S = require('../src/service');
const { makeFakeDb } = require('./fakeFirestore');
const SECRET = 'w'.repeat(40);

test('worker: allow-list, secret + real client IP forwarded, body bytes intact, origin hidden, full login→heartbeat', { skip: createApp ? false : 'dependencies not installed' }, async t => {
    let worker; try { worker = (await import('../worker/worker.js')).default; } catch (e) { return t.skip('ESM import unsupported: ' + e.message); }
    const db = makeFakeDb(), sink = { log() {}, warn() {}, error() {} };
    const config = { ADMIN_PASS: 'test-admin-password-123', SESSION_SECRET: '', URLKING_API: '', SITE_URL: 'http://x', FRONTEND_URL: 'http://x', ALLOWED_ORIGINS: [], MAX_PAYLOAD: '10kb',
        TRUST_PROXY: 1, ALLOW_QUERY_TOKEN: false, DISABLE_LEGACY_TOKEN: false, ORIGIN_SECRET: SECRET };
    const app = createApp({ getDb: () => db, serverTimestamp: () => new Date(), config, log: L.makeLogger(sink), state: { firebase: { status: 'ready' } } });
    const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    const env = { ORIGIN_URL: `http://127.0.0.1:${server.address().port}`, ORIGIN_SECRET: SECRET };
    const via = (method, path, { body, headers = {} } = {}) => worker.fetch(new Request('https://edge.test' + path, { method, body, headers: { 'cf-connecting-ip': '198.51.100.7', ...headers } }), env, { waitUntil() {} });
    try {
        assert.equal((await via('GET', '/api/admin/stats')).status, 404);                        // admin is not exposed through the Worker
        assert.equal((await via('GET', '/admin')).status, 404);
        assert.equal((await via('DELETE', '/api/app/login')).status, 404);
        assert.equal((await via('GET', '/health')).status, 200);
        assert.equal((await via('POST', '/api/app/session/push-token', { body: '{}', headers: { 'content-type': 'application/json' } })).status, 401);   // route exists, needs a session
        assert.equal((await via('GET', '/api/app/boot?vc=5')).status, 200);

        const [k] = await S.createKeys(db, { siteId: 'site1', count: 1 });
        const loginBody = JSON.stringify({ key: k.key, hwid: 'dev1', vc: 5 });
        const lg = await via('POST', '/api/app/login', { body: loginBody, headers: { 'content-type': 'application/json' } });
        assert.equal(lg.status, 200); const l = await lg.json();
        assert.equal(lg.headers.get('server'), null); assert.equal(lg.headers.get('x-powered-by'), null);      // origin details scrubbed
        assert.equal(db._store.get(`app_sessions/${l.sid}`).ip, '198.51.100.7');                              // real client IP reached the server

        // signed heartbeat through the Worker (body bytes must arrive unchanged)
        const hbBody = '{ "weird" :  "spacing" }', ts = Date.now(), nonce = crypto.randomBytes(12).toString('base64url');
        const sig = crypto.createHmac('sha256', l.secret).update(['POST', '/api/app/session/heartbeat', ts, 1, nonce, crypto.createHash('sha256').update(hbBody).digest('hex')].join('\n')).digest('base64url');
        const hb = await via('POST', '/api/app/session/heartbeat', { body: hbBody, headers: { 'content-type': 'application/json', authorization: `Bearer ${l.sid}`, 'x-ts': String(ts), 'x-seq': '1', 'x-nonce': nonce, 'x-sig': sig } });
        assert.equal(hb.status, 200); assert.equal((await hb.json()).ok, true);

        // junk without a session header is stopped at the edge (never reaches Firestore)
        const junk = await via('POST', '/api/app/session/feature', { body: '{}', headers: { 'content-type': 'application/json' } });
        assert.equal(junk.status, 401); assert.equal((await junk.json()).action, 'CRACKED');

        // direct hit on the origin without the secret is refused
        assert.equal((await fetch(`${env.ORIGIN_URL}/api/app/boot?vc=5`)).status, 404);

        // origin down → transient 502, never a "cracked" answer
        const down = await worker.fetch(new Request('https://edge.test/api/app/boot?vc=5', { headers: { 'cf-connecting-ip': '198.51.100.8' } }), { ...env, ORIGIN_URL: 'http://127.0.0.1:1' }, { waitUntil() {} });
        assert.equal(down.status, 502); assert.equal((await down.json()).action, 'NONE');
    } finally { app.locals.cleanup(); await new Promise(r => server.close(r)); }
});
