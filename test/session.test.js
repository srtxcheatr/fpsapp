'use strict';
// v5: server-side sessions, signed requests, signed responses, 10-minute heartbeat, origin lock.
const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('crypto');
let createApp; try { ({ createApp } = require('../src/app')); } catch (e) { createApp = null; }
const L = require('../src/lib');
const S = require('../src/service');
const SS = require('../src/appSession');
const { makeFakeDb } = require('./fakeFirestore');
const opts = { skip: createApp ? false : 'dependencies not installed' };
const PASS = 'test-admin-password-123';
const sha = b => crypto.createHash('sha256').update(b).digest('hex');
const hm = (k, d) => crypto.createHmac('sha256', k).update(d).digest('base64url');

async function boot(extra = {}) {
    const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
    const db = makeFakeDb(), sink = { log() {}, warn() {}, error() {} };
    const config = { ADMIN_PASS: PASS, SESSION_SECRET: '', URLKING_API: '', SITE_URL: 'http://x', FRONTEND_URL: 'http://x', ALLOWED_ORIGINS: [], MAX_PAYLOAD: '10kb',
        TRUST_PROXY: 1, ALLOW_QUERY_TOKEN: false, DISABLE_LEGACY_TOKEN: false, RESPONSE_SIGNING_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }), ...extra };
    const app = createApp({ getDb: () => db, serverTimestamp: () => new Date(), config, log: L.makeLogger(sink), state: { firebase: { status: 'ready' } } });
    const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const raw = async (method, path, { body, headers = {} } = {}) => {
        const nonce = headers['X-Nonce'] || crypto.randomBytes(12).toString('base64url');
        const res = await fetch(base + path, { method, body: body === undefined ? undefined : JSON.stringify(body),
            headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), 'X-Nonce': nonce, ...headers } });
        const text = await res.text(); let json; try { json = JSON.parse(text); } catch {}
        const rs = res.headers.get('x-resp-sig'), rts = res.headers.get('x-resp-ts');
        const signedOk = !!rs && crypto.verify('sha256', Buffer.from(`${nonce}.${rts}.${res.status}.${text}`), { key: publicKey, dsaEncoding: 'der' }, Buffer.from(rs, 'base64url'));
        return { status: res.status, json, text, signedOk, nonce };
    };
    // A well-behaved app: signs every call with the session secret and a rising counter.
    const signed = (sid, secret, st = { seq: 0 }) => async (method, path, body, over = {}) => {
        const ts = over.ts ?? Date.now(), seq = over.seq ?? ++st.seq, nonce = crypto.randomBytes(12).toString('base64url');
        const bodyText = body === undefined ? '' : JSON.stringify(body);
        const sig = over.sig ?? hm(secret, [method, path, ts, seq, nonce, sha(bodyText)].join('\n'));
        return raw(method, path, { body, headers: { Authorization: `Bearer ${sid}`, 'X-Ts': String(ts), 'X-Seq': String(seq), 'X-Nonce': nonce, 'X-Sig': sig, ...(over.headers || {}) } });
    };
    const login = async (key, hwid = 'dev1') => { const r = await raw('POST', '/api/app/login', { body: { key, hwid, vc: 5 } }); return r; };
    const lr = await raw('POST', '/api/admin/login', { body: { password: PASS } });
    return { db, raw, signed, login, base, close: () => { app.locals.cleanup(); return new Promise(r => server.close(r)); } };
}

test('login creates a server session; signed feature + heartbeat + stage2 work; responses are signed', opts, async () => {
    const t = await boot();
    try {
        const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 });
        const lg = await t.login(k.key);
        assert.equal(lg.status, 200); assert.ok(lg.signedOk, 'login response must carry a valid server signature');
        assert.ok(lg.json.sid && lg.json.secret); assert.equal(lg.json.nextInSec, 600);
        assert.ok(t.db._store.has(`app_sessions/${lg.json.sid}`));
        assert.equal(t.db._store.get(`keys/${k.key}`).activeSid, lg.json.sid);

        const api = t.signed(lg.json.sid, lg.json.secret);
        const f = await api('POST', '/api/app/session/feature', { feature: 'macroE' });
        assert.equal(f.status, 200); assert.equal(f.json.allowed, true); assert.ok(f.signedOk);
        assert.equal((await api('POST', '/api/app/session/feature', { feature: 'doesNotExist' })).json.allowed, false);
        const hb = await api('POST', '/api/app/session/heartbeat', {});
        assert.equal(hb.status, 200); assert.equal(hb.json.ok, true);
        const s2 = await api('GET', '/api/app/stage2');
        assert.equal(s2.status, 200); assert.equal(s2.json.stage, 2);
    } finally { await t.close(); }
});

test('no session / forged signature / wrong secret → CRACKED (exit app)', opts, async () => {
    const t = await boot();
    try {
        const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 });
        const lg = await t.login(k.key);
        const none = await t.raw('POST', '/api/app/session/feature', { body: { feature: 'macroE' } });
        assert.equal(none.status, 401); assert.equal(none.json.code, 'NO_SESSION'); assert.equal(none.json.action, 'CRACKED');
        const fake = await t.signed('A'.repeat(43), 'x')('POST', '/api/app/session/feature', { feature: 'macroE' });
        assert.equal(fake.json.code, 'NO_SESSION'); assert.equal(fake.json.action, 'CRACKED');
        const wrong = await t.signed(lg.json.sid, 'not-the-secret')('POST', '/api/app/session/feature', { feature: 'macroE' });
        assert.equal(wrong.json.code, 'BAD_SIG'); assert.equal(wrong.json.action, 'CRACKED');
        // body edited after signing
        const api = t.signed(lg.json.sid, lg.json.secret);
        const ts = Date.now(), nonce = crypto.randomBytes(12).toString('base64url');
        const sig = hm(lg.json.secret, ['POST', '/api/app/session/feature', ts, 1, nonce, sha(JSON.stringify({ feature: 'macroE' }))].join('\n'));
        const tampered = await t.raw('POST', '/api/app/session/feature', { body: { feature: 'gtFix' }, headers: { Authorization: `Bearer ${lg.json.sid}`, 'X-Ts': String(ts), 'X-Seq': '1', 'X-Nonce': nonce, 'X-Sig': sig } });
        assert.equal(tampered.json.code, 'BAD_SIG');
        assert.equal((await api('POST', '/api/app/session/heartbeat', {})).status, 200);       // the real client is unaffected
    } finally { await t.close(); }
});

test('replayed request (same counter) is refused', opts, async () => {
    const t = await boot();
    try {
        const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 });
        const lg = await t.login(k.key), st = { seq: 0 }, api = t.signed(lg.json.sid, lg.json.secret, st);
        assert.equal((await api('POST', '/api/app/session/heartbeat', {})).status, 200);       // seq 1
        const again = await api('POST', '/api/app/session/heartbeat', {}, { seq: 1 });
        assert.equal(again.json.code, 'REPLAY'); assert.equal(again.json.action, 'CRACKED');
        assert.equal((await api('POST', '/api/app/session/heartbeat', {})).status, 200);       // seq 2 still fine
    } finally { await t.close(); }
});

test('idle session expiry → SESSION_EXPIRED → CRASH; any valid call slides the window', opts, async () => {
    const t = await boot();
    try {
        const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 });
        const lg = await t.login(k.key), api = t.signed(lg.json.sid, lg.json.secret);
        const path = `app_sessions/${lg.json.sid}`, before = t.db._store.get(path).expMs;
        await new Promise(r => setTimeout(r, 5));
        assert.equal((await api('POST', '/api/app/session/heartbeat', {})).status, 200);
        assert.ok(t.db._store.get(path).expMs > before, 'heartbeat must extend the session');
        t.db._store.set(path, { ...t.db._store.get(path), expMs: Date.now() - 1000 });          // 13+ minutes of silence
        const dead = await api('POST', '/api/app/session/heartbeat', {});
        assert.equal(dead.status, 401); assert.equal(dead.json.code, 'SESSION_EXPIRED'); assert.equal(dead.json.action, 'CRASH');
    } finally { await t.close(); }
});

test('key revoked / expired / deleted → next call says CRASH', opts, async () => {
    const t = await boot();
    try {
        const mk = async () => { const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 }); const lg = await t.login(k.key); return { k, api: t.signed(lg.json.sid, lg.json.secret) }; };
        const a = await mk(); await S.revokeKeys(t.db, [a.k.key], 'test');
        const ra = await a.api('POST', '/api/app/session/heartbeat', {}); assert.equal(ra.json.code, 'KEY_INVALID'); assert.equal(ra.json.action, 'CRASH');
        const b = await mk(); t.db._store.set(`keys/${b.k.key}`, { ...t.db._store.get(`keys/${b.k.key}`), expiresAt: new Date(Date.now() - 1000).toISOString() });
        assert.equal((await b.api('POST', '/api/app/session/feature', { feature: 'macroE' })).json.code, 'KEY_INVALID');
        const c = await mk(); await S.deleteKeys(t.db, [c.k.key]);
        const rc = await c.api('POST', '/api/app/session/heartbeat', {}); assert.equal(rc.json.code, 'KEY_NOT_FOUND'); assert.equal(rc.json.action, 'CRASH');
    } finally { await t.close(); }
});

test('a newer login of the same key kills the older session (SESSION_REPLACED)', opts, async () => {
    const t = await boot();
    try {
        const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 });
        const l1 = await t.login(k.key), l2 = await t.login(k.key);
        assert.equal(l2.status, 200);
        const old = await t.signed(l1.json.sid, l1.json.secret)('POST', '/api/app/session/heartbeat', {});
        assert.equal(old.json.code, 'SESSION_REPLACED'); assert.equal(old.json.action, 'CRASH');
        assert.equal((await t.signed(l2.json.sid, l2.json.secret)('POST', '/api/app/session/heartbeat', {})).status, 200);
    } finally { await t.close(); }
});

test('wrong device clock → FIX_TIME (no crash); logout ends the session', opts, async () => {
    const t = await boot();
    try {
        const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 });
        const lg = await t.login(k.key), api = t.signed(lg.json.sid, lg.json.secret);
        const skew = await api('POST', '/api/app/session/heartbeat', {}, { ts: Date.now() - 20 * 60000 });
        assert.equal(skew.json.code, 'BAD_TS'); assert.equal(skew.json.action, 'FIX_TIME'); assert.ok(skew.json.serverTime);
        assert.equal((await api('POST', '/api/app/session/logout', {})).status, 200);
        const after = await api('POST', '/api/app/session/heartbeat', {});
        assert.equal(after.json.action, 'CRASH');
    } finally { await t.close(); }
});

test('login failures: wrong key shows an error on the login screen (not a crash)', opts, async () => {
    const t = await boot();
    try {
        const r = await t.login('SRT_NOPE1234');
        assert.equal(r.status, 403); assert.equal(r.json.code, 'KEY_NOT_FOUND'); assert.equal(r.json.action, 'SHOW_ERROR'); assert.ok(r.signedOk);
    } finally { await t.close(); }
});

test('origin lock: with ORIGIN_SECRET, direct /api/app is 404; via the Worker it works and the real client IP is used', opts, async () => {
    const t = await boot({ ORIGIN_SECRET: 'x'.repeat(40) });
    try {
        assert.equal((await t.raw('GET', '/api/app/boot?vc=5')).status, 404);
        assert.equal((await t.raw('GET', '/api/app/boot?vc=5', { headers: { 'X-Origin-Secret': 'wrong' + 'x'.repeat(35) } })).status, 404);
        const ok = await t.raw('GET', '/api/app/boot?vc=5', { headers: { 'X-Origin-Secret': 'x'.repeat(40), 'X-Client-IP': '203.0.113.9' } });
        assert.equal(ok.status, 200); assert.ok(ok.signedOk);
        assert.equal((await t.raw('GET', '/health')).status, 200);                              // /health stays public
    } finally { await t.close(); }
});

test('signer: rejects a non-P-256 key; unsigned mode still works', opts, async () => {
    const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' });
    assert.throws(() => SS.createSigner(rsa), /P-256/);
    assert.equal(SS.createSigner('').enabled, false);
});

// ── v5.1: server → app 8-minute check, FORCE_CLOSE push ──
test('server sweep: dead session / bad key → signed FORCE_CLOSE push to the phone; healthy sessions untouched', opts, async () => {
    const t = await boot();
    try {
        const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
        const signer = SS.createSigner(privateKey.export({ type: 'pkcs8', format: 'pem' }));
        const sessions = SS.createSessions();
        const sent = [], messaging = { send: async m => { sent.push(m); } };
        const FCM = n => `fcm-token-${n}-`.padEnd(40, 'x');
        const mk = async n => {
            const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 });
            const r = await t.raw('POST', '/api/app/login', { body: { key: k.key, hwid: 'dev' + n, vc: 5, fcm: FCM(n) } });
            return { k, sid: r.json.sid };
        };
        const ok = await mk(1), revoked = await mk(2), expired = await mk(3), gone = await mk(4);
        assert.equal(t.db._store.get(`app_sessions/${ok.sid}`).fcmToken, FCM(1));

        let r = await sessions.sweep(t.db, { messaging, signer });                       // everything healthy
        assert.deepEqual([r.checked, r.closed, r.pushed], [4, 0, 0]);

        await S.revokeKeys(t.db, [revoked.k.key], 't');
        t.db._store.set(`app_sessions/${expired.sid}`, { ...t.db._store.get(`app_sessions/${expired.sid}`), expMs: Date.now() - 1000 });
        await S.deleteKeys(t.db, [gone.k.key]);
        r = await sessions.sweep(t.db, { messaging, signer });
        assert.deepEqual([r.checked, r.closed, r.pushed], [4, 3, 3]);
        assert.deepEqual(sent.map(m => m.data.reason).sort(), ['KEY_INVALID', 'KEY_NOT_FOUND', 'SESSION_EXPIRED']);
        for (const m of sent) {                                                          // the app can verify each push with the public key
            assert.equal(m.data.type, 'FORCE_CLOSE'); assert.equal(m.android.priority, 'high');
            assert.ok(crypto.verify('sha256', Buffer.from(`FORCE_CLOSE.${m.data.sid}.${m.data.ts}`), { key: crypto.createPublicKey(privateKey), dsaEncoding: 'der' }, Buffer.from(m.data.sig, 'base64url')));
        }
        assert.equal(t.db._store.get(`app_sessions/${ok.sid}`).live, true);              // healthy one stays live
        r = await sessions.sweep(t.db, { messaging, signer });                           // closed ones are not pushed twice
        assert.deepEqual([r.checked, r.closed, r.pushed], [1, 0, 0]);
    } finally { await t.close(); }
});

test('push-token endpoint stores the Firebase token; restarting on the same device retires the old session quietly', opts, async () => {
    const t = await boot();
    try {
        const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 });
        const l1 = await t.login(k.key), api = t.signed(l1.json.sid, l1.json.secret);
        assert.equal((await api('POST', '/api/app/session/push-token', { fcm: 'bad token!' })).status, 400);
        const ok = await api('POST', '/api/app/session/push-token', { fcm: 'new-fcm-token-'.padEnd(50, 'y') });
        assert.equal(ok.status, 200); assert.equal(t.db._store.get(`app_sessions/${l1.json.sid}`).fcmToken, 'new-fcm-token-'.padEnd(50, 'y'));
        const l2 = await t.login(k.key);                                                 // same hwid = app restart
        assert.equal(t.db._store.get(`app_sessions/${l1.json.sid}`).live, false);        // no push will be sent for it
        assert.equal(t.db._store.get(`app_sessions/${l2.json.sid}`).live, true);
    } finally { await t.close(); }
});
