'use strict';
// HTTP-level tests for /api/app/* and /api/admin/app/* (real Express, fake Firestore).
// Skipped (not failed) when dependencies are not installed — run `npm install && npm test`.
const test = require('node:test');
const assert = require('node:assert/strict');
let createApp; try { ({ createApp } = require('../src/app')); } catch (e) { createApp = null; }
const L = require('../src/lib');
const S = require('../src/service');
const { makeFakeDb } = require('./fakeFirestore');
const opts = { skip: createApp ? false : 'dependencies not installed' };
const PASS = 'test-admin-password-123', CERT = 'ab'.repeat(32);
const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(40, 1)]);

async function boot() {
    const db = makeFakeDb(), sink = { log() {}, warn() {}, error() {} };
    const config = { ADMIN_PASS: PASS, SESSION_SECRET: '', URLKING_API: '', SITE_URL: 'http://x', FRONTEND_URL: 'http://x', ALLOWED_ORIGINS: [], MAX_PAYLOAD: '10kb', TRUST_PROXY: 1, ALLOW_QUERY_TOKEN: false, DISABLE_LEGACY_TOKEN: false };
    const app = createApp({ getDb: () => db, serverTimestamp: () => new Date(), config, log: L.makeLogger(sink), state: { firebase: { status: 'ready' } } });
    const server = await new Promise(r => { const s = app.listen(0, '127.0.0.1', () => r(s)); });
    const base = `http://127.0.0.1:${server.address().port}`;
    const call = async (method, path, { body, headers = {} } = {}) => {
        const res = await fetch(base + path, { method, body: body ? JSON.stringify(body) : undefined, headers: { ...(body ? { 'Content-Type': 'application/json' } : {}), ...headers } });
        const buf = Buffer.from(await res.arrayBuffer()); let json; try { json = JSON.parse(buf.toString()); } catch {}
        return { status: res.status, json, buf, headers: res.headers };
    };
    const lr = await call('POST', '/api/admin/login', { body: { password: PASS } });
    const adm = { Cookie: (lr.headers.get('set-cookie') || '').split(';')[0], 'X-CSRF-Token': lr.json.csrfToken };
    return { db, call, adm, close: () => { app.locals.cleanup(); return new Promise(r => server.close(r)); } };
}

test('full 2-step flow: boot → login → stage2 → assets; key deleted → files refused', opts, async () => {
    const t = await boot();
    try {
        assert.equal((await t.call('PUT', '/api/admin/app/config/stage1', { body: { getKeyUrl: 'https://get.example.com' }, headers: t.adm })).status, 200);
        assert.equal((await t.call('PUT', '/api/admin/app/config/stage2', { body: { overlayName: 'MY MENU', features: { macroE: false } }, headers: t.adm })).status, 200);
        assert.equal((await t.call('POST', '/api/admin/app/assets', { body: { slot: 'login_logo', data: PNG.toString('base64') }, headers: t.adm })).status, 200);
        assert.equal((await t.call('POST', '/api/admin/app/assets', { body: { slot: 'overlay_logo', data: PNG.toString('base64') }, headers: t.adm })).status, 200);

        const b = await t.call('GET', '/api/app/boot?vc=4');
        assert.equal(b.status, 200); assert.equal(b.json.config.getKeyUrl, 'https://get.example.com');
        assert.deepEqual(b.json.assets.map(a => a.slot), ['login_logo']);
        assert.equal((await t.call('GET', '/api/app/asset/login_logo')).status, 200);
        assert.equal((await t.call('GET', '/api/app/asset/overlay_logo')).json.code, 'TOKEN_EXPIRED');          // step-2 file without a token

        const [k] = await S.createKeys(t.db, { siteId: 'site1', count: 1 });
        const bad = await t.call('POST', '/api/app/login', { body: { key: 'SRT_NOPE1234', hwid: 'd1', vc: 4 } });
        assert.equal(bad.status, 403); assert.equal(bad.json.code, 'KEY_NOT_FOUND');
        const ok = await t.call('POST', '/api/app/login', { body: { key: k.key, hwid: 'd1', vc: 4 } });
        assert.equal(ok.status, 200); assert.ok(ok.json.token);
        const auth = { Authorization: `Bearer ${ok.json.token}` };

        const s2 = await t.call('GET', '/api/app/stage2', { headers: auth });
        assert.equal(s2.status, 200); assert.equal(s2.json.config.overlayName, 'MY MENU'); assert.equal(s2.json.config.features.macroE, false);
        assert.deepEqual(s2.json.assets.map(a => a.slot), ['overlay_logo']);
        const f = await t.call('GET', '/api/app/asset/overlay_logo', { headers: auth });
        assert.equal(f.status, 200); assert.ok(f.buf.equals(PNG)); assert.equal(f.headers.get('content-type'), 'image/png');
        assert.equal((await t.call('GET', '/api/app/stage2', { headers: { Authorization: `Bearer ${ok.json.token}x` } })).json.code, 'TOKEN_EXPIRED');

        await S.deleteKeys(t.db, [k.key]);                                              // admin deletes the key → 2nd check refuses
        const gone = await t.call('GET', '/api/app/stage2', { headers: auth });
        assert.equal(gone.status, 403); assert.equal(gone.json.code, 'KEY_NOT_FOUND');
        assert.equal((await t.call('GET', '/api/app/asset/overlay_logo', { headers: auth })).status, 403);
    } finally { await t.close(); }
});

test('patch + maintenance gate answer 423 on every app endpoint; APK modded answers APK_MODDED', opts, async () => {
    const t = await boot();
    try {
        await t.call('PUT', '/api/admin/app/config/gate', { body: { mode: 'patch', title: 'Patched', url: 'https://dl.example.com/a.apk' }, headers: t.adm });
        const g = await t.call('GET', '/api/app/boot?vc=1');
        assert.equal(g.status, 423); assert.equal(g.json.gate.type, 'patch'); assert.equal(g.json.gate.url, 'https://dl.example.com/a.apk');
        assert.equal((await t.call('POST', '/api/app/login', { body: { key: 'SRT_ABCD1234', hwid: 'd', vc: 1 } })).status, 423);
        await t.call('PUT', '/api/admin/app/config/gate', { body: { mode: 'maintenance', minutes: 60 }, headers: t.adm });
        const m = await t.call('GET', '/api/app/boot?vc=1');
        assert.equal(m.status, 423); assert.equal(m.json.gate.type, 'maintenance'); assert.ok(m.json.gate.remainingMs > 59 * 60000);
        await t.call('PUT', '/api/admin/app/config/gate', { body: { mode: 'none' }, headers: t.adm });
        assert.equal((await t.call('GET', '/api/app/boot?vc=1')).status, 200);

        await t.call('PUT', '/api/admin/app/config/security', { body: { enforceCert: true, allowedCertSha256: CERT }, headers: t.adm });
        const mod = await t.call('GET', `/api/app/boot?vc=1&cert=${'cd'.repeat(32)}`);
        assert.equal(mod.status, 403); assert.equal(mod.json.code, 'APK_MODDED');
        assert.equal((await t.call('GET', `/api/app/boot?vc=1&cert=${CERT}`)).status, 200);
    } finally { await t.close(); }
});

test('admin app routes need a session and reject bad input', opts, async () => {
    const t = await boot();
    try {
        assert.equal((await t.call('GET', '/api/admin/app/config')).status, 401);
        assert.equal((await t.call('PUT', '/api/admin/app/config/stage1', { body: { getKeyUrl: 'http://insecure.test' }, headers: t.adm })).status, 400);
        assert.equal((await t.call('POST', '/api/admin/app/assets', { body: { slot: 'login_logo', data: Buffer.from('not an image at all').toString('base64') }, headers: t.adm })).status, 400);
    } finally { await t.close(); }
});
