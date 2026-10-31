'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const AC = require('../src/appctl');
const S = require('../src/service');
const { makeFakeDb } = require('./fakeFirestore');

const PNG = Buffer.concat([Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]), Buffer.alloc(40, 1)]);
const MP3 = Buffer.concat([Buffer.from('ID3'), Buffer.alloc(40, 2)]);
const CERT = 'ab'.repeat(32);
const mk = async db => (await S.createKeys(db, { siteId: 'site1', count: 1, loginLimit: 1 }))[0].key;

test('defaults + section sanitising: https-only URLs, colours, feature flags, cert rules', async () => {
    const db = makeFakeDb();
    let cfg = await AC.saveSection(db, 'stage1', { getKeyUrl: 'https://example.com/get', loginTitle: '  HELLO  ', accent: '#112233' });
    assert.equal(cfg.stage1.getKeyUrl, 'https://example.com/get'); assert.equal(cfg.stage1.loginTitle, 'HELLO'); assert.equal(cfg.rev, 1);
    await assert.rejects(AC.saveSection(db, 'stage1', { getKeyUrl: 'http://evil.test' }), /https/);
    await assert.rejects(AC.saveSection(db, 'stage1', { getKeyUrl: 'javascript:alert(1)' }), /https/);
    await assert.rejects(AC.saveSection(db, 'stage1', { accent: 'red' }), /Colour/);
    cfg = await AC.saveSection(db, 'stage2', { features: { macroE: false } });
    assert.equal(cfg.stage2.features.macroE, false); assert.equal(cfg.stage2.features.macroG, true);
    await assert.rejects(AC.saveSection(db, 'stage2', { features: { 'bad name': true } }), /feature name/);
    await assert.rejects(AC.saveSection(db, 'security', { enforceCert: true }), /at least one/);
    await assert.rejects(AC.saveSection(db, 'security', { allowedCertSha256: ['abc'] }), /64 hex/);
    cfg = await AC.saveSection(db, 'security', { enforceCert: true, allowedCertSha256: CERT.toUpperCase().match(/.{2}/g).join(':') });
    assert.deepEqual(cfg.security.allowedCertSha256, [CERT]);
});

test('gate: patch blocks, maintenance counts down and ends by itself, minVersionCode forces update, notice does not block', async () => {
    const db = makeFakeDb(), t0 = Date.UTC(2026, 9, 31, 12);
    let cfg = await AC.saveSection(db, 'gate', { mode: 'patch', title: 'Patched', message: 'Get new one', url: 'https://dl.example.com/app.apk' }, t0);
    let g = AC.evalGate(cfg, 3, t0);
    assert.equal(g.blocked, true); assert.equal(g.type, 'patch'); assert.equal(g.url, 'https://dl.example.com/app.apk');
    cfg = await AC.saveSection(db, 'gate', { mode: 'maintenance', minutes: 60, message: 'Back soon' }, t0);
    g = AC.evalGate(cfg, 3, t0 + 10 * 60000);
    assert.equal(g.type, 'maintenance'); assert.equal(g.remainingMs, 50 * 60000);
    assert.equal(AC.evalGate(cfg, 3, t0 + 61 * 60000).blocked, false);            // timer over → normal again
    cfg = await AC.saveSection(db, 'gate', { mode: 'none', minVersionCode: 5 }, t0);
    assert.equal(AC.evalGate(cfg, 4, t0).type, 'patch'); assert.equal(AC.evalGate(cfg, 5, t0).blocked, false);
    cfg = await AC.saveSection(db, 'gate', { mode: 'notice', title: 'Hi', message: 'News', minVersionCode: 0 }, t0);
    g = AC.evalGate(cfg, 1, t0); assert.equal(g.blocked, false); assert.equal(g.notice.message, 'News');
});

test('assets: type sniffed from bytes, slot kind enforced, size cap, listing hides bytes', async () => {
    const db = makeFakeDb();
    const r = await AC.putAsset(db, 'overlay_logo', PNG.toString('base64'));
    assert.equal(r.mime, 'image/png'); assert.equal(r.stage, 2); assert.match(r.sha256, /^[0-9a-f]{64}$/);
    await assert.rejects(AC.putAsset(db, 'sound_fail', PNG.toString('base64')), /sound/);
    await assert.rejects(AC.putAsset(db, 'overlay_logo', MP3.toString('base64')), /image/);
    await assert.rejects(AC.putAsset(db, 'nope', PNG.toString('base64')), /Unknown/);
    await assert.rejects(AC.putAsset(db, 'overlay_logo', Buffer.alloc(AC.MAX_ASSET + 1, 7).toString('base64')), /too large/);
    await AC.putAsset(db, 'login_logo', PNG.toString('base64')); await AC.putAsset(db, 'sound_success', MP3.toString('base64'));
    const cfg = await AC.getConfig(db);
    const m1 = await AC.manifest(db, cfg, 1), m2 = await AC.manifest(db, cfg, 2);
    assert.deepEqual(m1.assets.map(a => a.slot), ['login_logo']);
    assert.deepEqual(m2.assets.map(a => a.slot).sort(), ['overlay_logo', 'sound_success']);
    assert.ok(!JSON.stringify(m2).includes('b64'));
    assert.equal((await AC.getAssetFile(db, 'overlay_logo')).buf.equals(PNG), true);
});

test('stage-2 key check: not found / revoked / expired / other device / APK modded — and never consumes a login', async () => {
    const db = makeFakeDb(), key = await mk(db);
    await assert.rejects(AC.peekKey(db, 'SRT_ZZZZZZZZ', 'dev1'), e => e.code === 'KEY_NOT_FOUND');
    await assert.rejects(AC.peekKey(db, key, 'dev1'), e => e.code === 'KEY_INVALID');                 // never logged in → no device bound
    const v = await S.verifyKey(db, key, 'dev1'); assert.equal(v.body.valid, true);
    const before = (await db.collection('keys').doc(key).get()).data().loginCount;
    await AC.peekKey(db, key, 'dev1'); await AC.peekKey(db, key, 'dev1');
    assert.equal((await db.collection('keys').doc(key).get()).data().loginCount, before);
    await assert.rejects(AC.peekKey(db, key, 'dev2'), e => e.code === 'KEY_INVALID');
    await S.revokeKeys(db, [key], 'test');
    await assert.rejects(AC.peekKey(db, key, 'dev1'), e => e.code === 'KEY_INVALID' && /revoked/.test(e.message));
    await S.restoreKeys(db, [key]); await AC.peekKey(db, key, 'dev1');
    await S.deleteKeys(db, [key]);
    await assert.rejects(AC.peekKey(db, key, 'dev1'), e => e.code === 'KEY_NOT_FOUND');
    const off = (await AC.getConfig(db)), on = await AC.saveSection(db, 'security', { enforceCert: true, allowedCertSha256: [CERT] });
    AC.checkCert(off, ''); AC.checkCert(on, CERT);
    assert.throws(() => AC.checkCert(on, 'cd'.repeat(32)), e => e.code === 'APK_MODDED');
    assert.throws(() => AC.checkCert(on, ''), e => e.code === 'APK_MODDED');
});

test('session tokens: bound, expire, tamper-proof, different secret rejected', () => {
    const T = AC.createTokens('secret-A', 1000), now = 1_000_000;
    const { token } = T.issue('SRT_ABCD1234', 'dev1', now);
    assert.equal(T.parse(token, now + 500).k, 'SRT_ABCD1234'); assert.equal(T.parse(token, now + 500).h, 'dev1');
    assert.equal(T.parse(token, now + 1001), null);
    const [b, s] = token.split('.');
    const forged = Buffer.from(JSON.stringify({ ...JSON.parse(Buffer.from(b, 'base64url')), h: 'dev2' })).toString('base64url');
    assert.equal(T.parse(`${forged}.${s}`, now + 1), null);
    assert.equal(AC.createTokens('secret-B', 1000).parse(token, now + 1), null);
    assert.equal(T.parse('garbage'), null); assert.equal(T.parse(token + '.x'), null);
});
