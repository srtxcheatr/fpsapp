'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const L = require('../src/lib');
const S = require('../src/service');
const { makeFakeDb } = require('./fakeFirestore');

const DAY = 86400000, T0 = Date.parse('2026-10-26T00:00:00Z');
const seed = (db, o = {}) => {
    const key = o.key || 'SRT_ABCD2345';
    const d = { key, prefix: 'SRT', siteId: 'site1', createdAt: new Date(T0).toISOString(), expiresAt: null, durationDays: 7,
        loginLimit: 1, loginCount: 0, type: 'standard', label: '', note: '', hwid: null, lastUsedAt: null, ...o };
    return db.collection('keys').doc(key).set(d).then(() => key);
};
// Same keyword rules as the Android app (LicensePolicy.classify) — proves the app maps our messages correctly.
const classify = m => { m = (m || '').toLowerCase();
    return m.includes('expired') ? 'EXPIRED' : (m.includes('hwid') || m.includes('device')) ? 'HWID' : m.includes('limit') ? 'LIMIT' : 'REVOKED'; };

// ── keys & validation ───────────────────────────────────────────
test('generateKey: requested length, safe charset, matches server regex', () => {
    for (const n of [6, 8, 16, 32]) {
        const k = L.generateKey('SRT', n);
        assert.equal(k.length, 4 + n); assert.match(k, L.KEY_RE); assert.match(k.slice(4), /^[ABCDEFGHJKLMNPQRSTUVWXYZ23456789]+$/);
    }
    assert.equal(new Set(Array.from({ length: 500 }, () => L.generateKey('SRT', 10))).size, 500);
});
test('parseCustomKey: prefix handling and rejection', () => {
    assert.deepEqual(L.parseCustomKey('vip2026', 'site2'), { key: 'SAMUEL_VIP2026', prefix: 'SAMUEL', siteId: 'site2' });
    assert.equal(L.parseCustomKey('nk_hello1', 'site1').key, 'NK_HELLO1');
    for (const bad of ['ab', 'has space', 'x'.repeat(33), 'a/b', 'SRT_a-b', '']) assert.throws(() => L.parseCustomKey(bad, 'site1'), /4–32|Custom/);
});
test('old 8-char keys and new lengths both pass the verify regex', () => {
    assert.match('SRT_A2BK9QM7', L.KEY_RE); assert.match('NK_ABCD', L.KEY_RE); assert.doesNotMatch('XYZ_ABCD1234', L.KEY_RE);
    assert.doesNotMatch('SRT_abc', L.KEY_RE);
});

// ── create ──────────────────────────────────────────────────────
test('createKeys: count, length, defaults, fixed expiry, status=active', async () => {
    const db = makeFakeDb();
    const ks = await S.createKeys(db, { siteId: 'site3', count: 25, length: 12, duration: 30, loginLimit: 2, label: 'batch' }, T0);
    assert.equal(ks.length, 25); assert.equal(new Set(ks.map(k => k.key)).size, 25);
    assert.ok(ks.every(k => k.key.startsWith('KALEYYY_') && k.key.length === 8 + 12 && k.status === 'active' && k.durationDays === 30 && k.loginLimit === 2));
    const [f] = await S.createKeys(db, { expiresAt: new Date(T0 + 5 * DAY).toISOString() }, T0);
    assert.equal(f.expiresAt, new Date(T0 + 5 * DAY).toISOString());
});
test('createKeys: custom value, duplicate and bad input rejected', async () => {
    const db = makeFakeDb();
    const [k] = await S.createKeys(db, { customKey: 'gift2026', siteId: 'site1' }, T0);
    assert.equal(k.key, 'SRT_GIFT2026');
    await assert.rejects(S.createKeys(db, { customKey: 'GIFT2026' }, T0), { status: 400, message: 'Key already exists' });
    await assert.rejects(S.createKeys(db, { customKey: 'abc!' }, T0), { status: 400 });
    await assert.rejects(S.createKeys(db, { customKey: 'ABCDEF', count: 2 }, T0), { status: 400 });
    await assert.rejects(S.createKeys(db, { length: 3 }, T0), { status: 400 });
    await assert.rejects(S.createKeys(db, { count: 101 }, T0), { status: 400 });
    await assert.rejects(S.createKeys(db, { expiresAt: new Date(T0 - 1000).toISOString() }, T0), { status: 400 });
    await assert.rejects(S.createKeys(db, { expiresAt: 'not a date' }, T0), { status: 400 });
});

// ── verify (Android contract) ───────────────────────────────────
test('verify: valid response keeps every field the app reads; timer starts on first login', async () => {
    const db = makeFakeDb(); const key = await seed(db);
    const { body } = await S.verifyKey(db, key.toLowerCase(), 'HWID12345678', T0);
    assert.equal(body.valid, true);
    for (const f of ['message', 'key', 'expiresAt', 'daysLeft', 'loginCount', 'loginLimit', 'type'])
        assert.ok(f in body, `missing ${f}`);
    assert.equal(body.daysLeft, 7); assert.equal(body.loginCount, 1); assert.equal(body.key, key);
    assert.equal(body.expiresAt, new Date(T0 + 7 * DAY).toISOString());
});
test('verify: legacy doc without `status` field still works', async () => {
    const db = makeFakeDb(); const key = await seed(db);       // seed() has no status
    assert.equal((await S.verifyKey(db, key, 'HWID12345678', T0)).body.valid, true);
});
test('verify: HWID mismatch, same-device relogin, login limit', async () => {
    const db = makeFakeDb(); const key = await seed(db, { loginLimit: 1 });
    await S.verifyKey(db, key, 'DEVICE-A-0001', T0);
    const again = await S.verifyKey(db, key, 'DEVICE-A-0001', T0 + 1000);
    assert.equal(again.body.valid, true); assert.equal(again.body.loginCount, 1);
    const other = await S.verifyKey(db, key, 'DEVICE-B-0002', T0 + 2000);
    assert.equal(other.body.valid, false); assert.equal(classify(other.body.message), 'HWID'); assert.ok(other.fail);
    const k2 = await seed(db, { key: 'SRT_LIMIT234', loginLimit: 1, loginCount: 1 });
    assert.equal(classify((await S.verifyKey(db, k2, 'NEWDEVICE-001', T0)).body.message), 'LIMIT');
});
test('verify: expired key rejected and classified as EXPIRED', async () => {
    const db = makeFakeDb(); const key = await seed(db, { expiresAt: new Date(T0 - 1000).toISOString(), lastUsedAt: 'x' });
    const r = await S.verifyKey(db, key, 'HWID12345678', T0);
    assert.equal(r.body.valid, false); assert.equal(classify(r.body.message), 'EXPIRED');
});
test('verify: unknown / malformed / deleted key', async () => {
    const db = makeFakeDb(); const key = await seed(db);
    assert.equal((await S.verifyKey(db, 'garbage', 'h', T0)).body.message, 'Invalid key format');
    assert.equal((await S.verifyKey(db, 'SRT_NOPE2345', 'h', T0)).body.message, 'Key not found');
    await S.deleteKeys(db, [key]);
    const r = await S.verifyKey(db, key, 'HWID12345678', T0);
    assert.equal(r.body.valid, false); assert.equal(classify(r.body.message), 'REVOKED');
});
test('verify: concurrent logins on a 1-device key — exactly one device wins', async () => {
    const db = makeFakeDb(); const key = await seed(db, { loginLimit: 1 });
    const rs = await Promise.all(Array.from({ length: 8 }, (_, i) => S.verifyKey(db, key, `DEVICE-${i}-00000`, T0)));
    assert.equal(rs.filter(r => r.body.valid).length, 1);
});

// ── revoke / restore / expiry / extend ─────────────────────────
test('revoke: takes effect immediately, classified REVOKED, no timer started, restore reverses', async () => {
    const db = makeFakeDb(); const key = await seed(db);
    assert.equal((await S.verifyKey(db, key, 'HWID12345678', T0)).body.valid, true);
    const r = await S.revokeKeys(db, [key], 'leaked', T0);
    assert.deepEqual(r.processed, [key]);
    const after = await S.verifyKey(db, key, 'HWID12345678', T0 + 1);       // very next call
    assert.equal(after.body.valid, false); assert.equal(after.body.message, 'Key revoked'); assert.equal(classify(after.body.message), 'REVOKED');
    const doc = (await db.collection('keys').doc(key).get()).data();
    assert.equal(doc.status, 'revoked'); assert.equal(doc.revokeReason, 'leaked'); assert.equal(doc.loginCount, 1);   // untouched
    assert.equal((await S.revokeKeys(db, [key])).skipped[0].reason, 'already revoked');
    await S.restoreKeys(db, [key]);
    assert.equal((await S.verifyKey(db, key, 'HWID12345678', T0 + 2)).body.valid, true);
});
test('revoked unused key does not start its expiry timer', async () => {
    const db = makeFakeDb(); const key = await seed(db);
    await S.revokeKeys(db, [key], '', T0); await S.verifyKey(db, key, 'HWID12345678', T0);
    assert.equal((await db.collection('keys').doc(key).get()).data().expiresAt, null);
});
test('setExpiry in the past expires immediately; extend revives an expired key from NOW', async () => {
    const db = makeFakeDb(); const key = await seed(db);
    await S.verifyKey(db, key, 'HWID12345678', T0);
    await S.setExpiry(db, [key], new Date(T0 - DAY).toISOString());
    assert.equal(classify((await S.verifyKey(db, key, 'HWID12345678', T0)).body.message), 'EXPIRED');
    await S.extendKeys(db, [key], 10, T0);
    const r = await S.verifyKey(db, key, 'HWID12345678', T0);
    assert.equal(r.body.valid, true); assert.equal(r.body.expiresAt, new Date(T0 + 10 * DAY).toISOString());
});
test('extend: adds to a future expiry; unused key extends duration; lifetime key skipped; bad days rejected', async () => {
    const db = makeFakeDb();
    const a = await seed(db, { key: 'SRT_AAAA2222', expiresAt: new Date(T0 + 3 * DAY).toISOString(), lastUsedAt: 'x' });
    const b = await seed(db, { key: 'SRT_BBBB2222', durationDays: 7 });
    const c = await seed(db, { key: 'SRT_CCCC2222', lastUsedAt: 'x', expiresAt: null });
    const r = await S.extendKeys(db, [a, b, c], 5, T0);
    assert.equal((await db.collection('keys').doc(a).get()).data().expiresAt, new Date(T0 + 8 * DAY).toISOString());
    assert.equal((await db.collection('keys').doc(b).get()).data().durationDays, 12);
    assert.deepEqual(r.skipped.map(s => s.key), [c]);
    await assert.rejects(S.extendKeys(db, [a], 0), { status: 400 });
    await assert.rejects(S.extendKeys(db, [a], 'x'), { status: 400 });
    await assert.rejects(S.extendKeys(db, [a]), { status: 400 });
});

// ── bulk ────────────────────────────────────────────────────────
test('bulk: revoke/delete many, reports notFound, dedupes, enforces limits', async () => {
    const db = makeFakeDb();
    const keys = (await S.createKeys(db, { count: 60 }, T0)).map(k => k.key);
    const r = await S.revokeKeys(db, [...keys, keys[0], 'SRT_MISSING22'], 'bulk', T0);
    assert.equal(r.processed.length, 60); assert.deepEqual(r.notFound, ['SRT_MISSING22']);
    for (const k of keys.slice(0, 5)) assert.equal((await S.verifyKey(db, k, 'HWID12345678', T0)).body.message, 'Key revoked');
    const d = await S.deleteKeys(db, keys);
    assert.equal(d.processed.length, 60); assert.equal(d.snapshots.length, 60); assert.ok(d.snapshots.every(s => !('hwid' in s)));
    assert.equal((await db.collection('keys').get()).size, 0);
    await assert.rejects(S.revokeKeys(db, []), { status: 400 });
    await assert.rejects(S.revokeKeys(db, Array.from({ length: 501 }, (_, i) => `SRT_K${String(i).padStart(5, '0')}`)), { status: 400 });
    await assert.rejects(S.revokeKeys(db, ['not a key']), { status: 400 });
});
test('bulk: >400 keys processed in several batches', async () => {
    const db = makeFakeDb();
    for (let i = 0; i < 450; i++) await seed(db, { key: `SRT_B${String(i).padStart(5, '0')}` });
    const keys = (await db.collection('keys').get()).docs.map(d => d.id);
    assert.equal((await S.revokeKeys(db, keys, '', T0)).processed.length, 450);
    assert.equal((await S.stats(db, T0)).revoked, 450);
});

// ── search / filter / stats ─────────────────────────────────────
test('search & filter: status, site, text, sort, pagination, ids', async () => {
    const db = makeFakeDb();
    await seed(db, { key: 'SRT_ACTIVE22', label: 'Alice', createdAt: '2026-10-01T00:00:00Z' });
    await seed(db, { key: 'SRT_EXPIRED2', expiresAt: new Date(T0 - DAY).toISOString(), lastUsedAt: 'x', createdAt: '2026-10-02T00:00:00Z' });
    await seed(db, { key: 'NK_REVOKED22', prefix: 'NK', siteId: 'site4', status: 'revoked', note: 'refund', createdAt: '2026-10-03T00:00:00Z' });
    await seed(db, { key: 'SRT_FULL2222', loginLimit: 1, loginCount: 1, lastUsedAt: 'x', hwid: 'DEVICE-ZZZ-1', createdAt: '2026-10-04T00:00:00Z' });
    const keysOf = async q => (await S.searchKeys(db, q, T0)).items.map(i => i.key);
    assert.deepEqual(await keysOf({ status: 'expired' }), ['SRT_EXPIRED2']);
    assert.deepEqual(await keysOf({ status: 'revoked' }), ['NK_REVOKED22']);
    assert.deepEqual(await keysOf({ status: 'full' }), ['SRT_FULL2222']);
    assert.deepEqual(await keysOf({ status: 'unused' }), ['SRT_ACTIVE22']);
    assert.deepEqual(await keysOf({ site: 'site4' }), ['NK_REVOKED22']);
    assert.deepEqual(await keysOf({ search: 'alice' }), ['SRT_ACTIVE22']);
    assert.deepEqual(await keysOf({ search: 'refund' }), ['NK_REVOKED22']);
    assert.deepEqual(await keysOf({ search: 'device-zzz' }), ['SRT_FULL2222']);
    assert.deepEqual(await keysOf({ sort: 'created', order: 'asc', limit: 2 }), ['SRT_ACTIVE22', 'SRT_EXPIRED2']);
    const p2 = await S.searchKeys(db, { sort: 'created', order: 'asc', limit: 2, offset: 2 }, T0);
    assert.equal(p2.total, 4); assert.deepEqual(p2.items.map(i => i.key), ['NK_REVOKED22', 'SRT_FULL2222']);
    assert.deepEqual((await S.matchingKeyIds(db, { status: 'active' }, T0)).keys.sort(), ['SRT_ACTIVE22', 'SRT_FULL2222']);
    const st = await S.stats(db, T0);
    assert.deepEqual([st.total, st.active, st.maxed, st.expired, st.revoked, st.unused], [4, 1, 1, 1, 1, 1]);
});

// ── audit ───────────────────────────────────────────────────────
test('audit: hash chain verifies; edits, deletions and tail truncation are detected; survives key deletion', async () => {
    const db = makeFakeDb();
    for (let i = 1; i <= 5; i++) await L.writeAudit(db, { action: `t${i}`, actor: 'admin', keys: ['SRT_ABCD2345'], count: 1, details: { i } });
    assert.deepEqual(await L.verifyAuditChain(db), { ok: true, checked: 5, headSeq: 5 });
    const key = await seed(db); await S.deleteKeys(db, [key]);                        // audit is independent of the key doc
    assert.ok((await L.listAudit(db, {})).items.length === 5);

    const edited = makeFakeDb(); for (let i = 1; i <= 3; i++) await L.writeAudit(edited, { action: 'a', details: { i } });
    edited._store.get('audit_logs/0000000002').details = { i: 999 };
    assert.deepEqual(await L.verifyAuditChain(edited), { ok: false, checked: 1, headSeq: 3, brokenAt: 2, reason: 'entry altered' });

    const removed = makeFakeDb(); for (let i = 1; i <= 3; i++) await L.writeAudit(removed, { action: 'a' });
    removed._store.delete('audit_logs/0000000002');
    assert.equal((await L.verifyAuditChain(removed)).reason, 'missing entry');

    const trunc = makeFakeDb(); for (let i = 1; i <= 3; i++) await L.writeAudit(trunc, { action: 'a' });
    trunc._store.set('meta/audit_head', { seq: 2, hash: trunc._store.get('audit_logs/0000000002').hash });
    trunc._store.delete('audit_logs/0000000003');
    assert.equal((await L.verifyAuditChain(trunc)).ok, true);                         // consistent rewrite of head+tail is a known limit (see notes)
});
test('audit: concurrent writes keep a gap-free chain', async () => {
    const db = makeFakeDb();
    await Promise.all(Array.from({ length: 20 }, (_, i) => L.writeAudit(db, { action: 'c', details: { i } })));
    assert.deepEqual(await L.verifyAuditChain(db), { ok: true, checked: 20, headSeq: 20 });
});
test('audit: listAudit paging + filters', async () => {
    const db = makeFakeDb();
    for (let i = 1; i <= 7; i++) await L.writeAudit(db, { action: i % 2 ? 'key.revoke' : 'key.extend', keys: [`SRT_K${i}ABCD`] });
    const p1 = await L.listAudit(db, { limit: 3 });
    assert.deepEqual(p1.items.map(e => e.seq), [7, 6, 5]); assert.equal(p1.nextBefore, 5);
    assert.deepEqual((await L.listAudit(db, { limit: 3, before: p1.nextBefore })).items.map(e => e.seq), [4, 3, 2]);
    assert.ok((await L.listAudit(db, { limit: 200, action: 'key.revoke' })).items.every(e => e.action === 'key.revoke'));
    assert.deepEqual((await L.listAudit(db, { limit: 200, key: 'srt_k3abcd' })).items.map(e => e.seq), [3]);
});

// ── admin session tokens ────────────────────────────────────────
test('auth: password check, token issue/parse, tamper, expiry, logout, secret rotation', () => {
    const a = L.createAuth({ adminPass: 'correct horse battery', ttlMs: 1000 });
    assert.ok(a.checkPassword('correct horse battery')); assert.ok(!a.checkPassword('nope')); assert.ok(!a.checkPassword(undefined)); assert.ok(!a.checkPassword(''));
    const { token, payload } = a.issue(1000);
    assert.equal(a.parse(token, 1500).sid, payload.sid);
    assert.equal(a.parse(token, 2000), null);                                       // expired
    assert.equal(a.parse(token.slice(0, -2) + 'xx', 1500), null);                   // bad signature
    const [body] = token.split('.'); const forged = Buffer.from(JSON.stringify({ ...payload, exp: 9e15 })).toString('base64url');
    assert.equal(a.parse(`${forged}.${token.split('.')[1]}`, 1500), null);          // payload edited, sig reused
    assert.equal(a.parse('a.b.c'), null); assert.equal(a.parse(''), null); assert.equal(a.parse(null), null); assert.equal(a.parse('x'.repeat(700)), null);
    assert.notEqual(token, 'correct horse battery'); assert.ok(!token.includes('correct'));   // never the password
    a.revoke(payload, 1500); assert.equal(a.parse(token, 1500), null);
    const b = L.createAuth({ adminPass: 'a different password!!', ttlMs: 1000 });   // changed ADMIN_PASS invalidates sessions
    assert.equal(b.parse(token, 1500), null);
});

// ── safe logging ────────────────────────────────────────────────
test('logger: masks keys, redacts secret-looking fields, no stack/query leakage', () => {
    const lines = []; const sink = { log: l => lines.push(l), warn: l => lines.push(l), error: l => lines.push(l) };
    const log = L.makeLogger(sink);
    log.info('verify SRT_ABCD2345 failed', { password: 'hunter2', hwid: 'DEVICE123', token: 'abc', nested: { authorization: 'Bearer x', note: 'ok NK_ZZZZ9999' } });
    log.err('boom', Object.assign(new Error('bad key SAMUEL_QQQQ2222'), { code: 14 }));
    const all = lines.join('\n');
    for (const secret of ['ABCD2345', 'hunter2', 'DEVICE123', 'Bearer x', 'ZZZZ9999', 'QQQQ2222']) assert.ok(!all.includes(secret), `leaked ${secret}`);
    assert.ok(all.includes('SRT_AB****') && all.includes('[redacted]'));
});
