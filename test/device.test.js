'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const S = require('../src/service');
const D = require('../src/device');
const { makeFakeDb } = require('./fakeFirestore');

const PHONE = { name: "Sam's phone", manufacturer: 'samsung', brand: 'samsung', model: 'SM-A546E', device: 'a54x', board: 'exynos1380', hardware: 'exynos1380',
    buildId: 'UP1A.231005.007', fingerprint: 'samsung/a54xnsxx/a54x:14/UP1A/A546EXXU:user/release-keys', kernel: '5.15.123-android13', release: '14', sdk: '34' };

async function setup() { const db = makeFakeDb(); const [k] = await S.createKeys(db, { duration: 7, loginLimit: 1 }); return { db, key: k.key }; }

test('device profile is saved on first login', async () => {
    const { db, key } = await setup();
    assert.equal((await S.verifyKey(db, key, 'HW1', Date.now(), { device: PHONE })).body.valid, true);
    const kd = (await db.collection('keys').doc(key).get()).data();
    assert.equal(kd.device.model, 'SM-A546E'); assert.equal(kd.device.kernel, '5.15.123-android13'); assert.equal(kd.hwid, 'HW1');
});
test('reinstall (new HWID, same phone) is re-linked automatically, no login slot used', async () => {
    const { db, key } = await setup();
    await S.verifyKey(db, key, 'HW1', Date.now(), { device: PHONE });
    const r = await S.verifyKey(db, key, 'HW2', Date.now(), { device: PHONE });
    assert.equal(r.body.valid, true);
    const kd = (await db.collection('keys').doc(key).get()).data();
    assert.equal(kd.hwid, 'HW2'); assert.equal(kd.rebindCount, 1); assert.equal(kd.loginCount, 1); assert.equal(kd.hwidHistory[0].hwid, 'HW1');
    assert.equal((await S.verifyKey(db, key, 'HW1', Date.now(), { device: PHONE })).body.valid, true);   // old HWID can come back only via another rebind
});
test('different phone model → still blocked', async () => {
    const { db, key } = await setup();
    await S.verifyKey(db, key, 'HW1', Date.now(), { device: PHONE });
    const r = await S.verifyKey(db, key, 'HW9', Date.now(), { device: { ...PHONE, model: 'Pixel 8', device: 'shiba', board: 'shusky', hardware: 'zuma' } });
    assert.equal(r.body.valid, false); assert.match(r.body.message, /HWID mismatch/);
});
test('same model but different build+kernel+name → blocked', async () => {
    const { db, key } = await setup();
    await S.verifyKey(db, key, 'HW1', Date.now(), { device: PHONE });
    const other = { ...PHONE, name: 'Friend', fingerprint: 'x/y', kernel: '4.19.1', release: '13' };
    assert.equal((await S.verifyKey(db, key, 'HW5', Date.now(), { device: other })).body.valid, false);
});
test('no device info sent → old behaviour (blocked)', async () => {
    const { db, key } = await setup();
    await S.verifyKey(db, key, 'HW1', Date.now(), { device: PHONE });
    assert.equal((await S.verifyKey(db, key, 'HW2')).body.valid, false);
});
test('rebind limit and AUTO_REBIND_MAX=0', async () => {
    const { db, key } = await setup();
    await S.verifyKey(db, key, 'H0', Date.now(), { device: PHONE, rebindMax: 2 });
    assert.equal((await S.verifyKey(db, key, 'H1', Date.now(), { device: PHONE, rebindMax: 2 })).body.valid, true);
    assert.equal((await S.verifyKey(db, key, 'H2', Date.now(), { device: PHONE, rebindMax: 2 })).body.valid, true);
    assert.equal((await S.verifyKey(db, key, 'H3', Date.now(), { device: PHONE, rebindMax: 2 })).body.valid, false);
    const b = await setup(); await S.verifyKey(b.db, b.key, 'A', Date.now(), { device: PHONE });
    assert.equal((await S.verifyKey(b.db, b.key, 'B', Date.now(), { device: PHONE, rebindMax: 0 })).body.valid, false);
});
test('admin reset clears device + counter; sanitizeDevice whitelists/caps', async () => {
    const { db, key } = await setup();
    await S.verifyKey(db, key, 'HW1', Date.now(), { device: PHONE }); await S.verifyKey(db, key, 'HW2', Date.now(), { device: PHONE });
    await S.resetDeviceAdmin(db, key);
    const kd = (await db.collection('keys').doc(key).get()).data();
    assert.equal(kd.hwid, null); assert.equal(kd.device, null); assert.equal(kd.rebindCount, 0);
    const d = D.sanitizeDevice({ model: 'x'.repeat(500), evil: '<script>', kernel: 'a\u0000b' });
    assert.equal(d.model.length, 60); assert.equal(d.evil, undefined); assert.equal(d.kernel, 'ab');
    assert.equal(D.sanitizeDevice('nope'), null);
});
