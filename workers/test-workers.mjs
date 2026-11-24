// Local end-to-end test: real server guard routes (fake Firestore) + the 5 worker modules. No Cloudflare / npm needed.
// Run from project root:  node workers/test-workers.mjs
import crypto from 'node:crypto'; import http from 'node:http'; import Module from 'node:module'; import { createRequire } from 'node:module';
const require = createRequire(import.meta.url);
// Tiny express stand-in so this test runs without `npm install` (the real app uses real Express).
const mkRouter = () => { const st = []; return { st, use: (...f) => st.push({ f }), post: (p, ...f) => st.push({ m: 'POST', p, f }) }; };
const origLoad = Module._load; Module._load = (r, ...a) => r === 'express' ? Object.assign(() => ({}), { Router: mkRouter }) : origLoad(r, ...a);
const { mountGuardRoutes } = require('../src/guardRoutes'), L = require('../src/lib'), S = require('../src/service'), AC = require('../src/appctl');
const { makeFakeDb } = require('../test/fakeFirestore');
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const WS = 'w'.repeat(40), ENV0 = { WORKER_SECRET: WS, SESSION_SECRET: 's'.repeat(40), GUARD_PRIVATE_KEY: privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64') };
const db = makeFakeDb(); let router;
mountGuardRoutes({ use: (p, r) => { router = r; }, get() {} }, { needDb: (req, res, next) => { req.db = db; next(); },
    safe: fn => async (req, res, next) => { try { await fn(req, res, next); } catch (e) { res.status(500).json({ err: String(e) }); } }, adminAuth() {}, recordFail() {}, config: { WORKER_SECRET: WS } });
const srv = http.createServer(async (rq, rs) => {
    let raw = ''; for await (const c of rq) raw += c;
    const req = { method: rq.method, headers: rq.headers, originalUrl: rq.url, body: raw ? JSON.parse(raw) : {} };
    const res = { status(c) { this.code = c; return this; }, json(o) { rs.writeHead(this.code || 200, { 'Content-Type': 'application/json' }); rs.end(JSON.stringify(o)); } };
    const route = router.st.find(x => x.m === 'POST' && '/api/internal/guard' + x.p === rq.url.split('?')[0]);
    const chain = [...router.st.filter(x => !x.m).flatMap(x => x.f), ...(route ? route.f : [])];
    if (!route) { rs.writeHead(404); return rs.end('{}'); }
    let i = 0; const next = () => { const f = chain[i++]; if (f) f(req, res, next); }; next();
}); await new Promise(r => srv.listen(0, '127.0.0.1', r));
const ENV = { ...ENV0, SERVER_URL: `http://127.0.0.1:${srv.address().port}` };
const W = { login: (await import('./login/index.js')).default, launch: (await import('./launch/index.js')).default, menu: (await import('./menu/index.js')).default,
    heartbeat: (await import('./heartbeat/index.js')).default, feature: (await import('./feature/index.js')).default };
const call = async (w, body) => {
    const nonce = crypto.randomBytes(12).toString('base64url');
    const res = await W[w].fetch(new Request('http://w/', { method: 'POST', body: JSON.stringify({ nonce, ...body }) }), ENV, {});
    const j = await res.json(), payload = Buffer.from(j.payload, 'base64');
    const ok = crypto.verify('sha256', payload, publicKey, Buffer.from(j.sig, 'base64'));   // exactly what the Android app does
    const p = JSON.parse(payload.toString()); if (!ok || p.n !== nonce || p.p !== w) throw new Error('BAD SIGNATURE/NONCE/PURPOSE');
    return p;
};
let fails = 0; const t = (name, got, want) => { const ok = got === want; if (!ok) fails++; console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}  → ${got}${ok ? '' : '  (wanted ' + want + ')'}`); };

const [k] = await S.createKeys(db, { duration: 7, loginLimit: 1 });
t('1 login: wrong key → DIALOG_EXIT', (await call('login', { key: 'SRT_NOPE0000', hwid: 'dev1' })).a, 'DIALOG_EXIT');
const lg = await call('login', { key: k.key, hwid: 'dev1' });
t('1 login: good key → ALLOW', lg.a, 'ALLOW'); const tok = lg.t;
t('1 login: same key, other device → denied', (await call('login', { key: k.key, hwid: 'dev2' })).a, 'DIALOG_EXIT');
t('2 launch: no key/session → CRASH', (await call('launch', {})).a, 'CRASH');
t('2 launch: forged token → CRASH', (await call('launch', { token: tok.slice(0, -3) + 'abc' })).a, 'CRASH');
t('2 launch: good token → ALLOW', (await call('launch', { token: tok })).a, 'ALLOW');
t('2 launch: stored key+hwid → ALLOW', (await call('launch', { key: k.key, hwid: 'dev1' })).a, 'ALLOW');
t('3 menu: correct name → ALLOW', (await call('menu', { token: tok, menuName: 'SENSI MACRO' })).a, 'ALLOW');
t('3 menu: wrong name → CRASH', (await call('menu', { token: tok, menuName: 'HACKED MENU' })).a, 'CRASH');
t('3 menu: no session → CRASH', (await call('menu', { menuName: 'SENSI MACRO' })).a, 'CRASH');
t('4 heartbeat: valid → ALLOW', (await call('heartbeat', { token: tok })).a, 'ALLOW');
t('5 feature: valid → ALLOW', (await call('feature', { token: tok, feature: 'macroE' })).a, 'ALLOW');
t('5 feature: no session → DIALOG_EXIT', (await call('feature', { feature: 'macroE' })).a, 'DIALOG_EXIT');
await AC.saveSection(db, 'stage2', { features: { macroG: false } });
t('5 feature: admin-disabled → FEATURE_OFF', (await call('feature', { token: tok, feature: 'macroG' })).a, 'FEATURE_OFF');
await db.collection('keys').doc(k.key).update({ expiresAt: new Date(Date.now() - 1000).toISOString() });
t('4 heartbeat: key expired → CLOSE_MENU_AND_EXIT', (await call('heartbeat', { token: tok })).a, 'CLOSE_MENU_AND_EXIT');
t('3 menu: key expired → CRASH', (await call('menu', { token: tok, menuName: 'SENSI MACRO' })).a, 'CRASH');
await db.collection('keys').doc(k.key).update({ expiresAt: null, status: 'revoked' });
t('5 feature: key revoked/cracked → DIALOG_EXIT', (await call('feature', { token: tok, feature: 'macroE' })).a, 'DIALOG_EXIT');
{ // reinstall scenario through the login worker
    const PH = { name: 'My phone', manufacturer: 'xiaomi', brand: 'redmi', model: 'M2101K6G', device: 'sweet', board: 'sm6150', hardware: 'qcom', fingerprint: 'redmi/sweet:13/TKQ1', kernel: '4.14.186', release: '13' };
    const [k2] = await S.createKeys(db, { duration: 7, loginLimit: 1 });
    t('reinstall: first login saves phone', (await call('login', { key: k2.key, hwid: 'OLD-ID', device: PH })).a, 'ALLOW');
    t('reinstall: new HWID + same phone → ALLOW (auto re-link)', (await call('login', { key: k2.key, hwid: 'NEW-ID', device: PH })).a, 'ALLOW');
    t('reinstall: new HWID + other phone → DIALOG_EXIT', (await call('login', { key: k2.key, hwid: 'EVIL', device: { ...PH, model: 'SM-X', device: 'x', board: 'y', hardware: 'z' } })).a, 'DIALOG_EXIT');
}
t('server rejects unsigned worker call', (await fetch(ENV.SERVER_URL + '/api/internal/guard/state', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' })).status, 401);
srv.close(); console.log(fails ? `\n${fails} FAILED` : '\nALL PASSED'); process.exit(fails ? 1 : 0);
