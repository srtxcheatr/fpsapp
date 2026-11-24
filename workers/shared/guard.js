// ═══ Shared guard library for all 5 Cloudflare Workers (bundled by wrangler) ═══
// Every response is a SIGNED verdict: { payload: base64(JSON), sig: base64(RSA-SHA256) }.
// The Android app embeds the PUBLIC key, so a fake server / hosts-file redirect / proxy cannot forge "ALLOW".
// Verdict actions the app must obey:
//   ALLOW               keep going
//   CRASH               force-crash the app immediately
//   CLOSE_MENU_AND_EXIT close floating menu, then close the app
//   DIALOG_EXIT         show dialog with the message and ONE button: [ Exit app ]
//   FEATURE_OFF         feature disabled by admin (toast only)
//   RETRY               server unreachable (app applies its short offline grace, then locks)

const enc = new TextEncoder(), dec = new TextDecoder();
const b64 = buf => btoa(String.fromCharCode(...new Uint8Array(buf)));
const b64u = buf => b64(buf).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const fromB64 = s => Uint8Array.from(atob(s), c => c.charCodeAt(0));
const fromB64u = s => fromB64(s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4));
const hex = buf => [...new Uint8Array(buf)].map(x => x.toString(16).padStart(2, '0')).join('');

export const SESSION_TTL_MS = 10 * 60 * 1000;

// ── HMAC helpers ──
async function hmacKey(secret) { return crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign', 'verify']); }
async function hmacHex(secret, msg) { return hex(await crypto.subtle.sign('HMAC', await hmacKey(secret), enc.encode(msg))); }
async function sha256Hex(s) { return hex(await crypto.subtle.digest('SHA-256', enc.encode(s))); }

// ── Session token (shared by all workers through SESSION_SECRET) ──
export async function issueToken(env, key, hwid, now = Date.now()) {
    const body = b64u(enc.encode(JSON.stringify({ k: key, h: hwid, iat: now, exp: now + SESSION_TTL_MS })));
    const sig = b64u(await crypto.subtle.sign('HMAC', await hmacKey(env.SESSION_SECRET), enc.encode('wsess.' + body)));
    return { token: `${body}.${sig}`, exp: now + SESSION_TTL_MS };
}
export async function parseToken(env, token, now = Date.now()) {
    if (typeof token !== 'string' || token.length > 600) return null;
    const [body, sig, extra] = token.split('.');
    if (!body || !sig || extra !== undefined) return null;
    let ok = false;
    try { ok = await crypto.subtle.verify('HMAC', await hmacKey(env.SESSION_SECRET), fromB64u(sig), enc.encode('wsess.' + body)); } catch { return null; }
    if (!ok) return null;
    try { const p = JSON.parse(dec.decode(fromB64u(body))); return p && p.exp > now ? p : null; } catch { return null; }
}

// ── Call the Render server (HMAC-authenticated, 8 s timeout) ──
export async function callServer(env, path, body) {
    const json = JSON.stringify(body), ts = String(Date.now());
    const nonce = b64u(crypto.getRandomValues(new Uint8Array(12)));
    const sig = await hmacHex(env.WORKER_SECRET, `${ts}.${nonce}.POST.${path}.${await sha256Hex(json)}`);
    const ac = new AbortController(), timer = setTimeout(() => ac.abort(), 8000);
    try {
        const res = await fetch(env.SERVER_URL.replace(/\/+$/, '') + path, { method: 'POST', signal: ac.signal,
            headers: { 'Content-Type': 'application/json', 'X-Guard-Auth': `${ts}.${nonce}.${sig}` }, body: json });
        if (res.status >= 500 || res.status === 429 || res.status === 401) throw new Error('server ' + res.status);
        return await res.json();
    } finally { clearTimeout(timer); }
}

// ── Signed verdict ──
let _priv; async function privKey(env) {
    if (!_priv) _priv = await crypto.subtle.importKey('pkcs8', fromB64(env.GUARD_PRIVATE_KEY.replace(/\s+/g, '')), { name: 'RSASSA-PKCS1-v1_5', hash: 'SHA-256' }, false, ['sign']);
    return _priv;
}
export async function verdict(env, purpose, nonce, v, status = 200) {
    const payload = JSON.stringify({ p: purpose, n: nonce, ts: Date.now(), a: v.action, c: v.code || 'OK', m: v.message || '', t: v.token || null, x: v.exp || null, e: v.expiresAt || null });
    const sig = await crypto.subtle.sign('RSASSA-PKCS1-v1_5', await privKey(env), enc.encode(payload));
    return new Response(JSON.stringify({ payload: b64(enc.encode(payload)), sig: b64(sig) }), { status,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff' } });
}

// ── Default user-facing messages per denial code ──
export const MESSAGES = {
    NO_SESSION: 'Login session not found. Please log in again.',
    KEY_NOT_FOUND: 'Key not found. Login was not valid.',
    KEY_EXPIRED: 'Your key has expired.',
    KEY_REVOKED: 'Your key was revoked.',
    KEY_DEVICE: 'This key is not bound to this device.',
    APK_MODDED: 'This APK is modified or not the official build.',
    MENU_TAMPERED: 'Menu name mismatch.',
    GATE: 'App is under maintenance or needs an update.',
    BAD_REQUEST: 'Bad request.',
};

// ── Wrapper: parses request, validates nonce, runs handler, ALWAYS answers with a signed verdict ──
// opts.denyAction = what this worker does on any denial (CRASH / CLOSE_MENU_AND_EXIT / DIALOG_EXIT)
export function guardWorker(purpose, denyAction, handler) {
    return {
        async fetch(request, env, ctx) {
            if (request.method !== 'POST') return new Response('Not found', { status: 404 });
            let body; try { const t = await request.text(); if (t.length > 4096) throw 0; body = JSON.parse(t); } catch { return new Response('Bad request', { status: 400 }); }
            const nonce = String(body.nonce || '');
            if (!/^[A-Za-z0-9_-]{8,64}$/.test(nonce)) return new Response('Bad request', { status: 400 });
            const deny = (code, message) => verdict(env, purpose, nonce, { action: denyAction, code, message: message || MESSAGES[code] || 'Access denied' });
            try {
                const c = { env, body, nonce, deny, request,
                    ip: request.headers.get('CF-Connecting-IP') || '', country: (request.cf && request.cf.country) || '',
                    allow: extra => verdict(env, purpose, nonce, { action: 'ALLOW', ...extra }),
                    // maps a server /state or /login reply to deny-or-undefined
                    fromServer: st => st && st.ok ? null : deny(st && st.code ? st.code : 'KEY_NOT_FOUND', st && st.message),
                };
                return await handler(c);
            } catch (e) {
                // Server unreachable / worker error: NOT proof of tampering → tell the app to use its offline grace.
                return verdict(env, purpose, nonce, { action: 'RETRY', code: 'UNAVAILABLE', message: 'Server unreachable' });
            }
        },
    };
}

// Requires a valid worker session token, then re-checks the key live in the database.
// Returns { deny } (a Response) or { session, state }.
export async function requireSession(c) {
    const p = await parseToken(c.env, c.body.token);
    if (!p) return { deny: await c.deny('NO_SESSION') };
    const st = await callServer(c.env, '/api/internal/guard/state', { key: p.k, hwid: p.h, vc: c.body.vc, cert: c.body.cert, feature: c.body.feature });
    const d = c.fromServer(st); if (d) return { deny: await d };
    return { session: p, state: st };
}
