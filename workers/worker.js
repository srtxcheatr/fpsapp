// ═══════════════════════════════════════════════════════════════════════════════
//  SRT X CHEATS — Cloudflare Worker  (edge shield + keep-warm for the key server)
//
//  The APP talks ONLY to this Worker (hard-coded workers.dev / custom domain).
//  The Worker talks to your Render server and proves it with a secret header.
//  Render (with ORIGIN_SECRET set) answers /api/app/* ONLY to this Worker → nobody can
//  bypass the edge rules by calling Render directly, and the Render URL never appears in the app.
//
//  What it does
//   1. Route allow-list      – only the 9 app endpoints pass; everything else = 404 (admin panel is NOT exposed here)
//   2. Method / size checks  – POST body ≤ 10 KB, forwarded byte-for-byte (the app's HMAC covers the exact bytes)
//   3. Edge rate limit       – per client IP, best effort, before Render / Firestore is touched
//   4. Header scrubbing      – only the headers the server needs go forward; only safe headers come back (origin hidden)
//   5. Real client IP        – sent as X-Client-IP so server bans / limits hit the user, not Cloudflare
//   6. Keep-warm cron        – pings /health every 10 min so Render's free plan doesn't fall asleep
//
//  Settings (Cloudflare → Worker → Settings → Variables and Secrets):
//     ORIGIN_URL     (SECRET)  https://your-service.onrender.com          ← no trailing slash. A secret = hidden in the dashboard, never shown again
//     ORIGIN_SECRET  (secret)  same 32+ random chars as Render's ORIGIN_SECRET
//     APP_UA_PREFIX  (text, optional)  e.g. "SRTX/"  → requests whose User-Agent doesn't start with it get 404
//  Trigger → Cron:  */10 * * * *
// ═══════════════════════════════════════════════════════════════════════════════

const MAX_BODY = 10 * 1024;                      // same as the server's MAX_PAYLOAD
const UPSTREAM_TIMEOUT_MS = 28000;               // Render cold start can be slow; the app has its own timeout + retry

// method + path → rule.   session:true = needs Authorization + X-Sig (junk is dropped at the edge)
const ROUTES = [
    { m: 'GET',  re: /^\/api\/app\/boot$/ },
    { m: 'GET',  re: /^\/api\/app\/asset\/[a-z0-9_]{1,40}$/ },
    { m: 'POST', re: /^\/api\/app\/login$/, body: true },
    { m: 'GET',  re: /^\/api\/app\/stage2$/, session: true },
    { m: 'POST', re: /^\/api\/app\/session\/(feature|heartbeat|logout|push-token)$/, body: true, session: true },
];

const PASS_REQ_HEADERS = ['content-type', 'authorization', 'x-ts', 'x-seq', 'x-nonce', 'x-sig', 'x-app-vc', 'x-app-cert', 'if-none-match'];
const PASS_RES_HEADERS = ['content-type', 'content-length', 'etag', 'retry-after', 'x-resp-ts', 'x-resp-sig', 'x-ratelimit-remaining'];

const json = (status, obj, extra = {}) => new Response(JSON.stringify(obj), {
    status, headers: { 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', ...extra },
});
const notFound = () => json(404, { error: 'Not found' });

// ── Edge rate limit (per isolate, per IP). Not a global counter — it stops floods cheaply; Render has the exact limits. ──
const hits = new Map();
function limited(ip, limit = 120, windowMs = 60000) {
    const now = Date.now();
    if (hits.size > 5000) for (const [k, v] of hits) if (now - v.t > windowMs) hits.delete(k);
    const h = hits.get(ip);
    if (!h || now - h.t > windowMs) { hits.set(ip, { t: now, n: 1 }); return false; }
    return ++h.n > limit;
}

async function handle(request, env, ctx) {
    const url = new URL(request.url);

    // Public liveness for uptime monitors — answered by the Worker itself, never reveals the origin.
    if (url.pathname === '/health' && request.method === 'GET') return json(200, { status: 'ok' });

    const rule = ROUTES.find(r => r.m === request.method && r.re.test(url.pathname));
    if (!rule) return notFound();
    if (!env.ORIGIN_URL || !env.ORIGIN_SECRET) return json(500, { error: 'Worker not configured' });

    const ua = request.headers.get('user-agent') || '';
    if (env.APP_UA_PREFIX && !ua.startsWith(env.APP_UA_PREFIX)) return notFound();

    const ip = request.headers.get('cf-connecting-ip') || '';
    if (!ip) return notFound();
    if (limited(ip)) return json(429, { ok: false, code: 'RATE', action: 'NONE', message: 'Too many requests. Wait a minute.' }, { 'retry-after': '60' });

    // Edge pre-filter: a real app always sends these. (Unsigned answer on purpose: the app treats it as "not the real server".)
    if (rule.session) {
        const h = request.headers;
        if (!/^Bearer [A-Za-z0-9_-]{32,64}$/.test(h.get('authorization') || '') || !h.get('x-sig') || !h.get('x-nonce'))
            return json(401, { ok: false, code: 'NO_SESSION', action: 'CRACKED', message: 'Session not found' });
    }

    // Body: read once as bytes (never re-encoded → the app's signature over the exact bytes still matches).
    let body;
    if (rule.body) {
        if (Number(request.headers.get('content-length') || 0) > MAX_BODY) return json(413, { error: 'Too large' });
        body = await request.arrayBuffer();
        if (body.byteLength > MAX_BODY) return json(413, { error: 'Too large' });
    }

    const fwd = new Headers();
    for (const n of PASS_REQ_HEADERS) { const v = request.headers.get(n); if (v) fwd.set(n, v); }
    fwd.set('x-origin-secret', env.ORIGIN_SECRET);
    fwd.set('x-client-ip', ip);
    fwd.set('user-agent', 'srtx-edge/1');

    let up;
    try {
        up = await fetch(env.ORIGIN_URL.replace(/\/+$/, '') + url.pathname + url.search, {
            method: request.method, headers: fwd, body, redirect: 'manual', signal: AbortSignal.timeout(UPSTREAM_TIMEOUT_MS),
        });
    } catch (e) {
        // Origin asleep / down: a transient 502 (the app retries; it never treats this as "cracked")
        return json(502, { ok: false, code: 'UPSTREAM', action: 'NONE', message: 'Server is waking up. Try again.' }, { 'retry-after': '15' });
    }

    const out = new Headers({ 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
    for (const n of PASS_RES_HEADERS) { const v = up.headers.get(n); if (v) out.set(n, v); }
    return new Response(up.status === 204 || up.status === 304 ? null : up.body, { status: up.status, headers: out });
}

export default {
    fetch: (request, env, ctx) => handle(request, env, ctx).catch(() => json(500, { error: 'Edge error' })),

    // Cron keep-warm (Render free plan sleeps after ~15 min without traffic). Set trigger: */10 * * * *
    async scheduled(event, env, ctx) {
        if (!env.ORIGIN_URL) return;
        ctx.waitUntil(fetch(env.ORIGIN_URL.replace(/\/+$/, '') + '/health', { headers: { 'user-agent': 'srtx-edge-warm/1' } }).catch(() => {}));
    },
};
