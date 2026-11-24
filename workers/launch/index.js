// WORKER 2 — APP-OPEN CHECK
// Runs every time the app opens (before any UI). {nonce, token?, key?, hwid?, vc, cert}
// No key / no session / cracked login  → CRASH.  Valid → ALLOW + fresh session token.
import { guardWorker, parseToken, callServer, issueToken } from '../shared/guard.js';

export default guardWorker('launch', 'CRASH', async c => {
    const { token, key, hwid, vc, cert } = c.body;
    const p = await parseToken(c.env, token);
    const k = p ? p.k : key, h = p ? p.h : hwid;            // returning user: stored key+hwid is accepted, token optional
    if (typeof k !== 'string' || typeof h !== 'string' || !k || !h) return c.deny('NO_SESSION');
    const st = await callServer(c.env, '/api/internal/guard/state', { key: k, hwid: h, vc, cert });
    const d = c.fromServer(st); if (d) return d;
    const t = await issueToken(c.env, st.key, h.trim().slice(0, 128));
    return c.allow({ token: t.token, exp: t.exp, expiresAt: st.expiresAt });
});
