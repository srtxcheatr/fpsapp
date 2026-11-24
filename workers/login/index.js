// WORKER 1 — LOGIN ACTIVITY / KEY CHECK
// App sends {nonce, key, hwid, vc, cert}. Consumes a login slot, binds HWID, logs activity,
// and returns a signed ALLOW + 10-minute session token. Any failure = DIALOG_EXIT-style denial shown on the login page.
import { guardWorker, callServer, issueToken } from '../shared/guard.js';

export default guardWorker('login', 'DIALOG_EXIT', async c => {
    const { key, hwid, vc, cert, device } = c.body;
    if (typeof key !== 'string' || typeof hwid !== 'string' || !key || !hwid) return c.deny('KEY_NOT_FOUND');
    const r = await callServer(c.env, '/api/internal/guard/login', { key, hwid, vc, cert, device, ip: c.ip, country: c.country });
    if (!r.ok) return c.deny(r.code, r.message);
    const t = await issueToken(c.env, r.key, hwid.trim().slice(0, 128));
    return c.allow({ token: t.token, exp: t.exp, expiresAt: r.expiresAt, message: 'Login OK' });
});
