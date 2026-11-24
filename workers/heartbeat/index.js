// WORKER 4 — TIME-TO-TIME KEY + SESSION EXPIRY (heartbeat)
// App calls every ~60 s while running. Key expired / revoked / session invalid →
// CLOSE_MENU_AND_EXIT (app closes the floating menu, stops macros, then exits). Valid → ALLOW + renewed token.
import { guardWorker, requireSession, issueToken } from '../shared/guard.js';

export default guardWorker('heartbeat', 'CLOSE_MENU_AND_EXIT', async c => {
    const r = await requireSession(c); if (r.deny) return r.deny;
    const t = await issueToken(c.env, r.session.k, r.session.h);   // rolling renewal
    return c.allow({ token: t.token, exp: t.exp, expiresAt: r.state.expiresAt });
});
