// WORKER 3 — FLOATING MENU NAME CHECK
// {nonce, token, menuName, vc, cert}. Menu name must equal the server's overlayName (admin panel → Stage 2),
// or env MENU_NAME if you pin it here. Wrong name / no key / no session → CRASH.
import { guardWorker, requireSession } from '../shared/guard.js';

const norm = s => String(s || '').normalize('NFKC').trim();

export default guardWorker('menu', 'CRASH', async c => {
    const r = await requireSession(c); if (r.deny) return r.deny;
    const want = norm(c.env.MENU_NAME || r.state.menuName);
    if (!want || norm(c.body.menuName) !== want) return c.deny('MENU_TAMPERED');
    return c.allow({});
});
