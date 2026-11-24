// WORKER 5 — FEATURE ENABLE GATE
// Called when the user taps to enable any feature on Home. {nonce, token, feature, vc, cert}
// No key / bad session / cracked login → DIALOG_EXIT (message + ONLY an [ Exit app ] button).
// Feature switched off by admin → FEATURE_OFF (toast, app stays open).
import { guardWorker, requireSession } from '../shared/guard.js';

export default guardWorker('feature', 'DIALOG_EXIT', async c => {
    const r = await requireSession(c); if (r.deny) return r.deny;
    if (c.body.feature && r.state.featureOn === false)
        return c.allow({ action: 'FEATURE_OFF', code: 'FEATURE_OFF', message: 'This feature is currently disabled.' });
    return c.allow({});
});
