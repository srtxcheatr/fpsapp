'use strict';
// ═══ Server-side app sessions (v5) ═══════════════════════════════════════════════════════════
// Login creates a REAL session record in Firestore (collection `app_sessions`), not a stateless token.
//   • one active session per key  (new login replaces the old one → copied/shared sessions die)
//   • sliding idle expiry         (every valid signed call extends it; no call for SESSION_IDLE_MIN → expired)
//   • every call is signed        HMAC-SHA256 with a per-session secret + timestamp + strictly increasing counter
//                                 → cannot be forged, cannot be replayed, cannot be edited in transit
//   • every call re-checks the key in the database (revoked / expired / deleted / other device = refused)
// Responses are signed with the SERVER's private key (ECDSA P-256). The app embeds only the public key,
// so a fake / mock / redirected server cannot produce an answer the app accepts.
const crypto = require('crypto');
const AC = require('./appctl');
const { AppDeny, checkKeyData } = AC;

const COL = 'app_sessions';
const SID_RE = /^[A-Za-z0-9_-]{32,64}$/;
const NONCE_RE = /^[A-Za-z0-9_-]{16,64}$/;
const FCM_RE = /^[A-Za-z0-9:_\-.]{20,4096}$/;
const validFcm = t => (typeof t === 'string' && FCM_RE.test(t)) ? t : null;
const rand = n => crypto.randomBytes(n).toString('base64url');
const sha256hex = b => crypto.createHash('sha256').update(b).digest('hex');
const hmac = (secret, data) => crypto.createHmac('sha256', secret).update(data).digest('base64url');

// What the app must DO for each code. Lives on the server so you can change behaviour without a new APK.
//   CRACKED  → show "This app is not officially launched. This is a cracked app." then exit
//   CRASH    → crash the app instantly (no dialog)
//   FIX_TIME → ask the user to set automatic date & time (nothing is wrong with the licence)
//   SHOW_ERROR → normal "wrong key" message on the login screen
const ACTION = {
    NO_SESSION: 'CRACKED', BAD_SIG: 'CRACKED', REPLAY: 'CRACKED', APK_MODDED: 'CRACKED',
    BAD_TS: 'FIX_TIME',
    SESSION_EXPIRED: 'CRASH', SESSION_REPLACED: 'CRASH', SESSION_REVOKED: 'CRASH',
    KEY_INVALID: 'CRASH', KEY_NOT_FOUND: 'CRASH', TOKEN_EXPIRED: 'CRASH',
};
const actionFor = (code, onLogin) => (onLogin && /^KEY_/.test(code)) ? 'SHOW_ERROR' : (ACTION[code] || 'NONE');

// ── Response signer (ECDSA P-256 / SHA-256, DER signature — verifies with Android's "SHA256withECDSA") ──
function createSigner(pem) {
    if (!pem) return { enabled: false, sign: () => '', publicKeyB64: '' };
    const key = crypto.createPrivateKey(String(pem).replace(/\\n/g, '\n'));
    const curve = key.asymmetricKeyDetails && key.asymmetricKeyDetails.namedCurve;
    if (key.asymmetricKeyType !== 'ec' || (curve && curve !== 'prime256v1'))
        throw new Error('RESPONSE_SIGNING_KEY must be an EC P-256 (prime256v1) private key — run: npm run gen-signing-key');
    return {
        enabled: true,
        sign: data => crypto.sign('sha256', Buffer.from(data), { key, dsaEncoding: 'der' }).toString('base64url'),
        publicKeyB64: crypto.createPublicKey(key).export({ type: 'spki', format: 'der' }).toString('base64'),
    };
}

function createSessions({ idleMs = 13 * 60 * 1000, skewMs = 5 * 60 * 1000 } = {}) {
    const col = db => db.collection(COL);

    // Called right after the key passed verifyKey(). Replaces any older session of the same key.
    async function create(db, { key, hwid, ip, vc, fcm }, nowMs = Date.now()) {
        const sid = rand(32), secret = rand(32), iso = new Date(nowMs).toISOString();
        const keyRef = db.collection('keys').doc(key);
        // Same device restarting the app: quietly retire its previous session (no push needed). Another device keeps `live`,
        // so the 8-minute sweep force-closes it.
        try {
            const kd = (await keyRef.get()).data() || {};
            if (kd.activeSid) {
                const ps = await col(db).doc(kd.activeSid).get();
                if (ps.exists && ps.data().hwid === hwid) await col(db).doc(kd.activeSid).update({ live: false, closedAt: iso, closeReason: 'SESSION_REPLACED' });
            }
        } catch { /* best effort */ }
        await col(db).doc(sid).set({ sid, key, hwid, secret, createdAt: iso, lastSeenAt: iso, lastSeq: 0, live: true,
            expMs: nowMs + idleMs, ip: String(ip || '').slice(0, 64), vc: Number(vc) || 0, fcmToken: validFcm(fcm) });
        await keyRef.update({ activeSid: sid, activeSidAt: iso });
        return { sid, secret, expiresAt: new Date(nowMs + idleMs).toISOString() };
    }

    // Verifies one signed request and (atomically) extends the session. Throws AppDeny on any problem.
    //   headers: Authorization: Bearer <sid> · X-Ts (ms) · X-Seq (int, strictly increasing) · X-Nonce · X-Sig
    //   X-Sig = base64url( HMAC-SHA256(secret, METHOD \n PATH \n TS \n SEQ \n NONCE \n sha256hex(body)) )
    async function verify(db, req, nowMs = Date.now()) {
        const h = n => String(req.headers[n] || '').slice(0, 200);
        const m = /^Bearer ([A-Za-z0-9_-]{32,64})$/.exec(h('authorization'));
        if (!m || !SID_RE.test(m[1])) throw new AppDeny('NO_SESSION', 'Session not found', 401);
        const sid = m[1], ts = Number(h('x-ts')), seq = Number(h('x-seq')), nonce = h('x-nonce'), sig = h('x-sig');
        if (!Number.isSafeInteger(ts) || !Number.isSafeInteger(seq) || seq < 1 || !NONCE_RE.test(nonce) || !/^[A-Za-z0-9_-]{20,100}$/.test(sig))
            throw new AppDeny('BAD_SIG', 'Bad request signature', 403);
        if (Math.abs(nowMs - ts) > skewMs) {
            const e = new AppDeny('BAD_TS', 'Device date/time is wrong — set automatic time', 403);
            e.extra = { serverTime: new Date(nowMs).toISOString() };
            throw e;
        }
        const path = (req.baseUrl || '') + (req.path || '');
        const canonical = [req.method.toUpperCase(), path, ts, seq, nonce, sha256hex(req.rawBody || '')].join('\n');

        return db.runTransaction(async tx => {
            const sref = col(db).doc(sid);
            const ss = await tx.get(sref);
            if (!ss.exists) throw new AppDeny('NO_SESSION', 'Session not found', 401);
            const s = ss.data();
            const want = Buffer.from(hmac(s.secret, canonical)), got = Buffer.from(sig);
            if (want.length !== got.length || !crypto.timingSafeEqual(want, got)) throw new AppDeny('BAD_SIG', 'Bad request signature', 403);
            if (s.revoked) throw new AppDeny('SESSION_REVOKED', 'Session ended', 401);
            if (nowMs > s.expMs) throw new AppDeny('SESSION_EXPIRED', 'Session expired', 401);
            if (seq <= (s.lastSeq || 0)) throw new AppDeny('REPLAY', 'Request replayed', 403);
            const ks = await tx.get(db.collection('keys').doc(s.key));
            const kd = checkKeyData(ks.exists ? ks.data() : null, s.hwid, nowMs);       // revoked / expired / deleted / other device
            if (kd.activeSid !== sid) throw new AppDeny('SESSION_REPLACED', 'Logged in on another session', 401);
            const expMs = nowMs + idleMs;
            tx.update(sref, { lastSeq: seq, lastSeenAt: new Date(nowMs).toISOString(), expMs });
            return { sid, key: s.key, hwid: s.hwid, keyData: kd, expiresAt: new Date(expMs).toISOString() };
        });
    }

    async function destroy(db, sid) {
        await col(db).doc(sid).update({ revoked: true, live: false, expMs: 0, closedAt: new Date().toISOString(), closeReason: 'LOGOUT' });
    }

    // Housekeeping (called from server.js every 2h): delete sessions that expired more than a day ago.
    async function purge(db, nowMs = Date.now()) {
        const snap = await col(db).where('expMs', '<', nowMs - 24 * 3600 * 1000).limit(200).get();
        if (snap.empty) return 0;
        const batch = db.batch();
        snap.docs.forEach(d => batch.delete(d.ref));
        await batch.commit();
        return snap.size;
    }

    // The app (re)registers its Firebase push token (token refresh). Called after a signed request was verified.
    async function setPushToken(db, sid, token) {
        const t = validFcm(token);
        if (!t) throw new AppDeny('BAD_SIG', 'Bad push token', 400);
        await col(db).doc(sid).update({ fcmToken: t });
    }

    // ── SERVER → APP check (every SERVER_CHECK_MIN, default 8 min) ─────────────────────────────
    // A server cannot open a connection to a phone, so it uses Firebase push (FCM), which the phone keeps open itself.
    // For every live session: re-check session + key in the database. If the session is gone / expired / replaced, or the key is
    // revoked / expired / deleted / on another device → send a SIGNED FORCE_CLOSE push. The app verifies the signature and kills itself —
    // this works even if the cracker blocks the server (FCM travels over Google's channel, not through your Worker).
    async function sweep(db, { messaging, signer, log, nowMs = Date.now(), limit = 500 } = {}) {
        const snap = await col(db).where('live', '==', true).limit(limit).get();
        const out = { checked: 0, closed: 0, pushed: 0 };
        for (const d of snap.docs) {
            const s = d.data(); out.checked++;
            let reason = null;
            if (s.revoked) reason = 'SESSION_REVOKED';
            else if (nowMs > s.expMs) reason = 'SESSION_EXPIRED';
            else {
                const ks = await db.collection('keys').doc(s.key).get();
                try { const kd = checkKeyData(ks.exists ? ks.data() : null, s.hwid, nowMs); if (kd.activeSid !== s.sid) reason = 'SESSION_REPLACED'; }
                catch (e) { reason = e.code || 'KEY_INVALID'; }
            }
            if (!reason) continue;
            await d.ref.update({ live: false, closedAt: new Date(nowMs).toISOString(), closeReason: reason });
            out.closed++;
            // push only if it only just died (older ones are almost surely closed apps — no point waking them)
            if (messaging && signer && signer.enabled && s.fcmToken && nowMs - s.expMs < 30 * 60 * 1000) {
                const ts = String(nowMs);
                try {
                    await messaging.send({ token: s.fcmToken, data: { type: 'FORCE_CLOSE', sid: s.sid, ts, reason, sig: signer.sign(`FORCE_CLOSE.${s.sid}.${ts}`) },
                        android: { priority: 'high', ttl: 10 * 60 * 1000 } });
                    out.pushed++;
                } catch (e) { if (log) log.warn('FCM push failed', { code: e && e.code }); }
            }
        }
        return out;
    }

    return { idleMs, skewMs, create, verify, destroy, purge, setPushToken, sweep };
}

module.exports = { COL, ACTION, actionFor, NONCE_RE, createSigner, createSessions };
