// ═══════════════════════════════════════════════════════════════════
//  SRT X CHEATS — SECURE KEY SERVER  v4.0   (bootstrap only)
//  App logic lives in src/ ; admin panel in public/admin/
// ═══════════════════════════════════════════════════════════════════
'use strict';
require('dotenv').config();

const { makeLogger } = require('./src/lib');
const log = makeLogger();

// ── Config ───────────────────────────────────────────────────────
// Fatal (server can't run safely): ADMIN_PASS, SITE_URL.
// Non-fatal: URLKING_API (only the ad flow is disabled) and Firebase (data routes answer 503, /health stays 200).
const env = process.env;
const missing = ['ADMIN_PASS', 'SITE_URL'].filter(k => !env[k]);
if (missing.length) {
    log.error('BOOT FAIL: missing required env vars', { missing: missing.join(',') });
    process.exit(1);
}
if (env.ADMIN_PASS.length < 12) log.warn('ADMIN_PASS is shorter than 12 characters — use a long random password');

const config = {
    PORT: parseInt(env.PORT) || 3000,
    ADMIN_PASS: env.ADMIN_PASS,
    SESSION_SECRET: env.SESSION_SECRET || '',
    URLKING_API: env.URLKING_API || '',
    SITE_URL: env.SITE_URL.replace(/\/+$/, ''),
    FRONTEND_URL: (env.FRONTEND_URL || env.SITE_URL).replace(/\/+$/, ''),
    ALLOWED_ORIGINS: (env.ALLOWED_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean),
    MAX_PAYLOAD: '10kb',
    TRUST_PROXY: env.TRUST_PROXY ? parseInt(env.TRUST_PROXY) : 1,   // Render: 1 proxy hop
    ALLOW_QUERY_TOKEN: env.ALLOW_QUERY_TOKEN === '1',                // legacy ?token=… (off: it leaks into logs)
    DISABLE_LEGACY_TOKEN: env.DISABLE_LEGACY_TOKEN === '1',          // refuse raw ADMIN_PASS in X-Admin-Token
};
if (!config.URLKING_API) log.warn('URLKING_API not set — /api/init-key-request is disabled');

// ── Firebase (failure-safe) ──────────────────────────────────────
const state = { firebase: { status: 'unavailable', reason: 'not initialised' } };
let db = null, FieldValue = null;
try {
    const admin = require('firebase-admin');
    if (!env.FIREBASE_SERVICE_ACCOUNT_KEY) throw new Error('FIREBASE_SERVICE_ACCOUNT_KEY is not set');
    const sa = JSON.parse(env.FIREBASE_SERVICE_ACCOUNT_KEY);
    if (typeof sa.private_key === 'string') sa.private_key = sa.private_key.replace(/\\n/g, '\n');
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    db = admin.firestore();
    FieldValue = admin.firestore.FieldValue;
    state.firebase = { status: 'ready' };
    log.info('Firebase initialised');
} catch (e) {
    // Message only — the service-account JSON is never logged.
    state.firebase = { status: 'unavailable', reason: String(e.message).slice(0, 120) };
    log.error('Firebase init FAILED — running degraded: data endpoints return 503, /health stays 200', { reason: e.message });
}

const { createApp } = require('./src/app');
const app = createApp({
    getDb: () => db,
    serverTimestamp: () => (FieldValue ? FieldValue.serverTimestamp() : new Date()),
    config, log, state,
});

// Clean old ad sessions every 2h (skipped while Firebase is down)
const cleanup = setInterval(async () => {
    if (!db) return;
    try {
        const snap = await db.collection('sessions').where('createdAt', '<', new Date(Date.now() - 2 * 3600 * 1000)).limit(100).get();
        if (snap.empty) return;
        const batch = db.batch();
        snap.docs.forEach(d => batch.delete(d.ref));
        await batch.commit();
        log.info('Session cleanup', { deleted: snap.size });
    } catch (e) { log.err('Session cleanup failed', e); }
}, 2 * 3600 * 1000);
cleanup.unref();

// ── Listen (Render: bind 0.0.0.0:$PORT) ──────────────────────────
const server = app.listen(config.PORT, '0.0.0.0', () => {
    log.info('Server listening', { port: config.PORT, firebase: state.firebase.status });
});
// Render's proxy keeps connections alive ~60s+; stay above it to avoid sporadic 502s.
server.keepAliveTimeout = 65000;
server.headersTimeout = 66000;
server.on('error', e => { log.err('Listen error', e); process.exit(1); });

// ── Process safety ───────────────────────────────────────────────
let closing = false;
function shutdown(reason, code) {
    if (closing) return;
    closing = true;
    log.warn('Shutting down', { reason });
    const force = setTimeout(() => process.exit(code), 10000);   // Render sends SIGKILL after 30s
    force.unref();
    app.locals.cleanup();
    server.close(() => process.exit(code));
}
process.on('SIGTERM', () => shutdown('SIGTERM', 0));
process.on('SIGINT', () => shutdown('SIGINT', 0));
// A rejected promise is logged and the server keeps serving.
process.on('unhandledRejection', r => log.error('unhandledRejection', { reason: r && r.message ? r.message : String(r) }));
// After an uncaught exception process state is unknown: drain, exit, let Render restart a clean process.
process.on('uncaughtException', e => { log.err('uncaughtException', e); shutdown('uncaughtException', 1); });
