// One-off, idempotent migration for v4:  node scripts/migrate-v4.js [--dry-run]
//   keys/*   → adds  status:'active', revokedAt:null, revokeReason:null  where `status` is missing
//   meta/audit_head is created lazily by the first audit entry (nothing to do)
// The server already treats a missing `status` as 'active', so this is OPTIONAL: it only makes the data uniform.
// No Firestore index is needed (all filtering is done in memory).
'use strict';
require('dotenv').config();
const admin = require('firebase-admin');
const dry = process.argv.includes('--dry-run');

(async () => {
    if (!process.env.FIREBASE_SERVICE_ACCOUNT_KEY) { console.error('FIREBASE_SERVICE_ACCOUNT_KEY is not set'); process.exit(1); }
    const sa = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
    if (typeof sa.private_key === 'string') sa.private_key = sa.private_key.replace(/\\n/g, '\n');
    admin.initializeApp({ credential: admin.credential.cert(sa) });
    const db = admin.firestore();

    let last = null, scanned = 0, changed = 0;
    for (;;) {
        let q = db.collection('keys').orderBy(admin.firestore.FieldPath.documentId()).limit(400);
        if (last) q = q.startAfter(last);
        const snap = await q.get();
        if (snap.empty) break;
        const batch = db.batch();
        for (const d of snap.docs) {
            scanned++;
            if (d.data().status === undefined) {
                changed++;
                if (!dry) batch.update(d.ref, { status: 'active', revokedAt: null, revokeReason: null });
            }
        }
        if (!dry) await batch.commit();
        last = snap.docs[snap.docs.length - 1];
    }
    console.log(`${dry ? '[dry-run] ' : ''}scanned=${scanned} updated=${changed}`);
})().catch(e => { console.error('Migration failed:', e.message); process.exit(1); });
