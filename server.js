require('dotenv').config();
const express = require('express');
const crypto  = require('crypto');
const admin   = require('firebase-admin');
const cors    = require('cors');

const app  = express();
const PORT = process.env.PORT || 3000;

// ====================================================
//  CONFIG
// ====================================================
const ADMIN_PASSWORD = process.env.ADMIN_PASS;
const URLKING_API    = process.env.URLKING_API;
const SITE_URL       = process.env.SITE_URL;      // Backend Render URL
const FRONTEND_URL   = process.env.FRONTEND_URL;  // Key website URL

if (!ADMIN_PASSWORD || !URLKING_API || !SITE_URL || !FRONTEND_URL) {
    console.error("❌ Missing required environment variables.");
    process.exit(1);
}

// ====================================================
//  FIREBASE
// ====================================================
if (!admin.apps.length) {
    try {
        if (!process.env.FIREBASE_SERVICE_ACCOUNT_KEY)
            throw new Error("FIREBASE_SERVICE_ACCOUNT_KEY missing.");
        admin.initializeApp({
            credential: admin.credential.cert(
                JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY)
            )
        });
        console.log("✅ Firebase Admin initialized.");
    } catch (e) {
        console.error("❌ Firebase error:", e.message);
        process.exit(1);
    }
}
const db = admin.firestore();

// ====================================================
//  MIDDLEWARE
// ====================================================
app.use(express.json());
app.use(cors());

// ====================================================
//  KEY GENERATOR
// ====================================================
const KEY_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

function generateKey() {
    let s = '';
    for (let i = 0; i < 8; i++)
        s += KEY_CHARS[Math.floor(Math.random() * KEY_CHARS.length)];
    return 'SRT_' + s;
}

async function uniqueKey() {
    let k, exists = true;
    while (exists) {
        k = generateKey();
        exists = (await db.collection('keys').doc(k).get()).exists;
    }
    return k;
}

// ====================================================
//  AD FLOW
// ====================================================
app.post('/api/init-key-request', async (req, res) => {
    try {
        const sessionId = crypto.randomBytes(16).toString('hex');
        await db.collection('sessions').doc(sessionId).set({
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            completed: false,
            key: null
        });
        const cbUrl      = encodeURIComponent(`${SITE_URL}/api/ad-callback?session=${sessionId}`);
        const redirectUrl = `https://go.urlking.in/st?api=${URLKING_API}&url=${cbUrl}`;
        res.json({ sessionId, redirectUrl });
    } catch (e) {
        res.status(500).json({ error: "Failed to init session" });
    }
});

app.get('/api/ad-callback', async (req, res) => {
    const { session } = req.query;
    if (!session) return res.redirect(`${FRONTEND_URL}/?error=no_session`);
    try {
        const ref  = db.collection('sessions').doc(session);
        const snap = await ref.get();
        if (!snap.exists) return res.redirect(`${FRONTEND_URL}/?error=invalid_session`);
        const sess = snap.data();
        if (sess.completed)
            return res.redirect(`${FRONTEND_URL}/?key=${sess.key}&already=1`);

        const newKey = await uniqueKey();
        await db.collection('keys').doc(newKey).set({
            key:        newKey,
            createdAt:  new Date().toISOString(),
            expiresAt:  null,   // ← timer starts on FIRST APP LOGIN
            durationDays: 7,
            loginLimit: 1,
            loginCount: 0,
            type:       'standard',
            label:      '',
            note:       'Auto-generated via URL King ad',
            hwid:       null,
            lastUsedAt: null
        });
        await ref.update({ completed: true, key: newKey });
        res.redirect(`${FRONTEND_URL}/?key=${newKey}`);
    } catch (e) {
        console.error("Callback error:", e);
        res.redirect(`${FRONTEND_URL}/?error=server_error`);
    }
});

// ====================================================
//  KEY VERIFICATION  ← BUG FIXED HERE
//
//  ROOT CAUSE OF "login limit reached" BUG:
//  Old code checked login limit BEFORE HWID, and incremented
//  loginCount on EVERY call — even same-device re-logins.
//  So after 1 login, loginCount hit the limit and blocked forever.
//
//  FIX: Check HWID first. If it's the SAME device (hwid matches),
//  skip the limit check entirely and don't increment loginCount.
//  Only count NEW device connections against the login limit.
// ====================================================
app.get('/api/verify-key', async (req, res) => {
    const { key, hwid } = req.query;
    if (!key) return res.json({ valid: false, message: 'No key provided' });

    try {
        const keyRef = db.collection('keys').doc(key);
        const doc    = await keyRef.get();
        if (!doc.exists) return res.json({ valid: false, message: 'Key not found' });

        const kd      = doc.data();
        const now     = new Date();
        const updates = {};

        // ── STEP 1: Start timer on first login ──
        let expiresAt = kd.expiresAt || null;
        if (!kd.lastUsedAt && !expiresAt) {
            expiresAt        = new Date(now.getTime() + (kd.durationDays || 7) * 86400000).toISOString();
            updates.expiresAt = expiresAt;
        }

        // ── STEP 2: Check expiry ──
        if (expiresAt && now > new Date(expiresAt)) {
            return res.json({ valid: false, message: 'Key expired', expiredAt: expiresAt });
        }

        // ── STEP 3: HWID check (MOVED BEFORE login limit) ──
        const hwidMismatch   = kd.hwid && hwid && kd.hwid !== hwid;
        const sameDevice     = kd.hwid && hwid && kd.hwid === hwid;

        if (hwidMismatch) {
            return res.json({ valid: false, message: 'HWID mismatch — different device' });
        }

        // ── STEP 4: Login limit (ONLY for new device connections) ──
        if (!sameDevice) {
            // New device trying to connect — check the limit
            if (kd.loginLimit > 0 && (kd.loginCount || 0) >= kd.loginLimit) {
                return res.json({ valid: false, message: 'Login limit reached' });
            }
            // Bind HWID on very first login
            if (!kd.hwid && hwid) updates.hwid = hwid;
            // Only increment for new connections, not returning device
            updates.loginCount = (kd.loginCount || 0) + 1;
        }
        // sameDevice == true → skip limit, skip count increment

        // ── STEP 5: Save & respond ──
        updates.lastUsedAt = now.toISOString();
        await keyRef.update(updates);

        const finalExpiry = updates.expiresAt || expiresAt;
        const msLeft      = finalExpiry ? new Date(finalExpiry) - now : null;
        const daysLeft    = msLeft ? Math.ceil(msLeft / 86400000) : null;

        res.json({
            valid:      true,
            message:    'Key valid',
            key:        kd.key,
            expiresAt:  finalExpiry,
            daysLeft,
            loginCount: updates.loginCount ?? kd.loginCount,
            loginLimit: kd.loginLimit,
            type:       kd.type,
            label:      kd.label || ''
        });
    } catch (e) {
        console.error("Verify error:", e);
        res.status(500).json({ valid: false, message: 'Server error' });
    }
});

// ====================================================
//  DEVICE RESET (from key website — user self-service)
//  Resets HWID only. Timer/expiry NOT touched.
//  Rate-limited to once per 24 hours.
// ====================================================
app.post('/api/reset-device', async (req, res) => {
    const { key } = req.body;
    if (!key) return res.status(400).json({ success: false, message: 'No key provided' });

    try {
        const keyRef = db.collection('keys').doc(key.trim().toUpperCase());
        const doc    = await keyRef.get();
        if (!doc.exists) return res.json({ success: false, message: 'Key not found' });

        const kd = doc.data();

        // Don't reset expired keys
        if (kd.expiresAt && new Date() > new Date(kd.expiresAt)) {
            return res.json({ success: false, message: 'This key has expired — get a new one' });
        }

        // 24-hour cooldown
        if (kd.lastResetAt) {
            const hrs = (Date.now() - new Date(kd.lastResetAt).getTime()) / 3600000;
            if (hrs < 24) {
                const left = Math.ceil(24 - hrs);
                return res.json({
                    success: false,
                    message: `⏳ Cooldown active — ${left}h ${Math.ceil((24 - hrs - Math.floor(24 - hrs)) * 60)}m remaining`
                });
            }
        }

        await keyRef.update({
            hwid:        null,
            loginCount:  0,
            lastResetAt: new Date().toISOString()
        });

        res.json({ success: true, message: '✅ Device unlinked! Open the app on your new device and login.' });
    } catch (e) {
        console.error("Reset error:", e);
        res.status(500).json({ success: false, message: 'Server error' });
    }
});

// ====================================================
//  ADMIN AUTH
// ====================================================
function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token;
    if (token !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
    next();
}

app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    password === ADMIN_PASSWORD
        ? res.json({ success: true, token: ADMIN_PASSWORD })
        : res.status(401).json({ success: false, error: 'Wrong password' });
});

// ── STATS  ← BUG FIXED: null expiresAt was treated as 1970 ──
app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const list = (await db.collection('keys').get()).docs.map(d => d.data());
        const now  = new Date();
        res.json({
            total:    list.length,
            // FIX: null expiresAt = timer not started yet = NOT expired
            active:   list.filter(k => {
                const notExpired = !k.expiresAt || new Date(k.expiresAt) > now;
                const notMaxed   = (k.loginCount || 0) < (k.loginLimit || 1);
                return notExpired && notMaxed;
            }).length,
            expired:  list.filter(k => k.expiresAt && new Date(k.expiresAt) <= now).length,
            maxed:    list.filter(k => {
                const notExpired = !k.expiresAt || new Date(k.expiresAt) > now;
                return notExpired && (k.loginCount || 0) >= (k.loginLimit || 1);
            }).length,
            standard: list.filter(k => k.type === 'standard').length,
            custom:   list.filter(k => k.type === 'custom').length
        });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.get('/api/admin/keys', adminAuth, async (req, res) => {
    try {
        const list = (await db.collection('keys').get()).docs.map(d => d.data());
        list.sort((a, b) => new Date(b.createdAt || 0) - new Date(a.createdAt || 0));
        res.json(list);
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.post('/api/admin/create-key', adminAuth, async (req, res) => {
    const { customKey, duration, loginLimit, label, note } = req.body;
    try {
        let newKey;
        if (customKey?.trim()) {
            newKey = customKey.trim().toUpperCase();
            if (!newKey.startsWith('SRT_')) newKey = 'SRT_' + newKey;
            if ((await db.collection('keys').doc(newKey).get()).exists)
                return res.status(400).json({ error: 'Key already exists' });
        } else {
            newKey = await uniqueKey();
        }
        const keyData = {
            key: newKey, createdAt: new Date().toISOString(),
            expiresAt: null, durationDays: parseInt(duration) || 7,
            loginLimit: parseInt(loginLimit) || 1, loginCount: 0,
            type: 'custom', label: label || '', note: note || '',
            hwid: null, lastUsedAt: null
        };
        await db.collection('keys').doc(newKey).set(keyData);
        res.json({ success: true, key: keyData });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.patch('/api/admin/key/:key', adminAuth, async (req, res) => {
    try {
        const ref = db.collection('keys').doc(req.params.key);
        if (!(await ref.get()).exists) return res.status(404).json({ error: 'Not found' });
        const { expiresAt, durationDays, loginLimit, loginCount, label, note, hwid } = req.body;
        const u = {};
        if (expiresAt    !== undefined) u.expiresAt    = expiresAt ? new Date(expiresAt).toISOString() : null;
        if (durationDays !== undefined) u.durationDays = parseInt(durationDays);
        if (loginLimit   !== undefined) u.loginLimit   = parseInt(loginLimit);
        if (loginCount   !== undefined) u.loginCount   = parseInt(loginCount);
        if (label        !== undefined) u.label        = label;
        if (note         !== undefined) u.note         = note;
        if (hwid         !== undefined) u.hwid         = hwid || null;
        await ref.update(u);
        res.json({ success: true, key: (await ref.get()).data() });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

app.delete('/api/admin/key/:key', adminAuth, async (req, res) => {
    try {
        const ref = db.collection('keys').doc(req.params.key);
        if (!(await ref.get()).exists) return res.status(404).json({ error: 'Not found' });
        await ref.delete();
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// Admin force-reset a key's device (no cooldown for admin)
app.post('/api/admin/key/:key/reset-device', adminAuth, async (req, res) => {
    try {
        const ref = db.collection('keys').doc(req.params.key);
        if (!(await ref.get()).exists) return res.status(404).json({ error: 'Not found' });
        await ref.update({ hwid: null, loginCount: 0, lastResetAt: new Date().toISOString() });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Failed' }); }
});

// ====================================================
//  START
// ====================================================
app.listen(PORT, () => {
    console.log(`\n  ╔══════════════════════════════════╗`);
    console.log(`  ║   SRT X CHEATS  KEY SYSTEM  🔑   ║`);
    console.log(`  ╚══════════════════════════════════╝`);
    console.log(`  🚀  Port      : ${PORT}`);
    console.log(`  🔗  Backend   : ${SITE_URL}`);
    console.log(`  🌐  Frontend  : ${FRONTEND_URL}\n`);
});
