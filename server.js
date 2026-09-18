require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ====================================================
//  CONFIG (ALL FROM .ENV)
// ====================================================
const ADMIN_PASSWORD = process.env.ADMIN_PASS;
const URLKING_API = process.env.URLKING_API;
const SITE_URL = process.env.SITE_URL;
const FRONTEND_URL = process.env.FRONTEND_URL;

// Safety check
if (!ADMIN_PASSWORD || !URLKING_API || !SITE_URL || !FRONTEND_URL) {
    console.error("❌ CRITICAL ERROR: Missing required environment variables.");
    process.exit(1);
}

// ====================================================
//  FIREBASE SETUP
// ====================================================
if (!admin.apps.length) {
    try {
        if (!process.env.FIREBASE_SERVICE_ACCOUNT_KEY) throw new Error("FIREBASE_SERVICE_ACCOUNT_KEY missing.");
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        console.log("✅ Firebase Admin initialized successfully.");
    } catch (error) {
        console.error("❌ Firebase Admin error:", error.message);
        process.exit(1);
    }
}
const db = admin.firestore();

app.use(express.json());
app.use(cors());

// ====================================================
//  KEY GENERATOR
// ====================================================
const KEY_CHARS = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
function generateKey() {
    let suffix = '';
    for (let i = 0; i < 8; i++) suffix += KEY_CHARS[Math.floor(Math.random() * KEY_CHARS.length)];
    return 'SRT_' + suffix;
}

async function uniqueKey() {
    let k; let exists = true;
    while (exists) {
        k = generateKey();
        const doc = await db.collection('keys').doc(k).get();
        exists = doc.exists;
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
            completed: false, key: null
        });

        const callbackUrl = encodeURIComponent(`${SITE_URL}/api/ad-callback?session=${sessionId}`);
        const redirectUrl = `https://go.urlking.in/st?api=${URLKING_API}&url=${callbackUrl}`;

        res.json({ sessionId, redirectUrl });
    } catch (error) {
        res.status(500).json({ error: "Failed to initialize session" });
    }
});

app.get('/api/ad-callback', async (req, res) => {
    const { session } = req.query;
    if (!session) return res.redirect(`${FRONTEND_URL}/?error=no_session`);

    try {
        const sessionRef = db.collection('sessions').doc(session);
        const sessionDoc = await sessionRef.get();

        if (!sessionDoc.exists) return res.redirect(`${FRONTEND_URL}/?error=invalid_session`);
        const sess = sessionDoc.data();

        if (sess.completed) return res.redirect(`${FRONTEND_URL}/?key=${sess.key}&session=${session}&already=1`);

        const newKey = await uniqueKey();
        
        // TIMER LOGIC: expiresAt is null. It starts on first login.
        await db.collection('keys').doc(newKey).set({
            key: newKey,
            createdAt: new Date().toISOString(),
            expiresAt: null, 
            durationDays: 7, 
            loginLimit: 1,
            loginCount: 0,
            type: 'standard',
            label: '', note: 'Auto-generated via URL King ad',
            hwid: null, lastUsedAt: null
        });

        await sessionRef.update({ completed: true, key: newKey });
        res.redirect(`${FRONTEND_URL}/?key=${newKey}&session=${session}`);
    } catch (error) {
        res.redirect(`${FRONTEND_URL}/?error=server_error`);
    }
});

// ====================================================
//  KEY VERIFICATION (LOGIN)
// ====================================================
app.get('/api/verify-key', async (req, res) => {
    const { key, hwid } = req.query;
    if (!key) return res.json({ valid: false, message: 'No key provided' });

    try {
        const keyRef = db.collection('keys').doc(key);
        const doc = await keyRef.get();

        if (!doc.exists) return res.json({ valid: false, message: 'Key not found' });

        const keyData = doc.data();
        const now = new Date();
        const updates = {};

        // 1. Timer Logic: If first login, start the timer now
        let expiresAt = keyData.expiresAt;
        if (!keyData.lastUsedAt) {
            const durationDays = keyData.durationDays || 7;
            expiresAt = new Date(now.getTime() + durationDays * 24 * 60 * 60 * 1000).toISOString();
            updates.expiresAt = expiresAt;
        }

        // 2. Check Expiration
        if (expiresAt && now > new Date(expiresAt)) {
            return res.json({ valid: false, message: 'Key expired', expiredAt: expiresAt });
        }

        // 3. Check Login Limit
        if (keyData.loginLimit > 0 && keyData.loginCount >= keyData.loginLimit) {
            return res.json({ valid: false, message: 'Login limit reached' });
        }

        // 4. HWID Check
        if (keyData.hwid && hwid && keyData.hwid !== hwid) {
            return res.json({ valid: false, message: 'HWID mismatch — different device' });
        }
        if (!keyData.hwid && hwid) updates.hwid = hwid;

        // 5. Apply Updates
        updates.loginCount = (keyData.loginCount || 0) + 1;
        updates.lastUsedAt = now.toISOString();
        await keyRef.update(updates);

        const msLeft = new Date(expiresAt) - now;
        const daysLeft = Math.ceil(msLeft / (1000 * 60 * 60 * 24));

        res.json({
            valid: true, message: 'Key valid',
            key: keyData.key, expiresAt: expiresAt,
            daysLeft: daysLeft, loginCount: updates.loginCount,
            loginLimit: keyData.loginLimit, type: keyData.type
        });
    } catch (error) {
        res.status(500).json({ valid: false, message: 'Server error' });
    }
});

// ====================================================
//  ADMIN ROUTES (Simplified for space)
// ====================================================
function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token;
    if (token !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
    next();
}
// Add your existing admin routes here...

app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));