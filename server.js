require('dotenv').config();
const express = require('express');
const crypto = require('crypto');
const admin = require('firebase-admin');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// ====================================================
//  CONFIG (STRICTLY FROM .ENV)
// ====================================================
const ADMIN_PASSWORD = process.env.ADMIN_PASS;
const URLKING_API = process.env.URLKING_API;
const SITE_URL = process.env.SITE_URL;         // Backend URL
const FRONTEND_URL = process.env.FRONTEND_URL; // Where the ad flow returns the user to get the key

// Safety check for critical variables
if (!ADMIN_PASSWORD || !URLKING_API || !SITE_URL || !FRONTEND_URL) {
    console.error("❌ CRITICAL ERROR: Missing required environment variables. Check your .env file or Render settings.");
    process.exit(1);
}

// ====================================================
//  FIREBASE SETUP
// ====================================================
if (!admin.apps.length) {
    try {
        if (!process.env.FIREBASE_SERVICE_ACCOUNT_KEY) {
            throw new Error("FIREBASE_SERVICE_ACCOUNT_KEY is missing.");
        }
        const serviceAccount = JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_KEY);
        admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
        console.log("✅ Firebase Admin initialized successfully.");
    } catch (error) {
        console.error("❌ Firebase Admin error:", error.message);
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
    let suffix = '';
    for (let i = 0; i < 8; i++) {
        suffix += KEY_CHARS[Math.floor(Math.random() * KEY_CHARS.length)];
    }
    return 'SRT_' + suffix;
}

async function uniqueKey() {
    let k;
    let exists = true;
    while (exists) {
        k = generateKey();
        const doc = await db.collection('keys').doc(k).get();
        exists = doc.exists;
    }
    return k;
}

// ====================================================
//  AD FLOW (Generates Key for the user)
// ====================================================

// Step 1: Frontend calls this to start the ad process
app.post('/api/init-key-request', async (req, res) => {
    try {
        const sessionId = crypto.randomBytes(16).toString('hex');
        
        await db.collection('sessions').doc(sessionId).set({
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            completed: false,
            key: null
        });

        const callbackUrl = encodeURIComponent(`${SITE_URL}/api/ad-callback?session=${sessionId}`);
        const redirectUrl = `https://go.urlking.in/st?api=${URLKING_API}&url=${callbackUrl}`;

        res.json({ sessionId, redirectUrl });
    } catch (error) {
        console.error("Init Error:", error);
        res.status(500).json({ error: "Failed to initialize session" });
    }
});

// Step 2: URL King redirects here after the user watches an ad
app.get('/api/ad-callback', async (req, res) => {
    const { session } = req.query;
    
    // We only redirect back to the FRONTEND here, because the user needs to SEE the key on the website
    if (!session) return res.redirect(`${FRONTEND_URL}/?error=no_session`);

    try {
        const sessionRef = db.collection('sessions').doc(session);
        const sessionDoc = await sessionRef.get();

        if (!sessionDoc.exists) return res.redirect(`${FRONTEND_URL}/?error=invalid_session`);
        
        const sess = sessionDoc.data();

        if (sess.completed) {
            return res.redirect(`${FRONTEND_URL}/?key=${sess.key}&session=${session}&already=1`);
        }

        const newKey = await uniqueKey();
        
        // TIMER LOGIC: expiresAt is null. It starts on first login.
        await db.collection('keys').doc(newKey).set({
            key: newKey,
            createdAt: new Date().toISOString(),
            expiresAt: null, // Timer starts on first login
            durationDays: 7, // Default duration
            loginLimit: 1,
            loginCount: 0,
            type: 'standard',
            label: '', note: 'Auto-generated via URL King ad',
            hwid: null, lastUsedAt: null
        });

        await sessionRef.update({ completed: true, key: newKey });
        
        // Redirect to frontend so they can see the generated key
        res.redirect(`${FRONTEND_URL}/?key=${newKey}&session=${session}`);
    } catch (error) {
        console.error("Callback Error:", error);
        res.redirect(`${FRONTEND_URL}/?error=server_error`);
    }
});

// ====================================================
//  KEY VERIFICATION (APP LOGIN API)
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

        // 5. Apply Updates to Firebase
        updates.loginCount = (keyData.loginCount || 0) + 1;
        updates.lastUsedAt = now.toISOString();
        await keyRef.update(updates);

        // 🔥 6. RETURN JSON ONLY. NO REDIRECTS.
        // The frontend (App Login Page) will handle the redirect based on this response.
        const msLeft = new Date(expiresAt) - now;
        const daysLeft = Math.ceil(msLeft / (1000 * 60 * 60 * 24));

        res.json({
            valid: true, 
            message: 'Key valid',
            key: keyData.key, 
            expiresAt: expiresAt,
            daysLeft: daysLeft, 
            loginCount: updates.loginCount,
            loginLimit: keyData.loginLimit, 
            type: keyData.type
        });
    } catch (error) {
        console.error("Verify Error:", error);
        res.status(500).json({ valid: false, message: 'Server error' });
    }
});

// ====================================================
//  ADMIN MIDDLEWARE & ROUTES
// ====================================================
function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token;
    if (token !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
    next();
}

app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        res.json({ success: true, token: ADMIN_PASSWORD });
    } else {
        res.status(401).json({ success: false, error: 'Wrong password' });
    }
});

app.get('/api/admin/stats', adminAuth, async (req, res) => {
    try {
        const snapshot = await db.collection('keys').get();
        const list = snapshot.docs.map(doc => doc.data());
        const now = new Date();
        
        res.json({
            total: list.length,
            active: list.filter(k => new Date(k.expiresAt) > now && k.loginCount < (k.loginLimit || Infinity)).length,
            expired: list.filter(k => new Date(k.expiresAt) <= now).length,
            maxed: list.filter(k => k.loginCount >= (k.loginLimit || 1) && new Date(k.expiresAt) > now).length,
            standard: list.filter(k => k.type === 'standard').length,
            custom: list.filter(k => k.type === 'custom').length
        });
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch stats' });
    }
});

app.get('/api/admin/keys', adminAuth, async (req, res) => {
    try {
        const snapshot = await db.collection('keys').get();
        const list = snapshot.docs.map(doc => doc.data());
        list.sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
        res.json(list);
    } catch (error) {
        res.status(500).json({ error: 'Failed to fetch keys' });
    }
});

app.post('/api/admin/create-key', adminAuth, async (req, res) => {
    const { customKey, duration, loginLimit, label, note } = req.body;

    try {
        let newKey;
        if (customKey && customKey.trim()) {
            newKey = customKey.trim().toUpperCase();
            if (!newKey.startsWith('SRT_')) newKey = 'SRT_' + newKey;
            const existing = await db.collection('keys').doc(newKey).get();
            if (existing.exists) return res.status(400).json({ error: 'Key already exists' });
        } else {
            newKey = await uniqueKey();
        }

        const keyData = {
            key: newKey,
            createdAt: new Date().toISOString(),
            expiresAt: null, // Timer starts on first login
            durationDays: parseInt(duration) || 7,
            loginLimit: parseInt(loginLimit) || 1,
            loginCount: 0,
            type: 'custom',
            label: label || '',
            note: note || '',
            hwid: null,
            lastUsedAt: null
        };

        await db.collection('keys').doc(newKey).set(keyData);
        res.json({ success: true, key: keyData });
    } catch (error) {
        res.status(500).json({ error: 'Failed to create key' });
    }
});

app.patch('/api/admin/key/:key', adminAuth, async (req, res) => {
    const keyName = req.params.key;
    const { expiresAt, durationDays, loginLimit, loginCount, label, note, hwid } = req.body;

    try {
        const keyRef = db.collection('keys').doc(keyName);
        const doc = await keyRef.get();
        if (!doc.exists) return res.status(404).json({ error: 'Key not found' });

        const updates = {};
        if (expiresAt !== undefined) updates.expiresAt = new Date(expiresAt).toISOString();
        if (durationDays !== undefined) updates.durationDays = parseInt(durationDays);
        if (loginLimit !== undefined) updates.loginLimit = parseInt(loginLimit);
        if (loginCount !== undefined) updates.loginCount = parseInt(loginCount);
        if (label !== undefined) updates.label = label;
        if (note !== undefined) updates.note = note;
        if (hwid !== undefined) updates.hwid = hwid || null;

        await keyRef.update(updates);
        const updatedDoc = await keyRef.get();
        res.json({ success: true, key: updatedDoc.data() });
    } catch (error) {
        res.status(500).json({ error: 'Failed to update key' });
    }
});

app.delete('/api/admin/key/:key', adminAuth, async (req, res) => {
    const keyName = req.params.key;
    try {
        const keyRef = db.collection('keys').doc(keyName);
        const doc = await keyRef.get();
        if (!doc.exists) return res.status(404).json({ error: 'Not found' });
        
        await keyRef.delete();
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Failed to delete key' });
    }
});

// ====================================================
//  START SERVER
// ====================================================
app.listen(PORT, () => {
    console.log(`🚀 Server listening on port ${PORT}`);
    console.log(`🔗 Backend URL: ${SITE_URL}`);
    console.log(`🌐 Frontend URL: ${FRONTEND_URL}`);
});