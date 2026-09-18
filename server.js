const express = require('express');
const fs      = require('fs');
const path    = require('path');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3000;

// ====================================================
//  CONFIG — change these before deploying
// ====================================================
const ADMIN_PASSWORD = process.env.ADMIN_PASS  || 'SRTxAdmin@2026';   // ← CHANGE THIS
const SITE_URL       = process.env.SITE_URL     || `http://localhost:${PORT}`;
const URLKING_API    = 'b6549d25fbfdc3085eb0aadcc2a3d45a7f7c4008';

// ====================================================
//  DATA HELPERS
// ====================================================
const DATA_DIR    = path.join(__dirname, 'data');
const KEYS_FILE   = path.join(DATA_DIR, 'keys.json');
const SESSIONS_FILE = path.join(DATA_DIR, 'sessions.json');

if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

function readDB(file) {
    try {
        if (!fs.existsSync(file)) { fs.writeFileSync(file, '{}'); return {}; }
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (e) { return {}; }
}
function writeDB(file, data) {
    fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ====================================================
//  MIDDLEWARE
// ====================================================
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// CORS — needed for Android app API calls
app.use((req, res, next) => {
    res.header('Access-Control-Allow-Origin', '*');
    res.header('Access-Control-Allow-Methods', 'GET, POST, PATCH, DELETE, OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, X-Admin-Token');
    if (req.method === 'OPTIONS') return res.sendStatus(200);
    next();
});

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

function uniqueKey(keys) {
    let k;
    do { k = generateKey(); } while (keys[k]);
    return k;
}

// ====================================================
//  AD FLOW
// ====================================================

// Step 1: frontend calls this, gets a URL King redirect link
app.post('/api/init-key-request', (req, res) => {
    const sessions = readDB(SESSIONS_FILE);

    // Clean expired sessions (>2h) to keep file small
    const cutoff = Date.now() - 2 * 60 * 60 * 1000;
    Object.keys(sessions).forEach(id => {
        if (sessions[id].createdAt < cutoff) delete sessions[id];
    });

    const sessionId  = crypto.randomBytes(16).toString('hex');
    sessions[sessionId] = { createdAt: Date.now(), completed: false, key: null };
    writeDB(SESSIONS_FILE, sessions);

    const callbackUrl = encodeURIComponent(`${SITE_URL}/api/ad-callback?session=${sessionId}`);
    const redirectUrl = `https://go.urlking.in/st?api=${URLKING_API}&url=${callbackUrl}`;

    res.json({ sessionId, redirectUrl });
});

// Step 2: URL King redirects here after ads
app.get('/api/ad-callback', (req, res) => {
    const { session } = req.query;
    if (!session) return res.redirect('/?error=no_session');

    const sessions = readDB(SESSIONS_FILE);
    const sess     = sessions[session];

    if (!sess) return res.redirect('/?error=invalid_session');
    if (Date.now() - sess.createdAt > 2 * 60 * 60 * 1000) return res.redirect('/?error=expired');

    // Already completed → return the same key (idempotent)
    if (sess.completed) {
        return res.redirect(`/?key=${sess.key}&session=${session}&already=1`);
    }

    // Generate key
    const keys   = readDB(KEYS_FILE);
    const newKey = uniqueKey(keys);
    const now    = new Date();
    const expiry = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);

    keys[newKey] = {
        key:        newKey,
        createdAt:  now.toISOString(),
        expiresAt:  expiry.toISOString(),
        loginLimit: 1,
        loginCount: 0,
        type:       'standard',
        label:      '',
        note:       'Auto-generated via URL King ad',
        hwid:       null
    };
    writeDB(KEYS_FILE, keys);

    sess.completed = true;
    sess.key       = newKey;
    writeDB(SESSIONS_FILE, sessions);

    res.redirect(`/?key=${newKey}&session=${session}`);
});

// Frontend can poll this while waiting
app.get('/api/check-session', (req, res) => {
    const { session } = req.query;
    if (!session) return res.json({ status: 'invalid' });

    const sessions = readDB(SESSIONS_FILE);
    const sess     = sessions[session];
    if (!sess) return res.json({ status: 'invalid' });
    if (Date.now() - sess.createdAt > 2 * 60 * 60 * 1000) return res.json({ status: 'expired' });
    if (sess.completed) return res.json({ status: 'completed', key: sess.key });
    return res.json({ status: 'pending' });
});

// ====================================================
//  PUBLIC KEY VERIFICATION  (used by Android app)
// ====================================================
app.get('/api/verify-key', (req, res) => {
    const { key, hwid } = req.query;
    if (!key) return res.json({ valid: false, message: 'No key provided' });

    const keys    = readDB(KEYS_FILE);
    const keyData = keys[key];

    if (!keyData) return res.json({ valid: false, message: 'Key not found' });

    const now    = new Date();
    const expiry = new Date(keyData.expiresAt);

    if (now > expiry) {
        return res.json({ valid: false, message: 'Key expired', expiredAt: keyData.expiresAt });
    }
    if (keyData.loginLimit > 0 && keyData.loginCount >= keyData.loginLimit) {
        return res.json({ valid: false, message: 'Login limit reached' });
    }
    // HWID check
    if (keyData.hwid && hwid && keyData.hwid !== hwid) {
        return res.json({ valid: false, message: 'HWID mismatch — different device' });
    }
    // Bind HWID on first login
    if (!keyData.hwid && hwid) {
        keyData.hwid = hwid;
    }

    keyData.loginCount  = (keyData.loginCount || 0) + 1;
    keyData.lastUsedAt  = now.toISOString();
    keys[key] = keyData;
    writeDB(KEYS_FILE, keys);

    const msLeft   = expiry - now;
    const daysLeft = Math.ceil(msLeft / (1000 * 60 * 60 * 24));

    res.json({
        valid:      true,
        message:    'Key valid',
        key:        keyData.key,
        expiresAt:  keyData.expiresAt,
        daysLeft,
        loginCount: keyData.loginCount,
        loginLimit: keyData.loginLimit,
        type:       keyData.type,
        label:      keyData.label || ''
    });
});

// ====================================================
//  ADMIN MIDDLEWARE
// ====================================================
function adminAuth(req, res, next) {
    const token = req.headers['x-admin-token'] || req.query.token;
    if (token !== ADMIN_PASSWORD) return res.status(401).json({ error: 'Unauthorized' });
    next();
}

// ====================================================
//  ADMIN ROUTES
// ====================================================
app.post('/api/admin/login', (req, res) => {
    const { password } = req.body;
    if (password === ADMIN_PASSWORD) {
        res.json({ success: true, token: ADMIN_PASSWORD });
    } else {
        res.status(401).json({ success: false, error: 'Wrong password' });
    }
});

app.get('/api/admin/stats', adminAuth, (req, res) => {
    const keys    = readDB(KEYS_FILE);
    const list    = Object.values(keys);
    const now     = new Date();
    res.json({
        total:    list.length,
        active:   list.filter(k => new Date(k.expiresAt) > now && k.loginCount < (k.loginLimit || Infinity)).length,
        expired:  list.filter(k => new Date(k.expiresAt) <= now).length,
        maxed:    list.filter(k => k.loginCount >= (k.loginLimit || 1) && new Date(k.expiresAt) > now).length,
        standard: list.filter(k => k.type === 'standard').length,
        custom:   list.filter(k => k.type === 'custom').length
    });
});

app.get('/api/admin/keys', adminAuth, (req, res) => {
    const keys = readDB(KEYS_FILE);
    const list = Object.values(keys).sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));
    res.json(list);
});

app.post('/api/admin/create-key', adminAuth, (req, res) => {
    const { customKey, duration, expiresAt: customExpiry, loginLimit, label, note } = req.body;

    const keys = readDB(KEYS_FILE);

    let newKey;
    if (customKey && customKey.trim()) {
        newKey = customKey.trim().toUpperCase();
        if (!newKey.startsWith('SRT_')) newKey = 'SRT_' + newKey;
    } else {
        newKey = uniqueKey(keys);
    }

    if (keys[newKey]) return res.status(400).json({ error: 'Key already exists' });

    let expiresAt;
    if (customExpiry) {
        expiresAt = new Date(customExpiry).toISOString();
    } else {
        const days = parseInt(duration) || 7;
        expiresAt  = new Date(Date.now() + days * 24 * 60 * 60 * 1000).toISOString();
    }

    const keyData = {
        key:        newKey,
        createdAt:  new Date().toISOString(),
        expiresAt,
        loginLimit: parseInt(loginLimit) || 1,
        loginCount: 0,
        type:       'custom',
        label:      label || '',
        note:       note  || '',
        hwid:       null
    };
    keys[newKey] = keyData;
    writeDB(KEYS_FILE, keys);

    res.json({ success: true, key: keyData });
});

app.patch('/api/admin/key/:key', adminAuth, (req, res) => {
    const keys    = readDB(KEYS_FILE);
    const keyName = req.params.key;
    if (!keys[keyName]) return res.status(404).json({ error: 'Key not found' });

    const { expiresAt, loginLimit, loginCount, label, note, hwid } = req.body;
    const kd = keys[keyName];
    if (expiresAt   !== undefined) kd.expiresAt   = new Date(expiresAt).toISOString();
    if (loginLimit  !== undefined) kd.loginLimit   = parseInt(loginLimit);
    if (loginCount  !== undefined) kd.loginCount   = parseInt(loginCount);
    if (label       !== undefined) kd.label        = label;
    if (note        !== undefined) kd.note         = note;
    if (hwid        !== undefined) kd.hwid         = hwid || null;

    writeDB(KEYS_FILE, keys);
    res.json({ success: true, key: kd });
});

app.delete('/api/admin/key/:key', adminAuth, (req, res) => {
    const keys    = readDB(KEYS_FILE);
    const keyName = req.params.key;
    if (!keys[keyName]) return res.status(404).json({ error: 'Not found' });
    delete keys[keyName];
    writeDB(KEYS_FILE, keys);
    res.json({ success: true });
});

// ====================================================
//  START
// ====================================================
app.listen(PORT, () => {
    console.log('');
    console.log('  ╔══════════════════════════════════╗');
    console.log('  ║   SRT X CHEATS  KEY SYSTEM  🔑   ║');
    console.log('  ╚══════════════════════════════════╝');
    console.log(`  🌐  http://localhost:${PORT}`);
    console.log(`  🔐  Admin password: ${ADMIN_PASSWORD}`);
    console.log('');
});
