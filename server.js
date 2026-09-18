require('dotenv').config();
const express = require('express');
const cors = require('cors');
const admin = require('firebase-admin');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

// ==========================================
// 1. FIREBASE ADMIN SETUP
// ==========================================
// Render Environment Variables needed:
// FIREBASE_PROJECT_ID
// FIREBASE_CLIENT_EMAIL
// FIREBASE_PRIVATE_KEY

if (!admin.apps.length) {
    try {
        // Verify that all required environment variables are present
        const requiredEnv = ['FIREBASE_PROJECT_ID', 'FIREBASE_CLIENT_EMAIL', 'FIREBASE_PRIVATE_KEY'];
        const missing = requiredEnv.filter(key => !process.env[key]);
        
        if (missing.length > 0) {
            throw new Error(`Missing environment variables: ${missing.join(', ')}. Please set them in your Render dashboard.`);
        }

        admin.initializeApp({
            credential: admin.credential.cert({
                projectId: process.env.FIREBASE_PROJECT_ID,
                clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
                // Replace literal \n with actual newlines, which is required on Render
                privateKey: process.env.FIREBASE_PRIVATE_KEY ? process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, '\n') : undefined,
            })
        });
        console.log("✅ Firebase Admin initialized successfully.");
    } catch (error) {
        console.error("❌ Firebase Admin initialization error:", error.message);
        console.error("⚠️ Please check your Render Environment Variables.");
        // Exit the process if Firebase cannot initialize
        process.exit(1); 
    }
}

const db = admin.firestore();

// Middleware
app.use(cors());
app.use(express.json());

// ==========================================
// 2. ROUTES
// ==========================================

// Health check route
app.get('/', (req, res) => {
    res.send('SRT X CHEATS API is running.');
});

// Route: Frontend calls this to start the process
app.post('/api/init-key-request', async (req, res) => {
    try {
        const sessionId = crypto.randomBytes(16).toString('hex');
        const now = Date.now();
        const expiresAt = now + 15 * 60 * 1000; // Session expires in 15 mins

        await db.collection('ad_sessions').doc(sessionId).set({
            status: 'pending',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt: expiresAt
        });

        console.log(`[INIT] Created new session: ${sessionId}`);

        // ⚠️ REPLACE 'https://your-ad-network.com/ad' WITH YOUR ACTUAL AD URL
        const callbackUrl = `https://fpsapp.onrender.com/api/ad-callback?session=${sessionId}`;
        const adUrl = `https://your-ad-network.com/ad?callback=${encodeURIComponent(callbackUrl)}`;
        
        res.json({ success: true, sessionId: sessionId, adUrl: adUrl });

    } catch (error) {
        console.error('[INIT ERROR]', error);
        res.status(500).json({ success: false, error: 'Failed to initialize session' });
    }
});

// Route: Ad network redirects the user here after they finish the ad
app.get('/api/ad-callback', async (req, res) => {
    let { session: sessionId } = req.query;
    
    console.log(`[CALLBACK] Received callback. Raw session: ${sessionId}`);

    if (!sessionId) {
        console.error('[CALLBACK ERROR] No session ID provided in URL');
        return res.redirect('https://cheats.xo.je/?error=missing_session');
    }

    sessionId = decodeURIComponent(sessionId).trim();

    try {
        const sessionRef = db.collection('ad_sessions').doc(sessionId);
        const sessionDoc = await sessionRef.get();

        if (!sessionDoc.exists) {
            console.error(`[CALLBACK ERROR] Session NOT FOUND in Firestore: ${sessionId}`);
            return res.redirect('https://cheats.xo.je/?error=invalid_session');
        }

        const sessionData = sessionDoc.data();

        if (Date.now() > sessionData.expiresAt) {
            console.error(`[CALLBACK ERROR] Session EXPIRED: ${sessionId}`);
            return res.redirect('https://cheats.xo.je/?error=session_expired');
        }

        if (sessionData.status === 'completed') {
            console.log(`[CALLBACK INFO] Session already completed: ${sessionId}`);
            return res.redirect(`https://cheats.xo.je/?session=${sessionId}&status=success`);
        }

        const generatedKey = 'SRT_' + crypto.randomBytes(5).toString('hex').toUpperCase();

        await db.runTransaction(async (transaction) => {
            const tSessionDoc = await transaction.get(sessionRef);
            
            if (!tSessionDoc.exists) {
                throw new Error('INVALID_SESSION');
            }

            const currentData = tSessionDoc.data();
            if (currentData.status === 'completed') return;

            transaction.update(sessionRef, {
                status: 'completed',
                generatedKey: generatedKey,
                completedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            const keyRef = db.collection('keys').doc(generatedKey);
            transaction.set(keyRef, {
                key: generatedKey,
                sessionId: sessionId,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                status: 'active'
            });
        });

        console.log(`[CALLBACK SUCCESS] Generated key ${generatedKey} for session ${sessionId}`);
        res.redirect(`https://cheats.xo.je/?session=${sessionId}&status=success`);

    } catch (error) {
        console.error(`[CALLBACK ERROR] Transaction failed for session ${sessionId}:`, error);
        res.redirect('https://cheats.xo.je/?error=internal_error');
    }
});

// Route: Frontend calls this to get the key after being redirected
app.get('/api/get-key/:sessionId', async (req, res) => {
    try {
        const { sessionId } = req.params;
        const sessionDoc = await db.collection('ad_sessions').doc(sessionId).get();
        
        if (!sessionDoc.exists) {
            return res.status(404).json({ success: false, error: 'Session not found' });
        }

        const data = sessionDoc.data();
        
        if (data.status === 'completed' && data.generatedKey) {
            return res.json({ success: true, key: data.generatedKey });
        } else {
            return res.status(400).json({ success: false, error: 'Key is not ready yet. Please wait.' });
        }
    } catch (error) {
        console.error('[GET KEY ERROR]', error);
        res.status(500).json({ success: false, error: 'Internal server error' });
    }
});

// ==========================================
// 3. START SERVER
// ==========================================
app.listen(PORT, () => {
    console.log(`🚀 Server listening on port ${PORT}`);
});