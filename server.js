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
// Ensure your Render Environment Variables are set exactly like this:
// FIREBASE_PROJECT_ID="your-project-id"
// FIREBASE_CLIENT_EMAIL="your-client-email"
// FIREBASE_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----\n"

if (!admin.apps.length) {
    try {
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
        console.error("❌ Firebase Admin initialization error:", error);
    }
}

const db = admin.firestore();

// Middleware
app.use(cors());
app.use(express.json());

// ==========================================
// 2. ROUTES
// ==========================================

// Health check route (for Render to know the app is alive)
app.get('/', (req, res) => {
    res.send('SRT X CHEATS API is running.');
});

// Route: Frontend calls this to start the process
app.post('/api/init-key-request', async (req, res) => {
    try {
        // 1. Generate a secure session ID
        const sessionId = crypto.randomBytes(16).toString('hex');
        const now = Date.now();
        const expiresAt = now + 15 * 60 * 1000; // Session expires in 15 mins

        // 2. Save session to Firestore
        await db.collection('ad_sessions').doc(sessionId).set({
            status: 'pending',
            createdAt: admin.firestore.FieldValue.serverTimestamp(),
            expiresAt: expiresAt
        });

        console.log(`[INIT] Created new session: ${sessionId}`);

        // 3. Construct your Ad Network URL
        // ⚠️ REPLACE 'https://your-ad-network.com/ad' WITH YOUR ACTUAL AD URL
        // The ad network MUST redirect back to your Render callback URL with the session ID.
        const callbackUrl = `https://fpsapp.onrender.com/api/ad-callback?session=${sessionId}`;
        const adUrl = `https://your-ad-network.com/ad?callback=${encodeURIComponent(callbackUrl)}`;
        
        res.json({ 
            success: true, 
            sessionId: sessionId, 
            adUrl: adUrl 
        });

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

    // Sanitize the ID in case the ad network encoded it weirdly
    sessionId = decodeURIComponent(sessionId).trim();

    try {
        const sessionRef = db.collection('ad_sessions').doc(sessionId);
        
        // 🔥 CRITICAL FIX: Check if session exists BEFORE starting the transaction
        // This prevents the INVALID_SESSION error during Firestore retries
        const sessionDoc = await sessionRef.get();

        if (!sessionDoc.exists) {
            console.error(`[CALLBACK ERROR] Session NOT FOUND in Firestore: ${sessionId}`);
            return res.redirect('https://cheats.xo.je/?error=invalid_session');
        }

        const sessionData = sessionDoc.data();

        // Check if session expired
        if (Date.now() > sessionData.expiresAt) {
            console.error(`[CALLBACK ERROR] Session EXPIRED: ${sessionId}`);
            return res.redirect('https://cheats.xo.je/?error=session_expired');
        }

        // Check if already processed (user refreshed the callback page)
        if (sessionData.status === 'completed') {
            console.log(`[CALLBACK INFO] Session already completed: ${sessionId}`);
            return res.redirect(`https://cheats.xo.je/?session=${sessionId}&status=success`);
        }

        // 4. Generate the Key
        // Format: SRT_XXXXXXXXXX
        const generatedKey = 'SRT_' + crypto.randomBytes(5).toString('hex').toUpperCase();

        // 5. Safely update via Transaction
        await db.runTransaction(async (transaction) => {
            const tSessionDoc = await transaction.get(sessionRef);
            
            // Double check inside transaction
            if (!tSessionDoc.exists) {
                throw new Error('INVALID_SESSION');
            }

            const currentData = tSessionDoc.data();
            if (currentData.status === 'completed') {
                return; // Already processed
            }

            // Update session
            transaction.update(sessionRef, {
                status: 'completed',
                generatedKey: generatedKey,
                completedAt: admin.firestore.FieldValue.serverTimestamp()
            });

            // Save the generated key in a separate 'keys' collection
            const keyRef = db.collection('keys').doc(generatedKey);
            transaction.set(keyRef, {
                key: generatedKey,
                sessionId: sessionId,
                createdAt: admin.firestore.FieldValue.serverTimestamp(),
                status: 'active'
            });
        });

        console.log(`[CALLBACK SUCCESS] Generated key ${generatedKey} for session ${sessionId}`);
        
        // 6. Redirect back to your frontend
        // We redirect back to cheats.xo.je with the session ID so the frontend can fetch the key
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