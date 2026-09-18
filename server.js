'use strict';

require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const {
    initializeApp,
    cert
} = require('firebase-admin/app');

const {
    getFirestore,
    Timestamp,
    FieldValue
} = require('firebase-admin/firestore');


/* =========================================================
   CONFIG
========================================================= */

const PORT = Number(
    process.env.PORT || 3000
);

const SITE_URL = (
    process.env.SITE_URL ||
    'https://cheats.xo.je'
).replace(/\/+$/, '');

const CALLBACK_BASE_URL = (
    process.env.CALLBACK_BASE_URL ||
    'https://fpsapp.onrender.com'
).replace(/\/+$/, '');

const URLKING_API =
    process.env.URLKING_API;

const ADMIN_PASSWORD =
    process.env.ADMIN_PASS;

const FIREBASE_SERVICE_ACCOUNT_JSON =
    process.env.FIREBASE_SERVICE_ACCOUNT_JSON;


if (!URLKING_API) {
    console.warn(
        'WARNING: URLKING_API is not configured.'
    );
}

if (!ADMIN_PASSWORD) {
    console.error(
        'ERROR: ADMIN_PASS is not configured.'
    );

    process.exit(1);
}

if (!FIREBASE_SERVICE_ACCOUNT_JSON) {
    console.error(
        'ERROR: FIREBASE_SERVICE_ACCOUNT_JSON is not configured.'
    );

    process.exit(1);
}


/* =========================================================
   FIREBASE ADMIN SDK
========================================================= */

let serviceAccount;

try {

    serviceAccount =
        JSON.parse(
            FIREBASE_SERVICE_ACCOUNT_JSON
        );

} catch (error) {

    console.error(
        'ERROR: FIREBASE_SERVICE_ACCOUNT_JSON is invalid JSON.'
    );

    process.exit(1);
}


initializeApp({
    credential: cert(serviceAccount)
});


const db = getFirestore();


/* =========================================================
   FIRESTORE COLLECTIONS
========================================================= */

const keysCollection =
    db.collection('keys');

const adSessionsCollection =
    db.collection('ad_sessions');

const adminSessionsCollection =
    db.collection('admin_sessions');


/* =========================================================
   EXPRESS
========================================================= */

const app = express();

app.set(
    'trust proxy',
    1
);

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(
    express.json({
        limit: '100kb'
    })
);

app.use(
    express.urlencoded({
        extended: false,
        limit: '100kb'
    })
);


/* =========================================================
   CORS
========================================================= */

app.use((req, res, next) => {

    const allowedOrigins = [
        SITE_URL,
        'https://cheats.xo.je',
        'https://www.cheats.xo.je'
    ];

    const origin =
        req.headers.origin;

    if (
        origin &&
        allowedOrigins.includes(origin)
    ) {

        res.header(
            'Access-Control-Allow-Origin',
            origin
        );

        res.header(
            'Vary',
            'Origin'
        );

    } else if (!origin) {

        /*
         * Android native HTTP requests normally
         * do not send an Origin header.
         */

        res.header(
            'Access-Control-Allow-Origin',
            '*'
        );
    }

    res.header(
        'Access-Control-Allow-Methods',
        'GET, POST, PATCH, DELETE, OPTIONS'
    );

    res.header(
        'Access-Control-Allow-Headers',
        'Content-Type, X-Admin-Token'
    );

    res.header(
        'Access-Control-Max-Age',
        '86400'
    );

    if (req.method === 'OPTIONS') {
        return res.sendStatus(204);
    }

    next();
});


/* =========================================================
   STATIC WEBSITE
========================================================= */

app.use(
    express.static(
        path.join(
            __dirname,
            'public'
        )
    )
);


/* =========================================================
   RATE LIMITING
========================================================= */

const publicLimiter =
    rateLimit({
        windowMs: 60 * 1000,
        limit: 60,
        standardHeaders: true,
        legacyHeaders: false
    });


const verifyLimiter =
    rateLimit({
        windowMs: 60 * 1000,
        limit: 30,
        standardHeaders: true,
        legacyHeaders: false
    });


const adminLimiter =
    rateLimit({
        windowMs: 15 * 60 * 1000,
        limit: 30,
        standardHeaders: true,
        legacyHeaders: false
    });


/* =========================================================
   HELPERS
========================================================= */

function normalizeKey(key) {

    return String(key || '')
        .trim()
        .toUpperCase();
}


function generateKey() {

    const chars =
        'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    const bytes =
        crypto.randomBytes(8);

    let suffix = '';

    for (
        let i = 0;
        i < 8;
        i++
    ) {

        suffix +=
            chars[
                bytes[i] % chars.length
            ];
    }

    return `SRT_${suffix}`;
}


function generateToken() {

    return crypto
        .randomBytes(32)
        .toString('hex');
}


function hashToken(token) {

    return crypto
        .createHash('sha256')
        .update(String(token))
        .digest('hex');
}


function safeEqual(a, b) {

    const aa =
        Buffer.from(String(a));

    const bb =
        Buffer.from(String(b));

    if (
        aa.length !== bb.length
    ) {
        return false;
    }

    return crypto.timingSafeEqual(
        aa,
        bb
    );
}


function isValidDate(value) {

    const date =
        new Date(value);

    return !Number.isNaN(
        date.getTime()
    );
}


function toDate(value) {

    if (!value) {
        return null;
    }

    if (
        value instanceof Timestamp
    ) {
        return value.toDate();
    }

    if (
        value &&
        typeof value.toDate === 'function'
    ) {
        return value.toDate();
    }

    return new Date(value);
}


function daysLeft(expiresAt) {

    const expiry =
        toDate(expiresAt);

    if (!expiry) {
        return 0;
    }

    const difference =
        expiry.getTime() -
        Date.now();

    return Math.max(
        0,
        Math.ceil(
            difference /
            (
                1000 *
                60 *
                60 *
                24
            )
        )
    );
}


function timestampFromDate(date) {

    return Timestamp.fromDate(
        new Date(date)
    );
}


function serializeKey(
    document
) {

    const data =
        document.data();

    return {
        id: document.id,

        key: data.key_value,

        key_value: data.key_value,

        createdAt:
            toDate(
                data.created_at
            )?.toISOString() || null,

        expiresAt:
            toDate(
                data.expires_at
            )?.toISOString() || null,

        loginLimit:
            Number(
                data.login_limit || 0
            ),

        loginCount:
            Number(
                data.login_count || 0
            ),

        type:
            data.type || 'standard',

        label:
            data.label || '',

        note:
            data.note || '',

        hwid:
            data.hwid || null,

        lastUsedAt:
            toDate(
                data.last_used_at
            )?.toISOString() || null
    };
}


/* =========================================================
   FIRESTORE KEY GENERATION
========================================================= */

async function createUniqueKey() {

    for (
        let attempt = 0;
        attempt < 20;
        attempt++
    ) {

        const key =
            generateKey();

        const snapshot =
            await keysCollection
                .where(
                    'key_value',
                    '==',
                    key
                )
                .limit(1)
                .get();

        if (
            snapshot.empty
        ) {
            return key;
        }
    }

    throw new Error(
        'Unable to generate unique key.'
    );
}


/* =========================================================
   HEALTH
========================================================= */

app.get(
    '/health',
    async (req, res) => {

        try {

            /*
             * Small Firestore read to verify
             * the Admin SDK connection.
             */

            await db
                .collection('_health')
                .doc('status')
                .get();

            return res.json({
                ok: true,
                service: 'SRT X CHEATS',
                database: 'firebase-firestore',
                firebaseProject:
                    serviceAccount.project_id ||
                    'configured',
                timestamp:
                    new Date().toISOString()
            });

        } catch (error) {

            console.error(
                'Health error:',
                error
            );

            return res.status(503).json({
                ok: false,
                service: 'SRT X CHEATS',
                database: 'disconnected'
            });
        }
    }
);


/* =========================================================
   INITIALIZE AD SESSION
========================================================= */

app.post(
    '/api/init-key-request',
    publicLimiter,
    async (req, res) => {

        try {

            if (!URLKING_API) {

                return res.status(503).json({
                    success: false,
                    error:
                        'Ad service is not configured'
                });
            }


            const sessionId =
                crypto
                    .randomBytes(16)
                    .toString('hex');


            const now =
                new Date();

            const expiresAt =
                new Date(
                    now.getTime() +
                    2 *
                    60 *
                    60 *
                    1000
                );


            await adSessionsCollection
                .doc(sessionId)
                .set({

                    created_at:
                        Timestamp.fromDate(now),

                    expires_at:
                        Timestamp.fromDate(
                            expiresAt
                        ),

                    completed: false,

                    key_value: null
                });


            const callbackUrl =
                `${CALLBACK_BASE_URL}/api/ad-callback?session=${encodeURIComponent(sessionId)}`;


            const redirectUrl =
                `https://go.urlking.in/st?api=${encodeURIComponent(URLKING_API)}&url=${encodeURIComponent(callbackUrl)}`;


            return res.json({

                success: true,

                sessionId,

                redirectUrl
            });

        } catch (error) {

            console.error(
                'init-key-request error:',
                error
            );

            return res.status(500).json({

                success: false,

                error:
                    'Unable to initialize key request'
            });
        }
    }
);


/* =========================================================
   URL KING CALLBACK
========================================================= */

app.get(
    '/api/ad-callback',
    async (req, res) => {

        const sessionId =
            String(
                req.query.session || ''
            ).trim();


        if (!sessionId) {

            return res.redirect(
                `${SITE_URL}/?error=no_session`
            );
        }


        try {

            const sessionRef =
                adSessionsCollection
                    .doc(sessionId);


            /*
             * Firestore transaction:
             *
             * This prevents two callback requests
             * from creating two keys for the same
             * advertising session.
             */

            const result =
                await db.runTransaction(
                    async transaction => {

                        const sessionSnapshot =
                            await transaction.get(
                                sessionRef
                            );


                        if (
                            !sessionSnapshot.exists
                        ) {

                            throw new Error(
                                'INVALID_SESSION'
                            );
                        }


                        const session =
                            sessionSnapshot.data();


                        const expiresAt =
                            toDate(
                                session.expires_at
                            );


                        if (
                            !expiresAt ||
                            expiresAt.getTime() <
                            Date.now()
                        ) {

                            throw new Error(
                                'EXPIRED_SESSION'
                            );
                        }


                        /*
                         * Callback replay:
                         *
                         * Return the same key.
                         */

                        if (
                            session.completed &&
                            session.key_value
                        ) {

                            return {
                                key:
                                    session.key_value,

                                alreadyCompleted:
                                    true
                            };
                        }


                        /*
                         * Generate key.
                         *
                         * Firestore transaction does not
                         * support an arbitrary asynchronous
                         * query safely inside all retry
                         * scenarios, so use the deterministic
                         * random key as the document ID.
                         */

                        let newKey =
                            generateKey();


                        /*
                         * Very unlikely collision.
                         * If the key document exists,
                         * regenerate.
                         */

                        let keyRef =
                            keysCollection
                                .doc(newKey);


                        let keySnapshot =
                            await transaction.get(
                                keyRef
                            );


                        let attempts = 0;

                        while (
                            keySnapshot.exists &&
                            attempts < 10
                        ) {

                            newKey =
                                generateKey();

                            keyRef =
                                keysCollection
                                    .doc(newKey);

                            keySnapshot =
                                await transaction.get(
                                    keyRef
                                );

                            attempts++;
                        }


                        if (
                            keySnapshot.exists
                        ) {

                            throw new Error(
                                'KEY_GENERATION_FAILED'
                            );
                        }


                        const now =
                            new Date();


                        const expires =
                            new Date(
                                now.getTime() +
                                7 *
                                24 *
                                60 *
                                60 *
                                1000
                            );


                        transaction.set(
                            keyRef,
                            {

                                key_value:
                                    newKey,

                                created_at:
                                    Timestamp.fromDate(
                                        now
                                    ),

                                expires_at:
                                    Timestamp.fromDate(
                                        expires
                                    ),

                                login_limit:
                                    1,

                                login_count:
                                    0,

                                type:
                                    'standard',

                                label:
                                    '',

                                note:
                                    'Auto-generated via URL King ad',

                                hwid:
                                    null,

                                last_used_at:
                                    null
                            }
                        );


                        transaction.update(
                            sessionRef,
                            {

                                completed:
                                    true,

                                key_value:
                                    newKey,

                                completed_at:
                                    Timestamp.fromDate(
                                        now
                                    )
                            }
                        );


                        return {

                            key:
                                newKey,

                            alreadyCompleted:
                                false
                        };
                    }
                );


            return res.redirect(
                `${SITE_URL}/?key=${encodeURIComponent(result.key)}&session=${encodeURIComponent(sessionId)}${result.alreadyCompleted ? '&already=1' : ''}`
            );

        } catch (error) {

            console.error(
                'ad-callback error:',
                error
            );


            if (
                error.message ===
                'INVALID_SESSION'
            ) {

                return res.redirect(
                    `${SITE_URL}/?error=invalid_session`
                );
            }


            if (
                error.message ===
                'EXPIRED_SESSION'
            ) {

                return res.redirect(
                    `${SITE_URL}/?error=expired`
                );
            }


            return res.redirect(
                `${SITE_URL}/?error=server_error`
            );
        }
    }
);


/* =========================================================
   CHECK AD SESSION
========================================================= */

app.get(
    '/api/check-session',
    publicLimiter,
    async (req, res) => {

        const sessionId =
            String(
                req.query.session || ''
            ).trim();


        if (!sessionId) {

            return res.json({
                status: 'invalid'
            });
        }


        try {

            const snapshot =
                await adSessionsCollection
                    .doc(sessionId)
                    .get();


            if (
                !snapshot.exists
            ) {

                return res.json({
                    status: 'invalid'
                });
            }


            const session =
                snapshot.data();


            const expiresAt =
                toDate(
                    session.expires_at
                );


            if (
                !expiresAt ||
                expiresAt.getTime() <
                Date.now()
            ) {

                return res.json({
                    status: 'expired'
                });
            }


            if (
                session.completed &&
                session.key_value
            ) {

                return res.json({

                    status:
                        'completed',

                    key:
                        session.key_value
                });
            }


            return res.json({
                status: 'pending'
            });

        } catch (error) {

            console.error(
                'check-session error:',
                error
            );

            return res.status(500).json({
                status: 'error'
            });
        }
    }
);


/* =========================================================
   ANDROID KEY VERIFICATION
========================================================= */

app.get(
    '/api/verify-key',
    verifyLimiter,
    async (req, res) => {

        const key =
            normalizeKey(
                req.query.key
            );

        const hwid =
            String(
                req.query.hwid || ''
            ).trim();


        if (!key) {

            return res.status(400).json({

                valid: false,

                code:
                    'KEY_REQUIRED',

                message:
                    'No key provided'
            });
        }


        if (!hwid) {

            return res.status(400).json({

                valid: false,

                code:
                    'HWID_REQUIRED',

                message:
                    'HWID is required'
            });
        }


        try {

            /*
             * The key itself is the Firestore document ID.
             */

            const keyRef =
                keysCollection
                    .doc(key);


            const result =
                await db.runTransaction(
                    async transaction => {

                        const snapshot =
                            await transaction.get(
                                keyRef
                            );


                        if (
                            !snapshot.exists
                        ) {

                            return {
                                valid: false,

                                code:
                                    'KEY_NOT_FOUND',

                                status:
                                    404
                            };
                        }


                        const data =
                            snapshot.data();


                        const expiresAt =
                            toDate(
                                data.expires_at
                            );


                        /*
                         * Expiry.
                         */

                        if (
                            !expiresAt ||
                            expiresAt.getTime() <=
                            Date.now()
                        ) {

                            return {

                                valid: false,

                                code:
                                    'KEY_EXPIRED',

                                status:
                                    403,

                                expiredAt:
                                    expiresAt
                                        ?.toISOString()
                            };
                        }


                        /*
                         * Existing HWID.
                         */

                        if (
                            data.hwid &&
                            data.hwid !== hwid
                        ) {

                            return {

                                valid: false,

                                code:
                                    'HWID_MISMATCH',

                                status:
                                    403
                            };
                        }


                        const loginLimit =
                            Number(
                                data.login_limit ||
                                0
                            );

                        const loginCount =
                            Number(
                                data.login_count ||
                                0
                            );


                        /*
                         * If this key is already bound
                         * to this same device, allow
                         * repeated verification without
                         * consuming another login slot.
                         */

                        if (
                            data.hwid &&
                            data.hwid === hwid
                        ) {

                            transaction.update(
                                keyRef,
                                {
                                    last_used_at:
                                        FieldValue.serverTimestamp()
                                }
                            );


                            return {

                                valid: true,

                                code:
                                    'VALID',

                                message:
                                    'Key valid',

                                key:
                                    data.key_value,

                                expiresAt:
                                    expiresAt.toISOString(),

                                daysLeft:
                                    daysLeft(
                                        expiresAt
                                    ),

                                loginCount,

                                loginLimit,

                                type:
                                    data.type ||
                                    'standard',

                                label:
                                    data.label ||
                                    '',

                                hwidBound:
                                    true
                            };
                        }


                        /*
                         * Login limit.
                         *
                         * loginLimit = 0 means unlimited.
                         */

                        if (
                            loginLimit > 0 &&
                            loginCount >=
                            loginLimit
                        ) {

                            return {

                                valid: false,

                                code:
                                    'LOGIN_LIMIT_REACHED',

                                status:
                                    403
                            };
                        }


                        /*
                         * First login:
                         * bind HWID and consume
                         * one login.
                         */

                        const newLoginCount =
                            loginCount + 1;


                        transaction.update(
                            keyRef,
                            {

                                hwid:
                                    hwid,

                                login_count:
                                    newLoginCount,

                                last_used_at:
                                    FieldValue.serverTimestamp()
                            }
                        );


                        return {

                            valid: true,

                            code:
                                'VALID',

                            message:
                                'Key valid',

                            key:
                                data.key_value,

                            expiresAt:
                                expiresAt.toISOString(),

                            daysLeft:
                                daysLeft(
                                    expiresAt
                                ),

                            loginCount:
                                newLoginCount,

                            loginLimit,

                            type:
                                data.type ||
                                'standard',

                            label:
                                data.label ||
                                '',

                            hwidBound:
                                true
                        };
                    }
                );


            if (
                result.valid === false
            ) {

                return res.status(
                    result.status || 403
                ).json(result);
            }


            return res.json(
                result
            );

        } catch (error) {

            console.error(
                'verify-key error:',
                error
            );

            return res.status(500).json({

                valid: false,

                code:
                    'SERVER_ERROR',

                message:
                    'Server error'
            });
        }
    }
);


/* =========================================================
   ADMIN AUTH
========================================================= */

async function adminAuth(
    req,
    res,
    next
) {

    const token =
        req.headers[
            'x-admin-token'
        ] ||
        req.query.token;


    if (!token) {

        return res.status(401).json({

            error:
                'Unauthorized'
        });
    }


    try {

        const tokenHash =
            hashToken(token);


        const snapshot =
            await adminSessionsCollection
                .doc(tokenHash)
                .get();


        if (
            !snapshot.exists
        ) {

            return res.status(401).json({

                error:
                    'Invalid or expired admin session'
            });
        }


        const session =
            snapshot.data();


        const expiresAt =
            toDate(
                session.expires_at
            );


        if (
            !expiresAt ||
            expiresAt.getTime() <=
            Date.now()
        ) {

            await adminSessionsCollection
                .doc(tokenHash)
                .delete();


            return res.status(401).json({

                error:
                    'Invalid or expired admin session'
            });
        }


        next();

    } catch (error) {

        console.error(
            'adminAuth error:',
            error
        );

        return res.status(500).json({

            error:
                'Authentication error'
        });
    }
}


/* =========================================================
   ADMIN LOGIN
========================================================= */

app.post(
    '/api/admin/login',
    adminLimiter,
    async (req, res) => {

        const password =
            String(
                req.body.password || ''
            );


        if (!password) {

            return res.status(400).json({

                success: false,

                error:
                    'Password required'
            });
        }


        if (
            !safeEqual(
                password,
                ADMIN_PASSWORD
            )
        ) {

            return res.status(401).json({

                success: false,

                error:
                    'Wrong password'
            });
        }


        try {

            /*
             * Delete expired sessions.
             */

            const expired =
                await adminSessionsCollection
                    .where(
                        'expires_at',
                        '<=',
                        Timestamp.now()
                    )
                    .get();


            const batch =
                db.batch();


            expired.forEach(
                document => {
                    batch.delete(
                        document.ref
                    );
                }
            );


            if (
                !expired.empty
            ) {
                await batch.commit();
            }


            const token =
                generateToken();


            const tokenHash =
                hashToken(token);


            const expires =
                new Date(
                    Date.now() +
                    24 *
                    60 *
                    60 *
                    1000
                );


            await adminSessionsCollection
                .doc(tokenHash)
                .set({

                    created_at:
                        FieldValue.serverTimestamp(),

                    expires_at:
                        Timestamp.fromDate(
                            expires
                        )
                });


            /*
             * IMPORTANT:
             *
             * Never return ADMIN_PASSWORD.
             */

            return res.json({

                success: true,

                token,

                expiresIn:
                    86400
            });

        } catch (error) {

            console.error(
                'admin login error:',
                error
            );

            return res.status(500).json({

                success: false,

                error:
                    'Unable to create admin session'
            });
        }
    }
);


/* =========================================================
   ADMIN LOGOUT
========================================================= */

app.post(
    '/api/admin/logout',
    adminAuth,
    async (req, res) => {

        try {

            const token =
                req.headers[
                    'x-admin-token'
                ];


            if (token) {

                await adminSessionsCollection
                    .doc(
                        hashToken(token)
                    )
                    .delete();
            }


            return res.json({
                success: true
            });

        } catch (error) {

            console.error(
                'admin logout error:',
                error
            );

            return res.status(500).json({

                success: false,

                error:
                    'Unable to logout'
            });
        }
    }
);


/* =========================================================
   ADMIN STATS
========================================================= */

app.get(
    '/api/admin/stats',
    adminAuth,
    async (req, res) => {

        try {

            const snapshot =
                await keysCollection
                    .get();


            let total = 0;
            let active = 0;
            let expired = 0;
            let maxed = 0;
            let standard = 0;
            let custom = 0;


            const now =
                Date.now();


            snapshot.forEach(
                document => {

                    total++;


                    const data =
                        document.data();


                    const expiresAt =
                        toDate(
                            data.expires_at
                        );


                    const loginLimit =
                        Number(
                            data.login_limit ||
                            0
                        );


                    const loginCount =
                        Number(
                            data.login_count ||
                            0
                        );


                    if (
                        expiresAt &&
                        expiresAt.getTime() <=
                        now
                    ) {

                        expired++;

                    } else {

                        active++;


                        if (
                            loginLimit > 0 &&
                            loginCount >=
                            loginLimit
                        ) {

                            maxed++;
                        }
                    }


                    if (
                        data.type ===
                        'custom'
                    ) {

                        custom++;

                    } else {

                        standard++;
                    }
                }
            );


            return res.json({

                total,

                active,

                expired,

                maxed,

                standard,

                custom
            });

        } catch (error) {

            console.error(
                'admin stats error:',
                error
            );

            return res.status(500).json({

                error:
                    'Unable to load statistics'
            });
        }
    }
);


/* =========================================================
   ADMIN LIST KEYS
========================================================= */

app.get(
    '/api/admin/keys',
    adminAuth,
    async (req, res) => {

        try {

            const snapshot =
                await keysCollection
                    .orderBy(
                        'created_at',
                        'desc'
                    )
                    .get();


            const keys =
                snapshot.docs.map(
                    serializeKey
                );


            return res.json(
                keys
            );

        } catch (error) {

            console.error(
                'admin keys error:',
                error
            );

            return res.status(500).json({

                error:
                    'Unable to load keys'
            });
        }
    }
);


/* =========================================================
   ADMIN CREATE KEY
========================================================= */

app.post(
    '/api/admin/create-key',
    adminAuth,
    async (req, res) => {

        const {
            customKey,
            duration,
            expiresAt: customExpiry,
            loginLimit,
            label,
            note
        } = req.body;


        try {

            let newKey;


            if (
                customKey &&
                String(
                    customKey
                ).trim()
            ) {

                newKey =
                    normalizeKey(
                        customKey
                    );


                if (
                    !newKey.startsWith(
                        'SRT_'
                    )
                ) {

                    newKey =
                        `SRT_${newKey}`;
                }

            } else {

                newKey =
                    await createUniqueKey();
            }


            const keyRef =
                keysCollection
                    .doc(newKey);


            const existing =
                await keyRef.get();


            if (
                existing.exists
            ) {

                return res.status(400).json({

                    error:
                        'Key already exists'
                });
            }


            let expiryDate;


            if (
                customExpiry
            ) {

                if (
                    !isValidDate(
                        customExpiry
                    )
                ) {

                    return res.status(400).json({

                        error:
                            'Invalid expiry date'
                    });
                }


                expiryDate =
                    new Date(
                        customExpiry
                    );

            } else {

                const durationDays =
                    Math.max(
                        1,
                        parseInt(
                            duration,
                            10
                        ) || 7
                    );


                expiryDate =
                    new Date(
                        Date.now() +
                        durationDays *
                        24 *
                        60 *
                        60 *
                        1000
                    );
            }


            const limit =
                Math.max(
                    0,
                    parseInt(
                        loginLimit,
                        10
                    ) || 1
                );


            const createdAt =
                new Date();


            await keyRef.set({

                key_value:
                    newKey,

                created_at:
                    Timestamp.fromDate(
                        createdAt
                    ),

                expires_at:
                    Timestamp.fromDate(
                        expiryDate
                    ),

                login_limit:
                    limit,

                login_count:
                    0,

                type:
                    'custom',

                label:
                    String(
                        label || ''
                    ),

                note:
                    String(
                        note || ''
                    ),

                hwid:
                    null,

                last_used_at:
                    null
            });


            const saved =
                await keyRef.get();


            return res.json({

                success: true,

                key:
                    serializeKey(
                        saved
                    )
            });

        } catch (error) {

            console.error(
                'create-key error:',
                error
            );

            return res.status(500).json({

                error:
                    'Unable to create key'
            });
        }
    }
);


/* =========================================================
   ADMIN EDIT KEY
========================================================= */

app.patch(
    '/api/admin/key/:key',
    adminAuth,
    async (req, res) => {

        const keyName =
            normalizeKey(
                req.params.key
            );


        const {
            expiresAt,
            loginLimit,
            loginCount,
            label,
            note,
            hwid
        } = req.body;


        try {

            const keyRef =
                keysCollection
                    .doc(keyName);


            const existing =
                await keyRef.get();


            if (
                !existing.exists
            ) {

                return res.status(404).json({

                    error:
                        'Key not found'
                });
            }


            const updates = {};


            if (
                expiresAt !== undefined
            ) {

                if (
                    !isValidDate(
                        expiresAt
                    )
                ) {

                    return res.status(400).json({

                        error:
                            'Invalid expiry date'
                    });
                }


                updates.expires_at =
                    Timestamp.fromDate(
                        new Date(
                            expiresAt
                        )
                    );
            }


            if (
                loginLimit !== undefined
            ) {

                updates.login_limit =
                    Math.max(
                        0,
                        parseInt(
                            loginLimit,
                            10
                        ) || 0
                    );
            }


            if (
                loginCount !== undefined
            ) {

                updates.login_count =
                    Math.max(
                        0,
                        parseInt(
                            loginCount,
                            10
                        ) || 0
                    );
            }


            if (
                label !== undefined
            ) {

                updates.label =
                    String(label);
            }


            if (
                note !== undefined
            ) {

                updates.note =
                    String(note);
            }


            if (
                hwid !== undefined
            ) {

                updates.hwid =
                    hwid
                        ? String(hwid)
                        : null;
            }


            if (
                Object.keys(
                    updates
                ).length === 0
            ) {

                return res.status(400).json({

                    error:
                        'No fields to update'
                });
            }


            await keyRef.update(
                updates
            );


            const updated =
                await keyRef.get();


            return res.json({

                success: true,

                key:
                    serializeKey(
                        updated
                    )
            });

        } catch (error) {

            console.error(
                'edit-key error:',
                error
            );

            return res.status(500).json({

                error:
                    'Unable to update key'
            });
        }
    }
);


/* =========================================================
   ADMIN DELETE KEY
========================================================= */

app.delete(
    '/api/admin/key/:key',
    adminAuth,
    async (req, res) => {

        const keyName =
            normalizeKey(
                req.params.key
            );


        try {

            const keyRef =
                keysCollection
                    .doc(keyName);


            const existing =
                await keyRef.get();


            if (
                !existing.exists
            ) {

                return res.status(404).json({

                    error:
                        'Key not found'
                });
            }


            await keyRef.delete();


            return res.json({

                success: true
            });

        } catch (error) {

            console.error(
                'delete-key error:',
                error
            );

            return res.status(500).json({

                error:
                    'Unable to delete key'
            });
        }
    }
);


/* =========================================================
   API 404
========================================================= */

app.use(
    '/api',
    (req, res) => {

        res.status(404).json({

            error:
                'API endpoint not found'
        });
    }
);


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use(
    (error, req, res, next) => {

        console.error(
            'Unhandled server error:',
            error
        );


        if (
            res.headersSent
        ) {

            return next(error);
        }


        res.status(500).json({

            error:
                'Internal server error'
        });
    }
);


/* =========================================================
   START
========================================================= */

async function start() {

    try {

        /*
         * Test Firebase connection.
         */

        await db
            .collection('_health')
            .doc('status')
            .get();


        app.listen(
            PORT,
            '0.0.0.0',
            () => {

                console.log('');
                console.log(
                    '======================================'
                );

                console.log(
                    '      SRT X CHEATS FIREBASE API'
                );

                console.log(
                    '======================================'
                );

                console.log(
                    `PORT: ${PORT}`
                );

                console.log(
                    `SITE_URL: ${SITE_URL}`
                );

                console.log(
                    `CALLBACK_BASE_URL: ${CALLBACK_BASE_URL}`
                );

                console.log(
                    `FIREBASE PROJECT: ${serviceAccount.project_id}`
                );

                console.log(
                    'DATABASE: FIRESTORE'
                );

                console.log(
                    'ADMIN AUTH: SESSION TOKEN'
                );

                console.log(
                    '======================================'
                );

                console.log('');
            }
        );

    } catch (error) {

        console.error(
            'Firebase initialization failed:',
            error
        );

        process.exit(1);
    }
}


/* =========================================================
   SHUTDOWN
========================================================= */

process.on(
    'SIGTERM',
    async () => {

        console.log(
            'SIGTERM received.'
        );

        process.exit(0);
    }
);


process.on(
    'SIGINT',
    async () => {

        console.log(
            'SIGINT received.'
        );

        process.exit(0);
    }
);


start();