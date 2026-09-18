'use strict';

require('dotenv').config();

const express = require('express');
const path = require('path');
const crypto = require('crypto');
const { Pool } = require('pg');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');

const app = express();

/* =========================================================
   CONFIGURATION
========================================================= */

const PORT = Number(process.env.PORT || 3000);

const DATABASE_URL = process.env.DATABASE_URL;

if (!DATABASE_URL) {
    console.error('ERROR: DATABASE_URL is not configured.');
    process.exit(1);
}

/*
 * SITE_URL:
 * Your actual public key website.
 */
const SITE_URL = (
    process.env.SITE_URL ||
    'https://cheats.xo.je'
).replace(/\/+$/, '');

/*
 * CALLBACK_BASE_URL:
 *
 * This must be the publicly reachable server containing
 * /api/ad-callback.
 *
 * If cheats.xo.je proxies /api to this Render service,
 * you can set this to:
 *
 * https://cheats.xo.je
 *
 * Otherwise keep:
 *
 * https://fpsapp.onrender.com
 */
const CALLBACK_BASE_URL = (
    process.env.CALLBACK_BASE_URL ||
    'https://fpsapp.onrender.com'
).replace(/\/+$/, '');

/*
 * NEVER hard-code your URL King API key in source code.
 * Put it in Render environment variables.
 */
const URLKING_API = process.env.URLKING_API;

if (!URLKING_API) {
    console.warn('WARNING: URLKING_API is not configured.');
}

/*
 * Admin password is supplied through Render environment
 * variable ADMIN_PASS.
 */
const ADMIN_PASSWORD = process.env.ADMIN_PASS;

if (!ADMIN_PASSWORD) {
    console.error('ERROR: ADMIN_PASS is not configured.');
    process.exit(1);
}


/* =========================================================
   POSTGRESQL
========================================================= */

const pool = new Pool({
    connectionString: DATABASE_URL,

    ssl: process.env.NODE_ENV === 'production'
        ? { rejectUnauthorized: false }
        : false,

    max: 10,

    idleTimeoutMillis: 30000,

    connectionTimeoutMillis: 10000
});


/* =========================================================
   EXPRESS
========================================================= */

app.set('trust proxy', 1);

app.use(
    helmet({
        crossOriginResourcePolicy: false
    })
);

app.use(express.json({
    limit: '100kb'
}));

app.use(express.urlencoded({
    extended: false,
    limit: '100kb'
}));


/* =========================================================
   CORS
========================================================= */

app.use((req, res, next) => {

    const allowedOrigins = [
        SITE_URL,
        'https://cheats.xo.je',
        'https://www.cheats.xo.je'
    ];

    const origin = req.headers.origin;

    if (origin && allowedOrigins.includes(origin)) {
        res.header('Access-Control-Allow-Origin', origin);
        res.header('Vary', 'Origin');
    } else if (!origin) {
        /*
         * Android native requests normally don't send Origin.
         */
        res.header('Access-Control-Allow-Origin', '*');
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
        path.join(__dirname, 'public')
    )
);


/* =========================================================
   RATE LIMITERS
========================================================= */

const publicLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 60,
    standardHeaders: true,
    legacyHeaders: false
});

const verifyLimiter = rateLimit({
    windowMs: 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false
});

const adminLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 30,
    standardHeaders: true,
    legacyHeaders: false
});


/* =========================================================
   HELPERS
========================================================= */

function now() {
    return new Date();
}

function normalizeKey(key) {
    return String(key || '')
        .trim()
        .toUpperCase();
}

function generateKey() {

    const chars =
        'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';

    const bytes = crypto.randomBytes(8);

    let suffix = '';

    for (let i = 0; i < 8; i++) {
        suffix += chars[bytes[i] % chars.length];
    }

    return `SRT_${suffix}`;
}

function generateToken() {
    return crypto.randomBytes(32).toString('hex');
}

function hashToken(token) {

    return crypto
        .createHash('sha256')
        .update(token)
        .digest('hex');
}

function safeEqual(a, b) {

    const aa = Buffer.from(String(a));
    const bb = Buffer.from(String(b));

    if (aa.length !== bb.length) {
        return false;
    }

    return crypto.timingSafeEqual(aa, bb);
}

function isValidDate(value) {

    const d = new Date(value);

    return !Number.isNaN(d.getTime());
}

function daysLeft(expiresAt) {

    const diff =
        new Date(expiresAt).getTime() -
        Date.now();

    return Math.max(
        0,
        Math.ceil(
            diff /
            (1000 * 60 * 60 * 24)
        )
    );
}


/* =========================================================
   DATABASE INITIALIZATION
========================================================= */

async function initializeDatabase() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS keys (
            id BIGSERIAL PRIMARY KEY,

            key_value VARCHAR(64) UNIQUE NOT NULL,

            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

            expires_at TIMESTAMPTZ NOT NULL,

            login_limit INTEGER NOT NULL DEFAULT 1,

            login_count INTEGER NOT NULL DEFAULT 0,

            type VARCHAR(32) NOT NULL DEFAULT 'standard',

            label TEXT NOT NULL DEFAULT '',

            note TEXT NOT NULL DEFAULT '',

            hwid VARCHAR(255),

            last_used_at TIMESTAMPTZ
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_keys_expires_at
        ON keys(expires_at);
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_keys_hwid
        ON keys(hwid);
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS ad_sessions (
            id VARCHAR(64) PRIMARY KEY,

            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

            expires_at TIMESTAMPTZ NOT NULL,

            completed BOOLEAN NOT NULL DEFAULT FALSE,

            key_value VARCHAR(64)
        );
    `);

    await pool.query(`
        CREATE INDEX IF NOT EXISTS idx_ad_sessions_expires_at
        ON ad_sessions(expires_at);
    `);

    await pool.query(`
        CREATE TABLE IF NOT EXISTS admin_sessions (
            token_hash VARCHAR(64) PRIMARY KEY,

            created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

            expires_at TIMESTAMPTZ NOT NULL
        );
    `);

    console.log('Database initialized successfully.');
}


/* =========================================================
   HEALTH CHECK
========================================================= */

app.get('/health', async (req, res) => {

    try {

        await pool.query('SELECT 1');

        res.json({
            ok: true,
            service: 'SRT X CHEATS',
            database: 'connected',
            timestamp: new Date().toISOString()
        });

    } catch (error) {

        console.error('Health check error:', error);

        res.status(503).json({
            ok: false,
            service: 'SRT X CHEATS',
            database: 'disconnected'
        });
    }
});


/* =========================================================
   KEY GENERATION
========================================================= */

async function createUniqueKey(client) {

    for (let attempt = 0; attempt < 20; attempt++) {

        const key = generateKey();

        const result = await client.query(
            `
            SELECT id
            FROM keys
            WHERE key_value = $1
            `,
            [key]
        );

        if (result.rowCount === 0) {
            return key;
        }
    }

    throw new Error('Unable to generate unique key.');
}


/* =========================================================
   AD FLOW
========================================================= */

/*
 * Step 1:
 *
 * POST /api/init-key-request
 *
 * Creates a temporary session and returns URL King URL.
 */

app.post(
    '/api/init-key-request',
    publicLimiter,
    async (req, res) => {

        try {

            if (!URLKING_API) {
                return res.status(503).json({
                    success: false,
                    error: 'Ad service is not configured'
                });
            }

            /*
             * Remove old sessions.
             */
            await pool.query(`
                DELETE FROM ad_sessions
                WHERE expires_at < NOW()
            `);

            const sessionId =
                crypto.randomBytes(16).toString('hex');

            await pool.query(
                `
                INSERT INTO ad_sessions
                (
                    id,
                    created_at,
                    expires_at,
                    completed,
                    key_value
                )
                VALUES
                (
                    $1,
                    NOW(),
                    NOW() + INTERVAL '2 hours',
                    FALSE,
                    NULL
                )
                `,
                [sessionId]
            );

            /*
             * IMPORTANT:
             *
             * URL King must be able to reach this endpoint.
             */
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
                error: 'Unable to initialize key request'
            });
        }
    }
);


/*
 * Step 2:
 *
 * URL King -> backend callback
 *
 * /api/ad-callback?session=XXXX
 */

app.get(
    '/api/ad-callback',
    async (req, res) => {

        const sessionId =
            String(req.query.session || '').trim();

        if (!sessionId) {
            return res.redirect(
                `${SITE_URL}/?error=no_session`
            );
        }

        const client = await pool.connect();

        try {

            await client.query('BEGIN');

            const sessionResult =
                await client.query(
                    `
                    SELECT *
                    FROM ad_sessions
                    WHERE id = $1
                    FOR UPDATE
                    `,
                    [sessionId]
                );

            if (sessionResult.rowCount === 0) {

                await client.query('ROLLBACK');

                return res.redirect(
                    `${SITE_URL}/?error=invalid_session`
                );
            }

            const session =
                sessionResult.rows[0];

            if (
                new Date(session.expires_at).getTime()
                < Date.now()
            ) {

                await client.query('ROLLBACK');

                return res.redirect(
                    `${SITE_URL}/?error=expired`
                );
            }


            /*
             * Already completed:
             *
             * Return exactly the same key.
             *
             * This prevents duplicate keys if the
             * callback is opened more than once.
             */
            if (session.completed && session.key_value) {

                await client.query('COMMIT');

                return res.redirect(
                    `${SITE_URL}/?key=${encodeURIComponent(session.key_value)}&session=${encodeURIComponent(sessionId)}&already=1`
                );
            }


            /*
             * Create key.
             */
            const newKey =
                await createUniqueKey(client);

            const expiresAt =
                new Date(
                    Date.now() +
                    7 * 24 * 60 * 60 * 1000
                );


            await client.query(
                `
                INSERT INTO keys
                (
                    key_value,
                    created_at,
                    expires_at,
                    login_limit,
                    login_count,
                    type,
                    label,
                    note,
                    hwid
                )
                VALUES
                (
                    $1,
                    NOW(),
                    $2,
                    1,
                    0,
                    'standard',
                    '',
                    'Auto-generated via URL King ad',
                    NULL
                )
                `,
                [
                    newKey,
                    expiresAt
                ]
            );


            /*
             * Mark session completed.
             */
            await client.query(
                `
                UPDATE ad_sessions
                SET
                    completed = TRUE,
                    key_value = $1
                WHERE id = $2
                `,
                [
                    newKey,
                    sessionId
                ]
            );


            await client.query('COMMIT');


            return res.redirect(
                `${SITE_URL}/?key=${encodeURIComponent(newKey)}&session=${encodeURIComponent(sessionId)}`
            );

        } catch (error) {

            await client.query('ROLLBACK');

            console.error(
                'ad-callback error:',
                error
            );

            return res.redirect(
                `${SITE_URL}/?error=server_error`
            );

        } finally {

            client.release();
        }
    }
);


/* =========================================================
   CHECK SESSION
========================================================= */

app.get(
    '/api/check-session',
    publicLimiter,
    async (req, res) => {

        const sessionId =
            String(req.query.session || '').trim();

        if (!sessionId) {
            return res.json({
                status: 'invalid'
            });
        }

        try {

            const result =
                await pool.query(
                    `
                    SELECT *
                    FROM ad_sessions
                    WHERE id = $1
                    `,
                    [sessionId]
                );

            if (result.rowCount === 0) {

                return res.json({
                    status: 'invalid'
                });
            }

            const session =
                result.rows[0];

            if (
                new Date(session.expires_at).getTime()
                < Date.now()
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
                    status: 'completed',
                    key: session.key_value
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
   ANDROID KEY LOGIN / VERIFICATION
========================================================= */

/*
 * GET /api/verify-key
 *
 * Parameters:
 *
 * key=SRT_XXXXXXXX
 * hwid=ANDROID_DEVICE_ID
 *
 * IMPORTANT:
 *
 * loginCount is incremented atomically.
 *
 * First device binds the HWID.
 *
 * Subsequent devices are rejected.
 */

app.get(
    '/api/verify-key',
    verifyLimiter,
    async (req, res) => {

        const key =
            normalizeKey(req.query.key);

        const hwid =
            String(req.query.hwid || '').trim();

        if (!key) {

            return res.status(400).json({
                valid: false,
                code: 'KEY_REQUIRED',
                message: 'No key provided'
            });
        }

        if (!hwid) {

            return res.status(400).json({
                valid: false,
                code: 'HWID_REQUIRED',
                message: 'HWID is required'
            });
        }

        const client =
            await pool.connect();

        try {

            await client.query('BEGIN');

            const result =
                await client.query(
                    `
                    SELECT *
                    FROM keys
                    WHERE key_value = $1
                    FOR UPDATE
                    `,
                    [key]
                );

            if (result.rowCount === 0) {

                await client.query('ROLLBACK');

                return res.status(404).json({
                    valid: false,
                    code: 'KEY_NOT_FOUND',
                    message: 'Key not found'
                });
            }

            const keyData =
                result.rows[0];

            const expiry =
                new Date(keyData.expires_at);

            const currentTime =
                new Date();


            /*
             * Expiry check.
             */
            if (currentTime > expiry) {

                await client.query('ROLLBACK');

                return res.status(403).json({
                    valid: false,
                    code: 'KEY_EXPIRED',
                    message: 'Key expired',
                    expiredAt: keyData.expires_at
                });
            }


            /*
             * HWID check.
             */
            if (
                keyData.hwid &&
                keyData.hwid !== hwid
            ) {

                await client.query('ROLLBACK');

                return res.status(403).json({
                    valid: false,
                    code: 'HWID_MISMATCH',
                    message: 'HWID mismatch — different device'
                });
            }


            /*
             * Login limit.
             *
             * If HWID is already bound, every successful
             * verification still consumes a login according
             * to your existing login-limit design.
             */
            if (
                keyData.login_limit > 0 &&
                keyData.login_count >= keyData.login_limit
            ) {

                /*
                 * Allow same bound device to be recognized,
                 * but DO NOT silently increase the count.
                 *
                 * This makes Android "session login" practical.
                 */
                if (
                    keyData.hwid &&
                    keyData.hwid === hwid
                ) {

                    const response = {
                        valid: true,
                        code: 'VALID',
                        message: 'Key valid',
                        key: keyData.key_value,
                        expiresAt: keyData.expires_at,
                        daysLeft: daysLeft(keyData.expires_at),
                        loginCount: keyData.login_count,
                        loginLimit: keyData.login_limit,
                        type: keyData.type,
                        label: keyData.label || '',
                        hwidBound: true
                    };

                    await client.query('ROLLBACK');

                    return res.json(response);
                }

                await client.query('ROLLBACK');

                return res.status(403).json({
                    valid: false,
                    code: 'LOGIN_LIMIT_REACHED',
                    message: 'Login limit reached'
                });
            }


            /*
             * First login:
             * bind HWID.
             */
            let boundHwid =
                keyData.hwid;

            if (!boundHwid) {
                boundHwid = hwid;
            }


            /*
             * Successful login.
             */
            const newLoginCount =
                Number(keyData.login_count || 0) + 1;


            const updateResult =
                await client.query(
                    `
                    UPDATE keys
                    SET
                        hwid = $1,
                        login_count = $2,
                        last_used_at = NOW()
                    WHERE id = $3
                    RETURNING *
                    `,
                    [
                        boundHwid,
                        newLoginCount,
                        keyData.id
                    ]
                );


            await client.query('COMMIT');


            const updated =
                updateResult.rows[0];


            return res.json({
                valid: true,
                code: 'VALID',
                message: 'Key valid',
                key: updated.key_value,
                expiresAt: updated.expires_at,
                daysLeft: daysLeft(updated.expires_at),
                loginCount: updated.login_count,
                loginLimit: updated.login_limit,
                type: updated.type,
                label: updated.label || '',
                hwidBound: true
            });

        } catch (error) {

            await client.query('ROLLBACK');

            console.error(
                'verify-key error:',
                error
            );

            return res.status(500).json({
                valid: false,
                code: 'SERVER_ERROR',
                message: 'Server error'
            });

        } finally {

            client.release();
        }
    }
);


/* =========================================================
   ADMIN AUTHENTICATION
========================================================= */

async function adminAuth(req, res, next) {

    const token =
        req.headers['x-admin-token'] ||
        req.query.token;

    if (!token) {

        return res.status(401).json({
            error: 'Unauthorized'
        });
    }

    try {

        const tokenHash =
            hashToken(token);

        const result =
            await pool.query(
                `
                SELECT token_hash
                FROM admin_sessions
                WHERE token_hash = $1
                AND expires_at > NOW()
                `,
                [tokenHash]
            );

        if (result.rowCount === 0) {

            return res.status(401).json({
                error: 'Invalid or expired admin session'
            });
        }

        next();

    } catch (error) {

        console.error(
            'adminAuth error:',
            error
        );

        return res.status(500).json({
            error: 'Authentication error'
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
            String(req.body.password || '');

        if (!password) {

            return res.status(400).json({
                success: false,
                error: 'Password required'
            });
        }

        if (!safeEqual(password, ADMIN_PASSWORD)) {

            return res.status(401).json({
                success: false,
                error: 'Wrong password'
            });
        }

        try {

            /*
             * Clean old admin sessions.
             */
            await pool.query(`
                DELETE FROM admin_sessions
                WHERE expires_at < NOW()
            `);

            const token =
                generateToken();

            const tokenHash =
                hashToken(token);

            await pool.query(
                `
                INSERT INTO admin_sessions
                (
                    token_hash,
                    created_at,
                    expires_at
                )
                VALUES
                (
                    $1,
                    NOW(),
                    NOW() + INTERVAL '24 hours'
                )
                `,
                [tokenHash]
            );

            /*
             * IMPORTANT:
             *
             * We NEVER return ADMIN_PASSWORD.
             * Only a random temporary session token.
             */
            return res.json({
                success: true,
                token,
                expiresIn: 86400
            });

        } catch (error) {

            console.error(
                'admin login error:',
                error
            );

            return res.status(500).json({
                success: false,
                error: 'Unable to create admin session'
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

        const token =
            req.headers['x-admin-token'];

        if (token) {

            await pool.query(
                `
                DELETE FROM admin_sessions
                WHERE token_hash = $1
                `,
                [hashToken(token)]
            );
        }

        res.json({
            success: true
        });
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

            const result =
                await pool.query(`
                    SELECT
                        COUNT(*)::int AS total,

                        COUNT(*) FILTER (
                            WHERE expires_at > NOW()
                            AND (
                                login_limit = 0
                                OR login_count < login_limit
                            )
                        )::int AS active,

                        COUNT(*) FILTER (
                            WHERE expires_at <= NOW()
                        )::int AS expired,

                        COUNT(*) FILTER (
                            WHERE expires_at > NOW()
                            AND login_limit > 0
                            AND login_count >= login_limit
                        )::int AS maxed,

                        COUNT(*) FILTER (
                            WHERE type = 'standard'
                        )::int AS standard,

                        COUNT(*) FILTER (
                            WHERE type = 'custom'
                        )::int AS custom

                    FROM keys
                `);

            res.json(result.rows[0]);

        } catch (error) {

            console.error(
                'admin stats error:',
                error
            );

            res.status(500).json({
                error: 'Unable to load statistics'
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

            const result =
                await pool.query(`
                    SELECT
                        id,
                        key_value AS key,
                        created_at AS "createdAt",
                        expires_at AS "expiresAt",
                        login_limit AS "loginLimit",
                        login_count AS "loginCount",
                        type,
                        label,
                        note,
                        hwid,
                        last_used_at AS "lastUsedAt"
                    FROM keys
                    ORDER BY created_at DESC
                `);

            res.json(result.rows);

        } catch (error) {

            console.error(
                'admin keys error:',
                error
            );

            res.status(500).json({
                error: 'Unable to load keys'
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

        const client =
            await pool.connect();

        try {

            await client.query('BEGIN');

            let newKey;

            if (
                customKey &&
                String(customKey).trim()
            ) {

                newKey =
                    normalizeKey(customKey);

                if (!newKey.startsWith('SRT_')) {
                    newKey =
                        `SRT_${newKey}`;
                }

            } else {

                newKey =
                    await createUniqueKey(client);
            }


            const exists =
                await client.query(
                    `
                    SELECT id
                    FROM keys
                    WHERE key_value = $1
                    `,
                    [newKey]
                );

            if (exists.rowCount > 0) {

                await client.query('ROLLBACK');

                return res.status(400).json({
                    error: 'Key already exists'
                });
            }


            let expiryDate;

            if (customExpiry) {

                if (!isValidDate(customExpiry)) {

                    await client.query('ROLLBACK');

                    return res.status(400).json({
                        error: 'Invalid expiry date'
                    });
                }

                expiryDate =
                    new Date(customExpiry);

            } else {

                const durationDays =
                    Math.max(
                        1,
                        parseInt(duration, 10) || 7
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
                    parseInt(loginLimit, 10) || 1
                );


            const result =
                await client.query(
                    `
                    INSERT INTO keys
                    (
                        key_value,
                        created_at,
                        expires_at,
                        login_limit,
                        login_count,
                        type,
                        label,
                        note,
                        hwid
                    )
                    VALUES
                    (
                        $1,
                        NOW(),
                        $2,
                        $3,
                        0,
                        'custom',
                        $4,
                        $5,
                        NULL
                    )
                    RETURNING
                        id,
                        key_value AS key,
                        created_at AS "createdAt",
                        expires_at AS "expiresAt",
                        login_limit AS "loginLimit",
                        login_count AS "loginCount",
                        type,
                        label,
                        note,
                        hwid
                    `,
                    [
                        newKey,
                        expiryDate,
                        limit,
                        label || '',
                        note || ''
                    ]
                );


            await client.query('COMMIT');


            return res.json({
                success: true,
                key: result.rows[0]
            });

        } catch (error) {

            await client.query('ROLLBACK');

            console.error(
                'create-key error:',
                error
            );

            return res.status(500).json({
                error: 'Unable to create key'
            });

        } finally {

            client.release();
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
            normalizeKey(req.params.key);

        const {
            expiresAt,
            loginLimit,
            loginCount,
            label,
            note,
            hwid
        } = req.body;

        try {

            const existing =
                await pool.query(
                    `
                    SELECT *
                    FROM keys
                    WHERE key_value = $1
                    `,
                    [keyName]
                );

            if (existing.rowCount === 0) {

                return res.status(404).json({
                    error: 'Key not found'
                });
            }


            const fields = [];
            const values = [];

            let index = 1;


            if (expiresAt !== undefined) {

                if (!isValidDate(expiresAt)) {

                    return res.status(400).json({
                        error: 'Invalid expiry date'
                    });
                }

                fields.push(
                    `expires_at = $${index++}`
                );

                values.push(
                    new Date(expiresAt)
                );
            }


            if (loginLimit !== undefined) {

                const value =
                    Math.max(
                        0,
                        parseInt(loginLimit, 10)
                    );

                fields.push(
                    `login_limit = $${index++}`
                );

                values.push(value);
            }


            if (loginCount !== undefined) {

                const value =
                    Math.max(
                        0,
                        parseInt(loginCount, 10)
                    );

                fields.push(
                    `login_count = $${index++}`
                );

                values.push(value);
            }


            if (label !== undefined) {

                fields.push(
                    `label = $${index++}`
                );

                values.push(
                    String(label)
                );
            }


            if (note !== undefined) {

                fields.push(
                    `note = $${index++}`
                );

                values.push(
                    String(note)
                );
            }


            if (hwid !== undefined) {

                fields.push(
                    `hwid = $${index++}`
                );

                values.push(
                    hwid ? String(hwid) : null
                );
            }


            if (fields.length === 0) {

                return res.status(400).json({
                    error: 'No fields to update'
                });
            }


            values.push(keyName);


            const result =
                await pool.query(
                    `
                    UPDATE keys
                    SET ${fields.join(', ')}
                    WHERE key_value = $${index}
                    RETURNING
                        id,
                        key_value AS key,
                        created_at AS "createdAt",
                        expires_at AS "expiresAt",
                        login_limit AS "loginLimit",
                        login_count AS "loginCount",
                        type,
                        label,
                        note,
                        hwid,
                        last_used_at AS "lastUsedAt"
                    `,
                    values
                );


            return res.json({
                success: true,
                key: result.rows[0]
            });

        } catch (error) {

            console.error(
                'edit-key error:',
                error
            );

            return res.status(500).json({
                error: 'Unable to update key'
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
            normalizeKey(req.params.key);

        try {

            const result =
                await pool.query(
                    `
                    DELETE FROM keys
                    WHERE key_value = $1
                    RETURNING key_value
                    `,
                    [keyName]
                );

            if (result.rowCount === 0) {

                return res.status(404).json({
                    error: 'Key not found'
                });
            }

            res.json({
                success: true
            });

        } catch (error) {

            console.error(
                'delete-key error:',
                error
            );

            res.status(500).json({
                error: 'Unable to delete key'
            });
        }
    }
);


/* =========================================================
   404 API HANDLER
========================================================= */

app.use('/api', (req, res) => {

    res.status(404).json({
        error: 'API endpoint not found'
    });
});


/* =========================================================
   ERROR HANDLER
========================================================= */

app.use((error, req, res, next) => {

    console.error(
        'Unhandled server error:',
        error
    );

    if (res.headersSent) {
        return next(error);
    }

    res.status(500).json({
        error: 'Internal server error'
    });
});


/* =========================================================
   START
========================================================= */

async function start() {

    try {

        await initializeDatabase();

        app.listen(
            PORT,
            '0.0.0.0',
            () => {

                console.log('');
                console.log(
                    '======================================'
                );
                console.log(
                    '       SRT X CHEATS KEY SYSTEM'
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
                    'DATABASE: PostgreSQL'
                );
                console.log(
                    'ADMIN PASSWORD: configured'
                );
                console.log(
                    '======================================'
                );
                console.log('');
            }
        );

    } catch (error) {

        console.error(
            'Unable to start server:',
            error
        );

        process.exit(1);
    }
}


process.on(
    'SIGTERM',
    async () => {

        console.log(
            'SIGTERM received. Closing database...'
        );

        await pool.end();

        process.exit(0);
    }
);

process.on(
    'SIGINT',
    async () => {

        console.log(
            'SIGINT received. Closing database...'
        );

        await pool.end();

        process.exit(0);
    }
);


start();