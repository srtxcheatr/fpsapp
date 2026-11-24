// node scripts/gen-keys.js  → prints every secret you need (run once, store them safely)
const crypto = require('crypto');
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const priv = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
console.log('\n# Render env + EVERY worker secret (must be identical):\nWORKER_SECRET=' + crypto.randomBytes(32).toString('hex'));
console.log('\n# EVERY worker secret only (not needed on Render):\nSESSION_SECRET=' + crypto.randomBytes(32).toString('hex'));
console.log('\n# EVERY worker secret (PRIVATE — never put in the app):\nGUARD_PRIVATE_KEY=' + priv);
console.log('\n# Goes INSIDE the Android app (public, safe):\nGUARD_PUBLIC_KEY=' + pub + '\n');
