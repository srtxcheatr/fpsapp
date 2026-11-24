'use strict';
// Generates the server's response-signing key pair (ECDSA P-256).
//   PRIVATE key → Render env  RESPONSE_SIGNING_KEY   (never put it in the app or in GitHub)
//   PUBLIC  key → hard-code in the app (APP_SERVER_PUBKEY)  — it can only VERIFY, never sign.
const crypto = require('crypto');
const { privateKey, publicKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const priv = privateKey.export({ type: 'pkcs8', format: 'pem' }).trim();
const pub = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');
console.log('\n=== 1) Render → Environment → RESPONSE_SIGNING_KEY (copy the ONE line below, exactly) ===\n');
console.log(priv.replace(/\n/g, '\\n'));
console.log('\n=== 2) App → APP_SERVER_PUBKEY (public key, base64) ===\n');
console.log(pub);
console.log('\nKeep a private copy of line 1 somewhere safe. If you lose it, generate a new pair and ship a new APK.\n');
