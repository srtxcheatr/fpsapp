// ONE command that makes every secret/env file for you:
//   node scripts/make-env.js <firebase-key.json> <https://your-app.onrender.com>
// Creates:  render.env          → paste into Render (Environment → "Add from .env")
//           workers/secrets.env → used by workers/set-secrets.sh
//           app-keys.txt        → public key for the Android app (+ your admin password)
// Add --force to regenerate (this CHANGES the keys: you must redeploy workers and rebuild the app).
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const root = path.join(__dirname, '..');
const args = process.argv.slice(2), force = args.includes('--force'), pos = args.filter(a => !a.startsWith('--'));
const fbPath = pos.find(a => /\.json$/i.test(a)), siteUrl = (pos.find(a => /^https?:\/\//i.test(a)) || '').replace(/\/+$/, '');
const out = f => path.join(root, f);
if (!force && fs.existsSync(out('render.env'))) {
    console.log('render.env already exists — NOT overwritten (keys are baked into your app).\nUse --force only if you really want brand-new keys.'); process.exit(0);
}
let firebase = '';
if (fbPath) {
    try { firebase = JSON.stringify(JSON.parse(fs.readFileSync(fbPath, 'utf8'))); }                  // minify to ONE line
    catch (e) { console.error('Cannot read Firebase JSON:', e.message); process.exit(1); }
    if (!/"private_key"/.test(firebase)) { console.error('That file is not a Firebase service-account key.'); process.exit(1); }
}
const rnd = n => crypto.randomBytes(n).toString('hex');
const pass = crypto.randomBytes(18).toString('base64url');
const WORKER_SECRET = rnd(32), SESSION_SECRET = rnd(32);
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const PRIV = privateKey.export({ type: 'pkcs8', format: 'der' }).toString('base64');
const PUB = publicKey.export({ type: 'spki', format: 'der' }).toString('base64');

fs.writeFileSync(out('render.env'), [
    `ADMIN_PASS=${pass}`,
    `SITE_URL=${siteUrl || 'https://CHANGE-ME.onrender.com'}`,
    `WORKER_SECRET=${WORKER_SECRET}`,
    `AUTO_REBIND_MAX=5`,
    `TRUST_PROXY=1`,
    `FIREBASE_SERVICE_ACCOUNT_KEY=${firebase || 'PASTE-THE-WHOLE-FIREBASE-JSON-ON-ONE-LINE'}`,
    '',
].join('\n'));
fs.writeFileSync(out('workers/secrets.env'), `WORKER_SECRET=${WORKER_SECRET}\nSESSION_SECRET=${SESSION_SECRET}\nGUARD_PRIVATE_KEY=${PRIV}\n`);
fs.writeFileSync(out('app-keys.txt'), `# Put in the ANDROID APP (public, safe):\nGUARD_PUBLIC_KEY=${PUB}\n\n# Your admin panel login (${siteUrl || 'your-url'}/admin/):\nADMIN_PASS=${pass}\n\n# Worker URLs (fill after ./deploy-all.sh):\nLOGIN_URL=\nLAUNCH_URL=\nMENU_URL=\nHEARTBEAT_URL=\nFEATURE_URL=\n`);

if (siteUrl) for (const w of ['login', 'launch', 'menu', 'heartbeat', 'feature']) {                 // set SERVER_URL in every worker
    const f = out(`workers/${w}/wrangler.toml`);
    fs.writeFileSync(f, fs.readFileSync(f, 'utf8').replace(/^SERVER_URL = ".*?"/m, `SERVER_URL = "${siteUrl}"`));
}
console.log(`
✅ Done. Files created:
   render.env           → Render → your service → Environment → "Add from .env" → paste/upload
   workers/secrets.env  → then run:  cd workers && ./set-secrets.sh && ./deploy-all.sh
   app-keys.txt         → public key for the app + your admin password

Admin password: ${pass}
${firebase ? '' : '\n⚠ Firebase JSON was not given: open render.env and paste it on the FIREBASE_SERVICE_ACCOUNT_KEY line (or re-run with the .json file path).'}
${siteUrl ? '' : '\n⚠ No URL given: edit SITE_URL in render.env and SERVER_URL in the 5 workers/*/wrangler.toml.'}
🔒 NEVER upload render.env, secrets.env, app-keys.txt or the Firebase .json to GitHub (.gitignore already blocks them).
`);
