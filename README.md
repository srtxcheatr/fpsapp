# 🔑 SRT X CHEATS — Key System

A full-stack license key generation system with ad monetization via URL King.

---

## 📁 File Structure

```
├── server.js            ← bootstrap: env, Firebase (failure-safe), listen, graceful shutdown
├── src/app.js           ← Express app: headers, rate limits, /health, public + admin API
├── src/service.js       ← key logic (verify, create, search, extend, revoke, delete, bulk)
├── src/lib.js           ← safe logger, key helpers, admin sessions, tamper-evident audit log
├── public/admin/        ← Admin panel (served at /admin)
├── scripts/migrate-v4.js← optional, idempotent data backfill
└── test/                ← node --test suites
```

---

## ⚙️ Setup & Run

### 1. Install dependencies
```bash
cd key-system
npm install
```

### 2. Set environment variables (optional but recommended)
```bash
export ADMIN_PASS="YourStrongPassword123"
export SITE_URL="https://your-domain.com"
export PORT=3000
```

Or create a `.env` file and use `dotenv` package.

### 3. Start the server
```bash
npm start
# or for development (auto-restart):
npm run dev
```

---

## 🌐 Deployment (Recommended: Railway or Render)

### Railway (free tier):
1. Push files to GitHub
2. Go to railway.app → New Project → Deploy from GitHub
3. Set env vars: `ADMIN_PASS`, `SITE_URL` (your Railway URL), `PORT`
4. Done — Railway gives you a public URL

### VPS (Ubuntu):
```bash
# Install Node.js
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# Install PM2 (process manager)
npm install -g pm2

# Start and keep running
SITE_URL=https://yourdomain.com ADMIN_PASS=YourPass pm2 start server.js --name srtx-keys
pm2 save
pm2 startup
```

---

## 🌐 Deployment (Render)

Build: `npm install` · Start: `npm start` · Health check path: `/health` · env vars: see `.env.example`.

## 🩺 /health and Render

`GET /health` → `200 {"status":"ok","uptime":<seconds>}` and nothing else (no memory, versions, env, Firebase state).
It proves only that the process is alive; it deliberately does **not** touch Firestore, so a Firebase outage can't make Render restart a healthy process.
Set Render → Settings → Health Check Path = `/health`. Firebase state is visible to admins at `GET /api/admin/system`.

**Free-plan limitation:** Render spins free web services down after ~15 minutes without inbound traffic; the next request cold-starts the service (can take a minute or more). `/health` cannot prevent this by itself. Options: paid instance (Starter or above — the only supported fix), or an external pinger hitting `/health` every ≤14 min (unofficial; Render may still restart free services). The Android app's connect/read timeouts (12 s / 15 s) are shorter than a cold start, so the first login after idle can show "waking up — retry".

## 🔐 Admin panel — `/admin`

Sign in with `ADMIN_PASS`. Session = HttpOnly + SameSite=Strict cookie (8 h) + CSRF header; the password itself is never used as a token. Failed logins only are rate-limited (5 / 15 min → 30 min IP ban).

Generate (count 1–100, random length 6–32, or a custom value 4–32 `A–Z0–9`; expiry as “N days after first login” or a fixed date; device limit; label/note) · search (key/label/note/HWID) · filter (active, unused, limit reached, expired, revoked, site, type) · sort · paginate · extend expiry · set exact expiry · revoke / restore · reset device · delete · bulk revoke/restore/extend/delete (≤500 per request; the UI chunks larger selections) · audit log viewer with chain verification.

**Revoked / expired / deleted keys stop working on the very next `/api/verify-key` call** — verify reads Firestore in a transaction on every request (no server-side cache), and the Android app re-checks at least every 60 s while running.

### Admin API (all require auth; mutating cookie calls need `X-CSRF-Token`)
| Method & path | Purpose |
|---|---|
| `POST /api/admin/login` · `/logout` · `GET /session` | auth |
| `GET /api/admin/stats` · `/system` | counters · Firebase/uptime |
| `GET /api/admin/keys` | legacy: full array (now with derived `status`) |
| `GET /api/admin/keys/search?search&status&site&type&sort&order&limit&offset` | filtered page `{total,items}` |
| `GET /api/admin/keys/ids?…same filters` | all matching key ids (≤5000) for “select all” |
| `POST /api/admin/create-key` | `{count,length,customKey,duration,expiresAt,loginLimit,siteId,label,note}` |
| `PATCH /api/admin/key/:key` · `DELETE /api/admin/key/:key` | edit · delete |
| `POST /api/admin/key/:key/{revoke,restore,extend,expiry,reset-device}` | single actions |
| `POST /api/admin/keys/bulk` | `{action:revoke|restore|extend|delete, keys[], days?, reason?, confirm?}` (`delete` needs `confirm:true`) |
| `GET /api/admin/audit?limit&before&action&key` · `/audit/verify` | read-only audit |

### Audit
Every admin action writes an append-only entry to Firestore `audit_logs/<seq>` (who/when/IP/action/keys/details; deleted keys keep a snapshot without HWID), SHA-256 hash-chained via `meta/audit_head`. There is no API to edit or delete entries; `/audit/verify` detects edited or missing entries. Failed audit writes are logged loudly but don't block the action. Keep Firestore rules closed to clients and restrict console write access.

## 🗄️ Data / migration
New optional key fields: `status` (`active`|`revoked`), `revokedAt`, `revokeReason`. Documents without `status` are treated as active, so **no migration is required**. To make data uniform: `npm run migrate -- --dry-run`, then `npm run migrate`. No Firestore index is needed. New collections `audit_logs` and `meta` are created on first use.

## 🧪 Tests
`npm install && npm test` (Node ≥18). `test/service.test.js` runs fully offline against an in-memory Firestore fake; `test/http.test.js` starts the real Express app and is skipped automatically until dependencies are installed.

## 📱 Android App Integration

To verify a key in your Android app, call:

```
GET https://your-domain.com/api/verify-key?key=SRT_XXXXXXXX&hwid=DEVICE_HWID
```

**Response (valid key):**
```json
{
  "valid": true,
  "message": "Key valid",
  "key": "SRT_XXXXXXXX",
  "expiresAt": "2026-09-25T...",
  "daysLeft": 7,
  "loginCount": 1,
  "loginLimit": 1,
  "type": "standard"
}
```

**Response (invalid key):**
```json
{
  "valid": false,
  "message": "Key expired"
}
```

**Getting HWID on Android:**
```java
String hwid = android.provider.Settings.Secure.getString(
    getContentResolver(),
    android.provider.Settings.Secure.ANDROID_ID
);
```

---

## 🔑 Key Format

Auto-generated keys: `SRT_` + 8 random uppercase alphanumeric chars
Example: `SRT_A2BK9QM7`

Characters used: `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`
(No I, O, 0, 1 to avoid confusion)

---

Generated keys may now use 6–32 random characters (default 8); `/api/verify-key` accepts 4–32. Existing 8-character keys are unaffected.

## ⚠️ Important Notes

1. Set a long random `ADMIN_PASS` and keep `FIREBASE_SERVICE_ACCOUNT_KEY` only in Render's environment.
2. If Firestore is unreachable the key endpoints return **503** (never `valid:false`), so the Android app keeps its stored license and treats it as offline instead of wiping it.
3. URL King's `/st` redirect gives no cryptographic proof of ad completion — the callback trusts the redirect.
