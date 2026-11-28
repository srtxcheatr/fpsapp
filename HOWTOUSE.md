# SRT X CHEATS — v5 Secure Session System

Server + Cloudflare Worker + app prompt. Do the 3 parts in this order: **A) server → B) worker → C) app (Google AI Studio)**.

---

## How it works (30 seconds)

```
APP ──(hard-coded)──► Cloudflare Worker ──(secret header)──► Render server ──► Firestore
                      edge shield, keep-warm                 sessions, keys
```

1. **Login** – app sends key + HWID. Server checks the key and creates a **real session** (`sid` + secret) in Firestore. Only 1 active session per key.
2. **Every feature switch** – before a feature turns ON, the app silently asks the server. Server checks: signature, session, key (revoked / expired / deleted / other device), and your admin on/off toggle for that feature.
3. **Every 10 minutes** – app sends a heartbeat. Session lives 13 min after the last call.
4. **Every answer is signed** by the server's private key. A fake/mock/redirected server can't sign → app knows.
5. **Every 8 minutes the SERVER checks the app's session.** A server can't open a connection into a phone, so it uses **Firebase push (FCM)** — the phone keeps that channel open itself. The server re-checks every live session + key in the database; if the session is not found / expired / replaced, or the key is revoked / expired / deleted → it sends a **signed `FORCE_CLOSE` push** and the app kills itself. This works even when a cracker blocks your server, because the push comes through Google, not through your Worker.

### What the app must do for each answer (server sends `action`)

| `action` | When | App does |
|---|---|---|
| `CRACKED` | no session, bad signature, replay, modded APK | dialog **"This app is not officially launched. This is a cracked app."** → **[Exit app]** |
| `CRASH` | session expired, key revoked/expired/deleted, logged in elsewhere | **crash instantly** (kill process, no dialog) |
| `FIX_TIME` | phone clock more than 5 min wrong | ask user to enable automatic date & time (no crash) |
| `SHOW_ERROR` | wrong key at login | normal red error on login screen |
| `GATE` (HTTP 423) | patch / maintenance from admin panel | existing patch / maintenance dialog |
| `NONE` | rate limit, server waking up | retry later |
| push `FORCE_CLOSE` | server's 8-minute check found a dead session / bad key | **force close instantly** (kill process) |

Because `action` comes from the server, you can change behaviour later (`ACTION` table in `src/appSession.js`) without a new APK.

---

## A) Server (Render)

1. Replace your GitHub repo files with this project (zip). New files: `src/appSession.js`, `scripts/gen-signing-key.js`, `worker/`. Changed: `src/app.js`, `src/appRoutes.js`, `src/appctl.js`, `server.js`, `package.json`, `.env.example`.
2. Make the signing key (Termux works):
   ```
   npm install
   npm run gen-signing-key
   ```
   It prints **(1) private key line** and **(2) public key**.
   - Private line → Render → Environment → `RESPONSE_SIGNING_KEY`. Never share it, never put it in the app.
   - Public key → goes in the app prompt (`APP_SERVER_PUBKEY`).
3. Make a long random secret (32+ chars) → Render env `ORIGIN_SECRET`. Use the same value in the Worker.
4. Optional: `SESSION_IDLE_MIN=13`, `HEARTBEAT_SEC=600`, `SERVER_CHECK_MIN=8` (defaults already right).
5. **Firebase push (for the 8-minute force-close):** use the same Firebase project your server already uses.
   - Firebase console → Project settings → **General → Add app → Android** → package name = your app's package (e.g. `com.srt.sensimacro`) → download `google-services.json` (needed in step C).
   - Project settings → **Cloud Messaging** → make sure **Firebase Cloud Messaging API (V1)** is *Enabled* (if it says disabled, click the 3-dot link and enable it in Google Cloud).
   - Your existing service account already works. If push fails with a permission error in Render logs, Google Cloud → IAM → give that service account the role **Firebase Cloud Messaging Admin**.
6. Deploy. Logs should NOT show the warnings (`ORIGIN_SECRET not set`, `RESPONSE_SIGNING_KEY not set`, `FCM unavailable`).

> Your admin panel stays on the Render URL as before. Only `/api/app/*` is locked to the Worker.

## B) Cloudflare Worker (phone friendly, no CLI)

1. Cloudflare dashboard → **Workers & Pages → Create → Hello World** → name it `srtx-edge` → Deploy.
2. **Edit code** → delete everything → paste `worker.js` → **Deploy**.
3. **Settings → Variables and Secrets → Add** (this is the Worker's "env" — your server URL lives ONLY here, never in the app and never in the code):
   - `ORIGIN_URL` — type **Secret** — `https://YOUR-SERVICE.onrender.com` (no trailing `/`). As a Secret the dashboard hides it after saving.
   - `ORIGIN_SECRET` — type **Secret** — same value as Render
   - optional `APP_UA_PREFIX` — type Text — `SRTX/` (then only requests from your app's User-Agent pass)
   - Click **Deploy** after adding variables.
4. **Settings → Trigger Events → Cron Triggers → Add** `*/10 * * * *` (keeps Render awake on the free plan).
5. Copy your Worker URL (`https://srtx-edge.YOURNAME.workers.dev`) → this is the app's `BASE_URL`.

**Test**
- `BASE_URL/health` → `{"status":"ok"}`
- `BASE_URL/api/app/boot?vc=1` → JSON with `"ok":true`
- `https://YOUR-SERVICE.onrender.com/api/app/boot?vc=1` (direct) → **404** (origin lock works)
- `BASE_URL/api/admin/stats` → 404 (admin is not exposed)

## C) App — Google AI Studio

1. Open Google AI Studio. Upload your project files (at least: login screen/activity, overlay service, the code that switches each feature, `AndroidManifest.xml`, `build.gradle`).
2. Put `google-services.json` (from Firebase, step A5) in your app module folder and upload it too. Fill the 3 values at the top of the prompt: `BASE_URL`, `APP_SERVER_PUBKEY`, `APP_VERSION_CODE`.
3. Paste the prompt. Review the files it returns before copying into your project.
4. Build, then test every row of the **Test list** at the bottom.

````text
You are a senior Android security engineer. Implant a server-verified licence system into MY existing Android app (SENSI MACRO / SRT X CHEATS). Use the same language as my project (Java or Kotlin) and the same HTTP client I already use (or plain HttpURLConnection). Add NO new libraries. Match my code style. Return complete files (no "..." and no placeholders), then a short list of every file you changed or created and where each feature check was added.

══ CONSTANTS (hard-coded in code, never from SharedPreferences / resources / remote config) ══
BASE_URL            = "https://srtx-edge.YOURNAME.workers.dev"
APP_SERVER_PUBKEY   = "PASTE_PUBLIC_KEY_BASE64_FROM_npm_run_gen-signing-key"   (X.509 SPKI, EC P-256)
APP_VERSION_CODE    = 5      (send as vc; must equal BuildConfig.VERSION_CODE)
User-Agent header   = "SRTX/" + versionName on EVERY request
The app must NEVER contain the Render/server URL — only BASE_URL (the Cloudflare Worker). Remove every other server URL, old verify-key call, old token / Bearer-token logic and old stage1/stage2 code that uses the previous token. All network calls go through ONE new class LicenseGuard.

══ SERVER API (all JSON, all over BASE_URL) ══
Every request sends header X-Nonce = 16+ random URL-safe chars (new per request).
Login/boot also send X-App-Vc. Signed calls send X-App-Vc and X-App-Cert (SHA-256 hex of my signing certificate, computed at runtime from PackageManager; for boot send it as ?cert=).

1) GET  /api/app/boot?vc=VC&cert=CERT                 → stage-1 config + asset manifest (no key)
2) POST /api/app/login   body {"key":K,"hwid":H,"vc":VC,"cert":CERT}
      200 → {ok,sid,secret,sessionExpiresAt,nextInSec,serverTime,...}   (keep sid + secret IN MEMORY ONLY, never on disk, never in logs)
3) GET  /api/app/stage2   (signed)   → stage-2 config + assets (use the existing stage-2 download logic, but via signed calls)
4) GET  /api/app/asset/:slot (signed for stage-2 slots)
5) POST /api/app/session/feature   body {"feature":"macroE"} (signed)
      200 → {ok:true, allowed:true|false, reason?:"DISABLED"|"UNKNOWN", ...}
6) POST /api/app/session/heartbeat body {} (signed)   → {ok:true, nextInSec, serverTime, ...}
7) POST /api/app/session/push-token body {"fcm":"<firebase token>"} (signed)  → {ok:true}  (call again whenever the token refreshes)
8) POST /api/app/session/logout    body {} (signed)
Login body may also contain "fcm": the current Firebase token (add it if already available).

Keep HWID exactly as my app computes it today (do not change it, existing keys are bound to it).

══ REQUEST SIGNING (signed calls) ══
Headers: Authorization: Bearer <sid> · X-Ts · X-Seq · X-Nonce · X-Sig
  X-Ts    = System.currentTimeMillis() + clockOffsetMs        (clockOffsetMs = serverTime(from login) - deviceNow at login)
  X-Seq   = AtomicLong counter, starts at 1 after each login, +1 per signed request, NEVER reused
  X-Sig   = Base64URL(no padding, no wrap) of HMAC-SHA256( key = UTF-8 bytes of the secret STRING, data = 
            METHOD + "\n" + PATH + "\n" + X-Ts + "\n" + X-Seq + "\n" + X-Nonce + "\n" + sha256hex(bodyBytes) )
  METHOD upper-case; PATH is the URL path only, e.g. /api/app/session/feature (no host, no query); bodyBytes are the EXACT bytes sent
  (GET → empty body → sha256 of empty string). sha256hex is lower-case hex.
Send the body with Content-Type: application/json. Serialize ALL signed requests with one lock/mutex (seq must arrive in order, so no parallel signed calls; download assets one after another).

══ RESPONSE VERIFICATION (every response, success AND error) ══
Server sends headers X-Resp-Ts and X-Resp-Sig. Signed text = nonce + "." + X-Resp-Ts + "." + httpStatus + "." + rawBodyString
Verify X-Resp-Sig (Base64URL, DER ECDSA) with Signature.getInstance("SHA256withECDSA") and the public key from APP_SERVER_PUBKEY (KeyFactory "EC", X509EncodedKeySpec). Also require |X-Resp-Ts - serverNow| < 5 minutes.
Rules:
 • HTTP 200/401/403/423 with a missing or invalid signature  → treat as FAKE SERVER → CRACKED action.
 • HTTP 429, 5xx, 502, 404, 400, 413, timeouts, no internet  → TRANSIENT: retry after 20 s (login screen: show "Server waking up, retry"). Never crash because of these alone.
 • Verify BEFORE parsing/using the body. Verify downloaded asset bytes against the sha256 in the signed manifest.

══ WHAT TO DO WITH THE ANSWER (read "action" from the signed JSON) ══
 CRACKED    → showCrackedAndExit()
 CRASH      → hardCrash()
 FIX_TIME   → dialog: "Set your phone date & time to automatic, then reopen the app." (no crash). Optionally retry once using serverTime as offset.
 SHOW_ERROR → show message on the login screen (wrong key etc.)
 GATE (HTTP 423) → keep my existing patch / maintenance dialog logic
 NONE       → transient, retry

showCrackedAndExit(): on the main thread show a NON-cancelable AlertDialog (also works from a service via an overlay/activity — use the safest option in my project) with EXACTLY this text:
   Title: "Not official"
   Message: "This app is not officially launched. This is a cracked app."
   Button: "Exit app"
 On click (and automatically after 4 seconds even if the dialog fails to show): stop the overlay service, then hardCrash().
hardCrash(): works from ANY thread, no dialog: stop services/overlay, then android.os.Process.killProcess(android.os.Process.myPid()); System.exit(1). Also call it from a finally-style fallback so it cannot be skipped by an exception.

══ LICENCE FLOW ══
 • Login screen: user enters key → LicenseGuard.login(key) on a background thread. Success → continue to stage-2 download → main UI. Save only the KEY locally (as today), never sid/secret.
 • On every app start with a saved key: login again automatically (a new session replaces the old one).
 • LicenseGuard.isActive() is true only after a successful verified login AND the last verified call is < 15 minutes old.
 • FEATURE GATE: for EVERY feature my app can switch on (fullScreenSensi, sensiZone, macroE, macroG, aimMarker, gtFix, fps120, touchBoost, ramBooster, plus any other toggle you find): find the exact place where the feature is enabled and wrap it:
       LicenseGuard.checkFeature("macroE") { allowed -> if (allowed) enableMacroE() else toast("This feature is disabled") }
   checkFeature runs the signed POST /session/feature on a background thread, silently (no spinner, no toast on success) and calls back on the main thread. The feature must NOT run before the callback says allowed. If the answer is a CRACKED/CRASH action, do that action immediately. If the call hits a transient error, retry up to 2 times (20 s apart), then do not enable the feature (do not crash).
   Do not leave any code path that enables a feature without going through checkFeature (check overlay buttons, quick toggles, auto-start-on-boot, restored saved state, services). Restored saved state must ALSO go through checkFeature after login.
 • HEARTBEAT: after login start a ScheduledExecutorService (NOT WorkManager) inside the foreground overlay service (also works while the app is in background): POST /session/heartbeat every 600 seconds (use nextInSec from the answer, clamp 300–600). Transient failure → retry every 20 s.
   Any CRASH/CRACKED answer → do that action instantly (so "session not found" or "session expired" = the app crashes instantly).
 • LOCAL WATCHDOG (works even if someone blocks my server with a firewall): remember SystemClock.elapsedRealtime() of the last VERIFIED successful answer. A separate timer checks every 30 s: if now - last > 15 minutes → hardCrash(). Use elapsedRealtime (not wall clock) so changing the phone clock does nothing.
 • SERVER FORCE-CLOSE PUSH (Firebase Cloud Messaging): every 8 minutes my server re-checks the session and, if the session is not found / expired / replaced or the key is revoked / expired / deleted, it sends a data push to this phone. Implement it:
     - Add the Firebase Messaging dependency (this is the ONLY allowed new dependency): firebase-bom + firebase-messaging, and the google-services plugin; I will put google-services.json in the app module. Show the exact gradle lines to add (both build.gradle files). Add a FirebaseMessagingService subclass to the manifest (exported=false, intent-filter com.google.firebase.MESSAGING_EVENT).
     - onNewToken(token): keep it in memory; if a session is active send it with POST /session/push-token (signed). At login, fetch FirebaseMessaging.getInstance().getToken() and send it as "fcm" in the login body (do not block login if the token is not ready; send it via push-token right after).
     - onMessageReceived(msg): data fields are type, sid, ts, reason, sig. Act ONLY if ALL are true: type == "FORCE_CLOSE"; this process has an ACTIVE LicenseGuard session and sid equals its current sid (ignore pushes for old/other sessions, ignore when the process has no session); |now - ts| < 10 minutes (ts is the server's clock: compare with deviceNow + clockOffsetMs); sig verifies (Base64URL DER ECDSA, SHA256withECDSA, APP_SERVER_PUBKEY) over the exact text "FORCE_CLOSE." + sid + "." + ts. If valid → hardCrash() immediately (no dialog). If anything is invalid → ignore silently.
     - Do not start the overlay service or any UI from this service; it only verifies and kills.
 • On normal exit/logout call POST /session/logout best-effort (this also stops the server from pushing to a closed app).
 • Thread safety: LicenseGuard is a singleton, volatile fields for sid/secret/offset/lastOk, one lock for signed requests.

══ HARDENING ══
 • Make LicenseGuard small and spread the checks (feature gate in several classes) — do not put a single boolean "isLicensed" that one patch can flip. Do not log sid, secret, key, signatures or request bodies (remove existing logs of them).
 • Build the constants (BASE_URL, public key) from split/obfuscated pieces (simple XOR or split strings) instead of one plain literal each.
 • Add R8/ProGuard rules (minifyEnabled true, shrinkResources true) in build.gradle release config and keep rules only for what must stay. Keep LicenseGuard class/method names unremarkable (do not name anything "crack", "license", "verify").
 • If my app has native C++ code (JNI), keep the HWID/cert computation where it is and add one extra check in native code that calls back LicenseGuard.isActive() before the first macro/touch action.
 • AndroidManifest: INTERNET permission must exist (plus POST_NOTIFICATIONS is NOT needed for data pushes); do not add cleartext traffic; set android:usesCleartextTraffic="false".

══ DELIVERABLE ══
1) LicenseGuard (full code), the FirebaseMessagingService class + any small helper classes. 2) Every modified file in full. 3) A table: feature name → file/line where checkFeature was added. 4) The manifest/gradle changes. 5) Short explanation of anything you could not do and why.
````

---

## D) Owner panel + Reseller panel (new)

Your old admin panel is now the **Owner Panel**. Same address and same password as before: `https://YOUR-SERVICE.onrender.com/admin/` (`/owner/` also works). Resellers get their own panel at `https://YOUR-SERVICE.onrender.com/panel/`. Both live on your Render URL (not on the Worker). The app login system was **not changed**: reseller keys are normal `SENSI_…` keys, and the app checks them exactly like your own keys.

### Owner: create a reseller
1. Owner Panel → **Resellers** tab → **+ New reseller**.
2. Enter a username, a password (a strong one is pre-filled) and the **key limit** (the total number of keys this reseller may ever make).
3. Press **Create**. You get a box with the panel address, username, password and **API key**. Copy it now and send it to the reseller. Passwords and API keys are stored hashed, so they can't be shown again (you can always make new ones).

### Owner: control a reseller (each reseller card)
| Button | What it does |
|---|---|
| **View keys** | all keys this reseller made, with status |
| **Block API** / **Enable API** | stops (or restores) key fetching. The reseller's panel buttons and their API both stop, they can still sign in and see their keys |
| **Block account** / **Unblock** | locks the whole account. They are signed out immediately and the API stops |
| **Settings → Key limit** | change the total key limit, then **Save settings**. Raising it gives them more keys |
| **Reset usage to 0** | gives them the full limit again |
| **New password** / **New API key** | the old password or key stops working immediately |
| **Revoke all their keys** | every key they made stops working in the app |
| **Delete reseller** | removes the account (their keys stay valid unless you revoke them first) |

Every reseller action (login, keys made, via panel or API) is written to the **Activity log** with the reseller's name.

### Reseller: the SENSI MACRO panel
1. Open `/panel/` → sign in with username + password.
2. Top shows **keys left** and a meter of the limit.
3. Choose how many keys per tap (1, 5, 10, 25), optionally type the customer's name, then tap **Get key** on the row for **1 day … 7 days**. The keys appear in a terminal box with Copy buttons.
4. **My keys** tab lists everything they made. **API** tab shows their API key info and ready-to-copy examples.
5. Keys are 1 device each. The validity timer starts at the customer's first login in the app (same as your own keys).

### Reseller: the key-fetch API
Send the API key in the `X-Api-Key` header (never in the URL). Days must be 1 to 7, up to 50 keys per request, 60 requests per minute.
```
# get 3 keys valid for 5 days
curl -X POST https://YOUR-SERVICE.onrender.com/api/v1/keys \
  -H "X-Api-Key: srtx.USERNAME.xxxxxxxx" -H "Content-Type: application/json" \
  -d '{"days":5,"count":3,"label":"Aman"}'

# limit + usage
curl https://YOUR-SERVICE.onrender.com/api/v1/me -H "X-Api-Key: srtx.USERNAME.xxxxxxxx"

# list their keys
curl https://YOUR-SERVICE.onrender.com/api/v1/keys -H "X-Api-Key: srtx.USERNAME.xxxxxxxx"
```
Answers: `201 {"success":true,"keys":[…],"keysLeft":N}`. Errors: `401` bad key, `403` limit reached / API blocked / account blocked, `400` bad days.

### Notes
- The limit is checked inside the database, so even 100 requests at once can never go over it.
- 5 wrong passwords lock that username for 15 minutes.
- No new Render settings are needed. The reseller panel uses your existing `ADMIN_PASS` / `SESSION_SECRET` for cookie signing. Because it re-reads the account on every request, blocking takes effect instantly.
- Test list: create a reseller with limit 3, get 3 keys, the 4th must fail; press **Block API**, the day buttons lock; log a key into the app, it must log in normally.

---

## Test list (do all of these once)

| Test | Expected |
|---|---|
| Good key, normal use | login OK, features switch ON normally |
| Wrong key | red error on login screen, no crash |
| Admin turns a feature OFF in panel → toggle it in app | "This feature is disabled" |
| Admin **revokes** the key while app is open | app crashes within ≤10 min (or instantly on the next feature toggle) |
| Same key logged in on a second phone/session | older session crashes (`SESSION_REPLACED`) |
| Turn off internet for 16+ min with app open | app crashes (local watchdog) |
| Admin **revokes/deletes the key** while the app is open and you block your phone's internet to the server | within ~8 min the **push** force-closes the app (Firebase push still arrives) |
| Phone clock set 1 hour wrong | "set automatic time" dialog, no crash |
| Pretend server (hosts file / mock) | "not officially launched… cracked app" + exit |
| Admin sets Gate → patch / maintenance | existing patch / maintenance screen |
| Release order | 1) deploy server+worker 2) ship new APK 3) admin → Gate → `minVersionCode` = new version so old APKs get the patch screen |

## Admin notes

- **Kill a user:** revoke or delete the key in admin → their next feature toggle, or the server's 8-minute check (push), closes the app — whichever comes first.
- Push needs the user's phone to have Google Play services and internet. Pushes are only sent for sessions that died in the last 30 min (so closed apps aren't woken).
- Idle time before a session dies: `SESSION_IDLE_MIN` (default 13). Keep it **greater than** the heartbeat (10 min).
- New Firestore collection `app_sessions` is created automatically; expired sessions are deleted after 24 h. Keys get two extra fields (`activeSid`, `activeSidAt`) — harmless.
- Cost: with 10-minute heartbeats Firestore and Worker usage stays well inside free limits for normal user counts.

## Honest limits (so you know what this does and doesn't do)

- ✅ Stops: fake logins, mock/redirected servers, replayed or edited requests, sharing one key across devices, using a revoked/expired key, blocking the server to keep running (watchdog), direct hits on Render, scanners at the edge.
- ⚠️ A cracker can also patch out the push handler or block Google services; the 10-minute heartbeat + local watchdog + per-feature server check are the other layers, so all of them have to be defeated together.
- ⚠️ A determined cracker with the APK can still patch the app's own code (e.g. delete the checks) — no server can stop that for code that runs on the phone. What this does is make it hard and noisy: every feature needs a signed server answer, answers can't be forged, and the logic you keep **on the server** (cosmetics, names, assets, feature flags — and anything valuable you move there) never reaches a cracked copy. For more protection, move more real data/values the features need into the signed server answers.
- HWID is still the Android ID your app already sends (can be spoofed on rooted phones). Changing it would unbind existing keys, so it was left as is.
