# 🛡️ SRT X — Worker Guard (v4.4) — How to use

```
Android app ──► 5 Cloudflare Workers ──(HMAC)──► Render server ──► Firestore
   ▲                    │
   └── signed verdict ◄─┘   (RSA-SHA256, nonce + purpose bound; app holds only the PUBLIC key)
```

| # | Worker | Folder | When the app calls it | On failure the app must… |
|---|--------|--------|-----------------------|--------------------------|
| 1 | Login / key check | `workers/login` | login button | show message, only **[ Exit app ]** (`DIALOG_EXIT`) |
| 2 | App-open check | `workers/launch` | every app start, before any UI | **force crash** (`CRASH`) |
| 3 | Floating menu name | `workers/menu` | when menu is created + every heartbeat | **force crash** (`CRASH`) |
| 4 | Key/session expiry | `workers/heartbeat` | every 60 s while app runs | close menu, then close app (`CLOSE_MENU_AND_EXIT`) |
| 5 | Feature enable gate | `workers/feature` | user taps any feature on Home | message + only **[ Exit app ]** (`DIALOG_EXIT`) |

Other verdicts: `ALLOW` (continue), `FEATURE_OFF` (admin disabled it → toast), `RETRY` (server unreachable → app uses short offline grace, then locks).

## ⚡ QUICK SETUP (easiest way — 1 command makes ALL secrets)

1. Firebase → Project settings → Service accounts → **Generate new private key** → save as `firebase-key.json` in this folder.
2. Run (put your Render URL):
   ```bash
   node scripts/make-env.js firebase-key.json https://YOUR-APP.onrender.com
   ```
   It creates **`render.env`** (everything Render needs), **`workers/secrets.env`** (worker secrets), **`app-keys.txt`** (public key for the app + your admin password) and sets `SERVER_URL` in all 5 workers.
3. Render → your service → **Environment → Add from .env** → paste/upload `render.env` → Save, Deploy.
4. `cd workers && npx wrangler login && ./set-secrets.sh && ./deploy-all.sh` → copy the 5 URLs into `app-keys.txt`.
5. Use the AI Studio prompt below with the contents of `app-keys.txt`.

Never upload `render.env`, `secrets.env`, `app-keys.txt` or `firebase-key.json` to GitHub (`.gitignore` blocks them). Running the script again will NOT overwrite existing keys unless you add `--force`.
(The Render file intentionally has no `GUARD_PRIVATE_KEY`/`SESSION_SECRET`: only the Workers sign and need them, so a leak of Render alone cannot forge verdicts.)

---

## STEP 1 — Update the server (Render)
1. Replace your server files with this folder (new: `src/guardRoutes.js`; edited: `src/app.js`, `server.js`, `.env.example`).
2. Generate all secrets once:
   ```bash
   node scripts/gen-keys.js
   ```
   Save the output safely. Put `WORKER_SECRET` in **Render → Environment** (≥ 32 chars). Redeploy.
3. Check: `https://YOUR-RENDER-URL/health` → `{"status":"ok"}`.
4. Admin panel → **Stage 2 → Overlay name** is the menu name Worker 3 enforces (default `SENSI MACRO`).
5. New admin API: `GET /api/admin/login-activity` (last logins: time, country, masked key, result).

## STEP 2 — Deploy the 5 Workers (Cloudflare, free plan is fine)
```bash
cd workers
# put the output of gen-keys.js in workers/secrets.env  (WORKER_SECRET=, SESSION_SECRET=, GUARD_PRIVATE_KEY=)
npx wrangler login
# edit SERVER_URL in each workers/*/wrangler.toml to your Render URL
./set-secrets.sh      # pushes the 3 secrets to all 5 workers
./deploy-all.sh       # deploys all 5
```
You get 5 URLs like `https://srtx-login.YOURNAME.workers.dev`. **Delete `secrets.env` afterwards.**
All 5 workers must use the **same** `WORKER_SECRET`, `SESSION_SECRET`, `GUARD_PRIVATE_KEY`.

Test everything locally first (no Cloudflare needed): `node workers/test-workers.mjs` → `ALL PASSED`.

## STEP 3 — Request / response contract (for the app)
All 5: `POST <worker-url>` JSON. Always send `nonce` (random 16+ chars, `[A-Za-z0-9_-]`), plus `vc` (versionCode) and `cert` (APK signing SHA-256 hex).

| Worker | Extra body fields |
|---|---|
| login | `key`, `hwid` |
| launch | `token` (or stored `key` + `hwid`) |
| menu | `token`, `menuName` |
| heartbeat | `token` |
| feature | `token`, `feature` (e.g. `macroE`) |

Reply: `{ "payload": "<base64 JSON>", "sig": "<base64 RSA-SHA256>" }`.
Payload JSON: `p` purpose · `n` nonce · `ts` server ms · `a` action · `c` code · `m` message · `t` new token · `x` token expiry ms · `e` key expiresAt.
The app MUST verify: signature ✔ · `n` == nonce sent ✔ · `p` == worker called ✔ · `|now − ts| < 2 min` ✔. Anything else = treat as `CRASH`.

---

## STEP 4 — Google AI Studio prompt (copy everything in the box)

Upload your Android project zip (`v345`) to AI Studio, then paste:

````text
You are a senior Android (Kotlin, Compose, DataStore, OkHttp) engineer. In my existing project (package com.srtxcheats) implement a "Worker Guard" that talks to 5 Cloudflare Workers. Keep all existing features working; change only what is needed. Return full changed files.

=== CONFIG (BuildConfig / constants) ===
LOGIN_URL, LAUNCH_URL, MENU_URL, HEARTBEAT_URL, FEATURE_URL = my 5 worker URLs (placeholders: https://srtx-login.YOURNAME.workers.dev etc.; keep them Base64-obfuscated like OBFUSCATED_BASE_URL in KeyRepository).
GUARD_PUBLIC_KEY = Base64 X.509 RSA public key (placeholder, I will paste mine).
APP_CERT_SHA256 = computed at runtime from the app's signing certificate (PackageManager signing info, SHA-256, lowercase hex, no colons).
VERSION_CODE = BuildConfig.VERSION_CODE.

=== NEW FILE keySystem/WorkerGuard.kt ===
object WorkerGuard with:
- enum Action { ALLOW, CRASH, CLOSE_MENU_AND_EXIT, DIALOG_EXIT, FEATURE_OFF, RETRY }
- data class Verdict(action, code, message, token: String?, tokenExpMs: Long?, expiresAt: String?)
- suspend fun call(worker: Worker, body: JSONObject): Verdict  (Dispatchers.IO, OkHttp, 10 s timeout, POST application/json)
  * Always add: nonce = 24 random chars [A-Za-z0-9], vc, cert.
  * Response JSON {payload, sig}. Decode payload (Base64 DEFAULT) -> bytes. Verify sig with java.security.Signature "SHA256withRSA" and the embedded public key over the RAW payload bytes.
  * Then check: payload.n == nonce, payload.p == purpose ("login","launch","menu","heartbeat","feature"), abs(now - payload.ts) < 120000.
  * ANY failure (bad signature, nonce, purpose, time skew, malformed JSON, non-200 HTTP 4xx) -> Verdict(CRASH, "TAMPERED"). Network exception / timeout / HTTP 5xx -> Verdict(RETRY).
  * If payload.t != null store it as the in-memory session token (never on disk); use it for menu/heartbeat/feature calls.
- Offline grace: RETRY is tolerated for max 5 minutes since the last ALLOW (use SystemClock.elapsedRealtime). After that behave like CLOSE_MENU_AND_EXIT.
- fun enforce(v: Verdict, activity/service context) executes the action:
  * CRASH: call Process.killProcess + also throw an uncatchable-looking RuntimeException on the main thread (force crash). First stop OverlayService.
  * CLOSE_MENU_AND_EXIT: stop OverlayService (remove floating menu, stop macros/touch injection/zone relay), clearSession(), then finishAffinity() and Process.killProcess.
  * DIALOG_EXIT: show a non-cancelable dialog (setCancelable(false), no outside touch) with the message and EXACTLY ONE button "Exit app". Button -> same as CLOSE_MENU_AND_EXIT. No back-button dismiss, no other buttons.
  * FEATURE_OFF: Toast with message only.
  * ALLOW: nothing.
  Use a Handler on Looper.getMainLooper() so enforce() is safe from any thread. From OverlayService (no Activity) show the dialog with a TYPE_APPLICATION_OVERLAY system-alert window containing the same single "Exit app" button.

=== WIRING (do all 5) ===
1) LOGIN (LoginViewModel / KeyRepository.verifyKeyOnline): replace the old GET /api/verify-key with WorkerGuard.call(LOGIN, {key, hwid}). ALLOW -> save session (key, hwid, expiresAt from verdict.e) and LicenseGuard.onServerVerified(); any denial -> show verdict.message on the login screen in a dialog with ONLY "Exit app" button (DIALOG_EXIT). Keep existing UI/animation.
2) APP OPEN (MainActivity.onCreate, before setContent shows anything, and OverlayService.onCreate): call WorkerGuard.call(LAUNCH, {token or stored key+hwid}). If no stored key and no token -> verdict is CRASH -> enforce. Show the splash screen until the verdict arrives. ALLOW -> continue to home (or login if there is no stored key — in that case skip LAUNCH and go to the login page).
3) MENU NAME (OverlayService, when the floating menu view is created and again every heartbeat): read the name actually shown by the floating menu title (the same string used for the title text view) and send WorkerGuard.call(MENU, {token, menuName}). Wrong name / no session -> CRASH. Do NOT hard-code the expected name in the app: the worker compares it with the server value.
4) HEARTBEAT (OverlayService coroutine, every 60 s while the app or menu is alive; also in MainActivity while resumed): WorkerGuard.call(HEARTBEAT, {token}). ALLOW -> replace token. CLOSE_MENU_AND_EXIT -> enforce. Replace the old LicenseGuard 30 s loop with this, but keep LicenseGuard.isAuthorizedFast() as the cheap synchronous gate used by MacroTapExecutor and ZoneRelayEngine (set true on ALLOW for max 90 s, false on any denial).
5) FEATURE GATE (Home screen / MainDashboardScreen and OverlayService toggles): before enabling ANY feature (fullScreenSensi, sensiZone, macroE, macroG, aimMarker, gtFix, fps120, touchBoost, ramBooster) call WorkerGuard.call(FEATURE, {token, feature = "<featureName>"}) and only enable the feature on ALLOW. DIALOG_EXIT -> dialog with the message and ONLY "Exit app". FEATURE_OFF -> toast, feature stays off. RETRY -> do not enable, toast "Check your connection".

=== HARDENING ===
- Log nothing sensitive (use AppLogger.maskKey). Never log the token, nonce or signature.
- Keep all denial paths idempotent: if several workers deny at once, enforce once.
- Add proguard keep rules only if needed; do not add new permissions except SYSTEM_ALERT_WINDOW (already used).
- Add unit tests (JVM) for: valid signature accepted, tampered payload rejected, wrong nonce rejected, wrong purpose rejected, old timestamp rejected, RETRY grace expiry.
- At the end list every file changed and the exact places I must paste: the 5 worker URLs and GUARD_PUBLIC_KEY.
````

## STEP 5 — Paste your keys into the app
- Worker URLs → the 5 constants.
- `GUARD_PUBLIC_KEY=` line printed by `gen-keys.js` → the public-key constant.
- Release-sign your APK, then in Admin → **Security** add its SHA-256 certificate hash and turn on *Enforce certificate* (this is what makes "modified APK" fail every worker).

---

## 🔁 v4.4 — Device profile + automatic re-link after reinstall

**Why you had to reset keys:** your HWID is `ANDROID_ID`. On Android 8+ it **changes when the APK is signed with a different key** (debug vs release, a rebuilt/re-signed APK) or after a factory reset. So a reinstall looked like a new phone.

**What the server does now**
- Saves the phone profile with the key: device name, brand, model, codename, board, hardware, build ID, build fingerprint, **kernel**, Android version. Visible in Admin → key → *Manage* (Phone, Android/build, Kernel, Auto re-links).
- If the HWID changes but the profile is the **same phone** (all hardware fields equal **and** at least 2 of: build fingerprint, kernel, device name, Android version) → the key is **re-linked automatically**, no login slot is used, old HWID is kept in `hwidHistory`.
- Different phone → still blocked ("HWID mismatch").
- Limit: `AUTO_REBIND_MAX` (Render env, default **5** re-links per key, `0` = off). Admin **Reset device** clears the profile and the counter.
- Old keys have no profile yet: the profile is saved on the next successful login from the already-bound device. If one is already broken, press **Reset device** once.

**Trade-off (be aware):** two phones of the *same model with the same build/kernel* look identical to the server, so a user could move a key between them. The 5-re-link cap and the `login_activity` log limit this; lower `AUTO_REBIND_MAX` (e.g. 2) if you see abuse.

**Most important fix on the app side:** always release-sign every build with the **same keystore**. Then ANDROID_ID survives reinstalls and re-links are rarely needed.

### Add this to the Google AI Studio prompt (paste at the end of Step 4's prompt)

````text
=== DEVICE PROFILE (new) ===
In DeviceInfo.kt add fun getDeviceProfile(context): JSONObject with exactly these keys (strings):
 name  = Settings.Global.getString(resolver, "device_name") ?: Settings.Secure.getString(resolver, "bluetooth_name") ?: Build.MODEL
 manufacturer = Build.MANUFACTURER, brand = Build.BRAND, model = Build.MODEL, device = Build.DEVICE, board = Build.BOARD,
 hardware = Build.HARDWARE, product = Build.PRODUCT, buildId = Build.DISPLAY, fingerprint = Build.FINGERPRINT,
 kernel = System.getProperty("os.version") ?: "", release = Build.VERSION.RELEASE, sdk = Build.VERSION.SDK_INT.toString()
 (wrap every read in try/catch -> "" ; no permissions needed; do not read IMEI/serial.)
Send it as the "device" object in the LOGIN worker body: {key, hwid, device}. Also send it in the first LAUNCH call is NOT needed.
For the legacy GET /api/verify-key (if still used) append &dev=<Base64 URL-safe, no padding, of the JSON> (must be < 1000 chars).
Keep HWID = ANDROID_ID as today. Add a unit test that getDeviceProfile never throws and never returns null values.
Also add a note in code comments: always sign release builds with the same keystore.
````

---

## ⚠️ Honest limits (read once)
- Anything that runs on the phone can be edited by a determined cracker (they can delete the check calls from the APK). The Workers cannot stop that by themselves. What really protects you: (1) the existing **stage-2 assets/config are only served with a valid key** — keep your most valuable logic/data server-side; (2) certificate enforcement; (3) signed verdicts mean a fake server cannot say "ALLOW"; (4) short 10-minute sessions + 60 s heartbeat cut off shared/revoked keys fast.
- Add Cloudflare **Rate limiting rules** on the 5 worker routes (e.g. 30 req/min per IP) and keep Render `ADMIN_PASS` strong.
- Rotate `GUARD_PRIVATE_KEY` only together with an app update (the public key is baked into the APK).
