# 🔑 SRT X CHEATS — Key System

A full-stack license key generation system with ad monetization via URL King.

---

## 📁 File Structure

```
key-system/
├── server.js          ← Node.js Express backend
├── package.json
├── data/
│   ├── keys.json      ← auto-created
│   └── sessions.json  ← auto-created
└── public/
    ├── index.html     ← User-facing key generator
    └── admin.html     ← Admin panel
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

## 🔗 How Key Generation Works

1. User clicks **"CREATE NEW KEY"** on the frontend
2. Frontend calls `POST /api/init-key-request` → gets URL King redirect URL
3. User is sent to URL King ad page
4. After completing the ad, URL King redirects to `/api/ad-callback?session=XXX`
5. Backend generates a key (`SRT_XXXXXXXX`) and stores it
6. User lands back on the site with their key displayed

---

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

## 🔐 Admin Panel

Visit `/admin.html` → login with your `ADMIN_PASS`.

### Features:
- **Stats dashboard** — total/active/expired/maxed keys
- **Create custom key** — set custom value, duration, login limit, label
- **Key list** — search, filter by status, copy, edit, delete
- **Edit any key** — change expiry, login limit, reset login count, unlock HWID, add labels

---

## 🔑 Key Format

Auto-generated keys: `SRT_` + 8 random uppercase alphanumeric chars
Example: `SRT_A2BK9QM7`

Characters used: `ABCDEFGHJKLMNPQRSTUVWXYZ23456789`
(No I, O, 0, 1 to avoid confusion)

---

## ⚠️ Important Notes

1. **Change your admin password** before deploying!
2. The `data/` folder stores all keys — back it up regularly
3. URL King's `/st` endpoint doesn't provide cryptographic proof of ad completion — the system trusts the redirect. This is standard for URL shortener monetization.
4. Set `SITE_URL` to your actual public domain so the URL King callback works correctly.
