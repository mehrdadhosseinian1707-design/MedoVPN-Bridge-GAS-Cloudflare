# 🚀 Quick Setup Guide

## Prerequisites
- Windows 10/11 or Linux
- Administrator/root access
- Google Account (for Apps Script)
- Cloudflare Account (free tier)

## 5-Minute Setup

### 1️⃣ Deploy Google Apps Script (2 minutes)

1. Visit https://script.google.com/
2. Click **"New Project"**
3. Copy everything from `google-apps-script/code.gs`
4. Paste into the editor
5. **Line 3**: Change `AUTH_KEY = "PUT_YOUR_PASSWORD_HERE"` to your own strong password
6. **Line 4**: You'll update `WORKER_URL` after Step 2
7. Click **Deploy** → **New Deployment** → **Web app**
8. **Execute as**: Me
9. **Who has access**: Anyone
10. Click **Deploy** and copy the URL

### 2️⃣ Deploy Cloudflare Worker (2 minutes)

1. Visit https://dash.cloudflare.com/
2. Go to **Workers & Pages** → **Create Application** → **Create Worker**
3. Name it (example: `medo-endpoint`)
4. Click **Quick Edit**
5. Copy everything from `cloudflare-worker/worker.js`
6. Paste into the editor (replace all existing code)
7. **Line 3**: Change `WORKER_URL = "Your-Cloudflare-worker-address"` to your worker URL
   (Example: `https://medo-endpoint.yourname.workers.dev`)
8. Click **Save and Deploy**
9. **Copy your worker URL**

### 3️⃣ Update Google Apps Script

1. Go back to your Google Apps Script project
2. **Line 4**: Update `WORKER_URL` with the Cloudflare worker URL you just copied
3. Click **Deploy** → **Manage Deployments** → **Edit** (pencil icon)
4. **Version**: New version
5. Click **Deploy**

### 4️⃣ Run the Client (1 minute)

#### Windows
1. Download `medovpn-bridge-windows-amd64.exe` from [Releases](../../releases)
2. Double-click to run
3. GUI opens automatically at http://127.0.0.1:5560

#### Linux
```bash
wget https://github.com/YOUR_USERNAME/MedoVPN-Bridge/releases/latest/download/medovpn-bridge-linux-amd64
chmod +x medovpn-bridge-linux-amd64
./medovpn-bridge-linux-amd64
```

### 5️⃣ Configure the Client

In the web GUI that opened:

1. **Google Apps Script URL**: Paste your GAS URL from Step 1
2. **Auth Key**: Enter the password you set in Step 1
3. Click **"Install CA Certificate"**
4. Click **"Start Proxy"**

### 6️⃣ Configure Your Browser

**Firefox:**
1. Settings → Network Settings → Manual proxy
2. HTTP Proxy: `127.0.0.1` Port: `5555`
3. ✅ Check "Also use this proxy for HTTPS"

**Chrome:**
1. Install [Proxy SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/)
2. New profile → HTTP proxy `127.0.0.1:5555`

## ✅ Test It

Visit https://www.google.com - if it loads, you're connected!

## 🔧 Troubleshooting

**"Certificate not trusted"**
- Re-run "Install CA Certificate" from the GUI
- Restart your browser

**"Connection timeout"**
- Verify both GAS and Worker are deployed
- Test worker health: `https://your-worker.workers.dev/` (should show a webpage)
- Check URLs in configuration

**Still having issues?**
- Check the [full README](README.md)
- Open an [issue](../../issues)

## 🎉 You're Done!

You now have a two-tier censorship-resistant proxy running. Stay safe!
