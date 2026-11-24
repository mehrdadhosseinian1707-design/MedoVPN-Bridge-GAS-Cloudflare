# 🛡️ MedoVPN Bridge

> **A resilient, two-tier censorship circumvention solution designed for high-censorship environments**

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-green.svg)]()
[![Status](https://img.shields.io/badge/Status-Production-brightgreen.svg)]()

## 📋 Overview

**MedoVPN Bridge** is a sophisticated anti-censorship tool designed specifically for environments with aggressive internet filtering and deep packet inspection (DPI). It employs a **two-relay architecture** using Google Apps Script as a bridge layer and Cloudflare Workers as the endpoint, making detection and blocking significantly more difficult.

### Why Two Relays?

In highly restrictive networks, single-hop proxies are often detected and blocked. MedoVPN Bridge adds an additional layer:

```
Browser → Local Client → Google Apps Script → Cloudflare Worker → Target Website
```

This architecture provides:
- ✅ **Enhanced Anonymity** - Your traffic passes through two independent services
- ✅ **DPI Resistance** - Traffic patterns are harder to fingerprint
- ✅ **Redundancy** - If one layer is blocked, you can switch configurations
- ✅ **Free Infrastructure** - Leverages Google and Cloudflare's free tiers

---

## 🌟 Key Features

### 🔐 Security & Privacy
- **HTTPS MITM Inspection** with locally-trusted CA certificates
- **Domain fronting** capabilities through major CDN providers
- **TLS fragmentation** to bypass SNI-based blocking
- **No logging** - all processing happens client-side

### 🚀 Performance
- **Batch request optimization** for improved throughput
- **Automatic retry** with exponential backoff
- **Connection pooling** and reuse
- **Hedge requests** for latency-sensitive operations

### 🎯 Reliability
- **Health monitoring** with automatic failover
- **Graceful degradation** when relays are unavailable
- **Comprehensive error handling** and recovery
- **DNS over HTTPS** (DoH) support

### 💻 User Experience
- **Local web GUI** for easy configuration
- **System tray integration** (Windows)
- **Real-time connection statistics**
- **One-click certificate installation**

---

## 🎯 Who Should Use MedoVPN Bridge?

### ✅ Perfect For:
- **High-censorship countries** (China, Iran, Turkmenistan, etc.)
- **Aggressive DPI environments** where single-hop proxies are blocked
- **Maximum anonymity needs** - traffic goes through 2 independent providers
- **Journalists and activists** in restrictive regions
- **Redundancy requirements** - fallback if Cloudflare is blocked

### ⚠️ Consider Direct Mode Instead If:
- You need **lower latency** (< 300ms)
- You want to **stream video** without buffering
- Your region has **moderate censorship** (single-hop works)
- You prefer **simpler setup** (one less component)

---

## 🏗️ Architecture

### Components

#### 1. **Desktop Client** (`client/medovpn-bridge.go`)
Local HTTP/HTTPS proxy that:
- Intercepts browser traffic on `127.0.0.1:5555`
- Terminates HTTPS with a local CA certificate
- Encodes requests as JSON and forwards to Google Apps Script

#### 2. **Google Apps Script Bridge** (`google-apps-script/code.gs`)
Middleware relay that:
- Receives JSON-encoded requests from the client
- Forwards them to the Cloudflare Worker
- Returns responses back to the client
- Provides batch request optimization

#### 3. **Cloudflare Worker Endpoint** (`cloudflare-worker/worker.js`)
Final relay that:
- Performs actual HTTP requests to target websites
- Handles response encoding and compression
- Implements loop detection and security measures
- Serves a decoy website for GET requests

---

## 📦 Installation

### Prerequisites
- **Windows 10/11** or **Linux** (kernel 3.2+)
- Administrator/root access (for certificate installation)

### Quick Start

#### Option 1: Pre-built Binaries

1. **Download** the latest release from the [Releases](../../releases) page:
   - Windows: `medovpn-bridge-windows-amd64.exe`
   - Linux: `medovpn-bridge-linux-amd64`
   - Debian/Ubuntu: `medovpn-bridge_amd64.deb`

2. **Run** the application:
   ```bash
   # Windows
   .\medovpn-bridge-windows-amd64.exe
   
   # Linux
   chmod +x medovpn-bridge-linux-amd64
   ./medovpn-bridge-linux-amd64
   ```

3. **Configure** through the web GUI that opens automatically at `http://127.0.0.1:5560`

#### Option 2: Build from Source

```bash
# Clone the repository
git clone https://github.com/YOUR_USERNAME/MedoVPN-Bridge.git
cd MedoVPN-Bridge/client

# Build for your platform
go build -o medovpn-bridge medovpn-bridge.go

# Run
./medovpn-bridge
```

---

## ⚙️ Setup Guide

### Step 1: Deploy Google Apps Script

1. Go to [Google Apps Script](https://script.google.com/)
2. Create a **New Project**
3. Copy the entire contents of `google-apps-script/code.gs`
4. Paste into the script editor
5. **Edit line 3**: Set your password in `AUTH_KEY`
6. **Edit line 4**: Set your Cloudflare Worker URL in `WORKER_URL`
7. Click **Deploy** → **New Deployment**
8. Choose **Web app**
9. Set access to **Anyone**
10. Copy the deployment URL

### Step 2: Deploy Cloudflare Worker

1. Log in to [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. Go to **Workers & Pages**
3. Click **Create Application** → **Create Worker**
4. Name it (e.g., `medo-endpoint`)
5. Click **Quick Edit**
6. Copy the entire contents of `cloudflare-worker/worker.js`
7. Paste into the editor
8. **Edit line 3**: Set your worker domain in `WORKER_URL`
9. Click **Save and Deploy**
10. Copy the worker URL (e.g., `https://medo-endpoint.yourname.workers.dev`)

### Step 3: Configure Client

1. **Open the GUI**: The application opens `http://127.0.0.1:5560` automatically
2. **Enter the Google Apps Script URL** you copied in Step 1
3. **Enter the AUTH_KEY password** you set in Step 1
4. **Install the CA certificate** (click the button in the GUI)
5. **Start the proxy**

### Step 4: Configure Your Browser

#### Firefox (Recommended)
1. Settings → Network Settings → **Manual proxy configuration**
2. HTTP Proxy: `127.0.0.1` Port: `5555`
3. ✅ Check "Also use this proxy for HTTPS"

#### Chrome
1. Install [Proxy SwitchyOmega](https://chrome.google.com/webstore/detail/proxy-switchyomega/)
2. Create a new profile with HTTP proxy `127.0.0.1:5555`
3. Enable the profile

---

## 🔧 Configuration

### Environment Variables

```bash
# Google Apps Script URL (required)
export GAS_SCRIPT_URL="https://script.google.com/macros/s/YOUR_SCRIPT_ID/exec"

# Authentication key (required)
export GAS_AUTH_KEY="your-secure-password"

# Local proxy address (optional, default: 127.0.0.1:5555)
export LISTEN_ADDR="127.0.0.1:5555"

# GUI address (optional, default: 127.0.0.1:5560)
export GUI_LISTEN_ADDR="127.0.0.1:5560"

# CA certificate paths (optional)
export CA_CERT_FILE="/path/to/mycert.crt"
export CA_KEY_FILE="/path/to/mycert.key"
```

### Command-line Flags

```bash
./medovpn-bridge \
  --listen "127.0.0.1:5555" \
  --gui-listen "127.0.0.1:5560" \
  --ca-cert "/path/to/cert.crt" \
  --ca-key "/path/to/key.key" \
  --no-open  # Don't open GUI in browser
```

---

## 🛠️ Advanced Usage

### DNS over HTTPS (DoH)

Enable DoH in the GUI to prevent DNS-based blocking:
- Cloudflare: `https://1.1.1.1/dns-query`
- Google: `https://dns.google/dns-query`

### TLS Fragmentation

Enable ClientHello fragmentation to bypass SNI inspection:
1. Open GUI → Settings
2. Enable "Fragment TLS ClientHello"
3. Adjust fragment size (default: 64 bytes)

### Connection Rotation

Rotate worker connections to avoid pattern detection:
1. Open GUI → Settings
2. Enable "Rotate connections"
3. Set max connection age (default: 5 minutes)

---

## 🔒 Security & Privacy

### Multi-Layer Protection

**Layer 1: Client → Google Apps Script**
- TLS 1.3 encrypted connection
- Authentication with AUTH_KEY
- Request payload is JSON-encoded

**Layer 2: Google Apps Script → Cloudflare Worker**
- TLS 1.3 encrypted connection
- Independent from first hop
- Cloudflare cannot trace back to your IP

**Layer 3: Cloudflare Worker → Target Website**
- Standard HTTPS (if target supports it)
- Cloudflare's IP is visible to target
- Your IP is completely hidden

### Threat Model

**What MedoVPN Bridge Protects Against:**
- ✅ Advanced DPI (Deep Packet Inspection)
- ✅ SNI-based censorship
- ✅ DNS-based blocking
- ✅ IP-based blocking
- ✅ Traffic pattern analysis
- ✅ Single-point-of-failure blocking

**Additional Benefits Over Direct Mode:**
- Two hops = harder to correlate traffic
- If Cloudflare is blocked, only GAS needs to work
- Google Apps Script is rarely blocked (business-critical)

**What It Does NOT Protect Against:**
- ❌ Compromise of either Google or Cloudflare
- ❌ Client-side malware
- ❌ Endpoint surveillance
- ❌ Targeted nation-state attacks with full MITM capability

### Privacy Considerations

**Who Can See What:**

| Party | Can See |
|-------|---------|
| **Your ISP** | You're connecting to Google Apps Script (looks like normal Google API usage) |
| **Google** | Encrypted requests to Cloudflare Worker, but not the final destination |
| **Cloudflare** | Final destination URLs, but NOT your IP (sees Google's IP) |
| **Target Website** | Cloudflare's IP, not yours |

### Best Practices

1. **Use strong AUTH_KEY**: Minimum 20 random characters
2. **Enable DoH**: Prevents DNS leaks
3. **Rotate credentials**: Change AUTH_KEY every 2-3 months
4. **Use TLS fragmentation**: Defeats SNI inspection
5. **Don't reuse passwords**: AUTH_KEY should be unique
6. **Verify HTTPS**: Only visit HTTPS sites for end-to-end encryption

---

## ❓ Frequently Asked Questions (FAQ)

### General Questions

**Q: Why use two relays instead of one?**  
A: Single-hop proxies are easier to detect and block. Two independent hops (Google + Cloudflare) make traffic correlation much harder.

**Q: Is this completely free?**  
A: Yes! Uses free tiers:
- Google Apps Script: 20,000 URL Fetch calls/day
- Cloudflare Workers: 100,000 requests/day

**Q: Which is more secure - Direct or Bridge?**  
A: Bridge is more censorship-resistant. Direct is faster but easier to block.

**Q: Can I trust Google and Cloudflare?**  
A: They see encrypted traffic but not content (if you use HTTPS sites). For high-risk scenarios, use Tor instead.

**Q: Is this legal?**  
A: Depends on your country. It's a privacy tool, but check local laws. The developers are not responsible for your use.

### Technical Questions

**Q: Why Google Apps Script specifically?**  
A: 
- Rarely blocked (businesses depend on it)
- Free tier is generous
- Trusted domain (google.com)
- Easy deployment

**Q: What if Google Apps Script gets blocked?**  
A: You can replace it with other relays: Azure Functions, AWS Lambda, or even another Cloudflare Worker.

**Q: Can I see the traffic between hops?**  
A: No, everything is TLS-encrypted. Even you can't decrypt it without compromising the services.

**Q: Does this protect against government surveillance?**  
A: Against passive surveillance (ISP logging), yes. Against active attacks (MITM with fake certificates), it depends on your threat model.

**Q: How is the certificate installation safe?**  
A: The certificate is generated locally on YOUR computer. It only works for YOUR browser. Nobody else can use it to intercept your traffic.

### Performance Questions

**Q: Why is Bridge slower than Direct?**  
A: One extra hop adds ~200-500ms latency. Google Apps Script processing time contributes most of the delay.

**Q: Can I improve performance?**  
A: Yes:
- Enable batch request optimization in GAS
- Use hedge requests
- Enable connection pooling
- Multiple worker endpoints

**Q: How many users can share one setup?**  
A: Google free tier allows 20,000 requests/day. Light browsing ≈ 1000 requests/day per user, so ~15-20 users.

**Q: What's the daily quota?**  
A: Bottleneck is Google Apps Script: 20,000 URL Fetch calls/day. For heavy users, upgrade to Google Workspace (~50,000/day).

### Troubleshooting Questions

**Q: I get "Loop detected" errors**  
A: Your WORKER_URL in code.gs points to wrong endpoint. It should point to Cloudflare Worker, not back to Google Apps Script.

**Q: "403 Forbidden" from Google Apps Script**  
A: AUTH_KEY mismatch. Verify password in code.gs matches client configuration exactly.

**Q: Certificate errors in browser**  
A: Certificate not installed or not trusted. Re-install from GUI and restart browser.

**Q: Slow performance or timeouts**  
A: Google Apps Script can be slow. Try:
- Redeploying the script
- Using multiple workers for load balancing
- Switching to Direct mode if GAS is the bottleneck

### Comparison Questions

**Q: Bridge vs Tor - which is better?**  
A:
- **Tor**: Better anonymity, often blocked, very slow
- **Bridge**: Better performance, harder to detect, less anonymous

**Q: Bridge vs VPN?**  
A:
- **VPN**: Faster, easier, but VPN providers can be blocked
- **Bridge**: Free, you control it, uses trusted infrastructure

**Q: Can I combine this with Tor?**  
A: Yes! Run Bridge → Tor for extreme privacy, but very slow.

---

## 📡 Monitoring & Maintenance

### Health Dashboard

Control panel at `http://127.0.0.1:5560` shows:

| Metric | Description | Target |
|--------|-------------|--------|
| **Latency** | Round-trip time (ms) | < 800ms |
| **Success Rate** | % of successful requests | > 90% |
| **GAS Quota** | Daily requests remaining | Monitor if heavy usage |
| **Worker Health** | Cloudflare endpoint status | "Healthy" |
| **Active Connections** | Current open connections | Varies |

### Quota Monitoring

**Google Apps Script Limits:**
- Free: 20,000 URL Fetch calls/day
- Workspace: ~50,000 URL Fetch calls/day

**Check Usage:**
1. Go to [Google Apps Script](https://script.google.com/)
2. Open your project
3. Left sidebar → "Executions"
4. See daily usage

**Warning Signs:**
- Success rate drops below 85%
- "Service invoked too many times" errors
- Blank responses

**Solutions:**
- Upgrade to Google Workspace
- Deploy multiple GAS instances and load-balance
- Switch to Direct mode for heavy usage

### Maintenance Tasks

**Weekly:**
- Check control panel metrics
- Verify certificate validity
- Review error logs (if enabled)

**Monthly:**
- Check GAS quota usage
- Rotate AUTH_KEY password
- Update client to latest version
- Review Cloudflare Worker analytics

**Quarterly:**
- Redeploy Google Apps Script (new version)
- Redeploy Cloudflare Worker
- Review and update evasion techniques

---

## 🌍 Deployment Scenarios

### Personal Use (Single User)

**Basic Setup:**
```
You
↓
Google Apps Script (1 instance)
↓
Cloudflare Worker (1 instance)
```

**Cost:** $0/month  
**Quota:** 20,000 requests/day  
**Suitable for:** Daily browsing, social media

---

### Family/Friends (5-10 Users)

**Shared Setup:**
```
Multiple Users
↓
Google Apps Script (1 instance, shared AUTH_KEY)
↓
Cloudflare Worker (1 instance)
```

**Cost:** $0/month  
**Quota:** 20,000 requests/day (shared)  
**Suitable for:** Light browsing, text content

**Setup:**
- Share GAS URL + AUTH_KEY securely (Signal, WhatsApp)
- Each user runs own client
- Monitor quota usage

---

### Organization (20+ Users)

**High-Availability Setup:**
```
Users
├── Load Balancer (client-side)
├── Google Apps Script #1 (AUTH_KEY_1)
├── Google Apps Script #2 (AUTH_KEY_2)
└── Google Apps Script #3 (AUTH_KEY_3)
     ↓
  Round-Robin
     ↓
├── Cloudflare Worker EU
├── Cloudflare Worker US
└── Cloudflare Worker Asia
```

**Cost:** $0 - $15/month (if using Workspace)  
**Quota:** 60,000+ requests/day  
**Suitable for:** Organizations, NGOs, news outlets

**Setup:**
1. Deploy 3+ GAS instances (different Google accounts)
2. Deploy 3+ Workers (different regions)
3. Configure client with all URLs
4. Enable automatic failover

---

### High-Risk Environment (Maximum Evasion)

**Hardened Setup:**
```
You
↓ (DoH enabled)
Google Apps Script (custom deployment)
↓
Cloudflare Worker (custom domain)
↓ (TLS fragmentation)
Target
```

**Additional Evasion:**
- Custom domain on Cloudflare (not *.workers.dev)
- TLS ClientHello fragmentation
- DNS over HTTPS (DoH)
- Connection rotation every 2 minutes
- Hedge requests enabled
- Multiple fallback GAS/Worker pairs

---

## 🔧 Advanced Configuration

### Custom Cloudflare Domain

**Why:** `*.workers.dev` can be fingerprinted. Custom domains look like normal traffic.

**Setup:**
1. Add domain to Cloudflare (free)
2. Worker → Triggers → Add Custom Domain
3. Use `api.yourdomain.com` or similar
4. Update WORKER_URL in code.gs

### Multiple Workers with Load Balancing

**Scenario:** Distribute load, increase reliability

**Google Apps Script Code:**
```javascript
const WORKERS = [
  "https://worker1.workers.dev",
  "https://worker2.workers.dev",
  "https://worker3.workers.dev"
];

function doPost(e) {
  // Round-robin or random selection
  const worker = WORKERS[Math.floor(Math.random() * WORKERS.length)];
  // ... rest of code
}
```

### Docker Deployment

**Dockerfile:**
```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY client/ .
RUN go build -o medovpn-bridge medovpn-bridge.go

FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/medovpn-bridge /usr/local/bin/
EXPOSE 5555 5560
CMD ["medovpn-bridge"]
```

**Run:**
```bash
docker build -t medovpn-bridge .
docker run -d \
  -p 5555:5555 \
  -p 5560:5560 \
  -e GAS_SCRIPT_URL="https://script.google.com/..." \
  -e GAS_AUTH_KEY="your-password" \
  medovpn-bridge
```

### Systemd Service (Linux)

**File:** `/etc/systemd/system/medovpn-bridge.service`

```ini
[Unit]
Description=MedoVPN Bridge Client
After=network.target

[Service]
Type=simple
User=your-username
Environment="GAS_SCRIPT_URL=https://script.google.com/..."
Environment="GAS_AUTH_KEY=your-password"
ExecStart=/usr/local/bin/medovpn-bridge
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**Enable:**
```bash
sudo systemctl daemon-reload
sudo systemctl enable medovpn-bridge
sudo systemctl start medovpn-bridge
```

### Windows Service with NSSM

```powershell
# Download NSSM: https://nssm.cc/
nssm install MedoVPNBridge "C:\path\to\medovpn-bridge.exe"
nssm set MedoVPNBridge AppDirectory "C:\path\to\"
nssm set MedoVPNBridge AppEnvironmentExtra GAS_SCRIPT_URL=https://... GAS_AUTH_KEY=password
nssm start MedoVPNBridge
```

---

## 🛡️ Hardening Guide

### For Maximum Censorship Resistance

**1. Obfuscate All Layers**
```bash
✅ Use custom domain for Worker
✅ Enable TLS fragmentation
✅ Enable DNS over HTTPS
✅ Rotate connections every 2-5 minutes
✅ Enable hedge requests
```

**2. Diversify Infrastructure**
```bash
✅ Multiple GAS instances (different accounts)
✅ Multiple Workers (different regions)
✅ Automatic failover between them
✅ Health monitoring with auto-switch
```

**3. Operational Security**
```bash
✅ Use strong random AUTH_KEY (30+ chars)
✅ Rotate credentials monthly
✅ Don't share credentials in cleartext
✅ Use Signal/WhatsApp for sharing
✅ Monitor for unusual activity
```

**4. Network-Level Evasion**
```bash
✅ Fragment TLS ClientHello (40-64 bytes)
✅ Add random delays (10-50ms)
✅ Vary User-Agent strings
✅ Randomize request timing
```

---

## 🔍 Troubleshooting

### "Certificate not trusted" errors
**Solution**: Re-install the CA certificate from the GUI. On Windows, it must be in "Trusted Root Certification Authorities"

### "Connection timeout" errors
**Solution**: 
1. Verify Google Apps Script and Cloudflare Worker are deployed correctly
2. Check the URLs in your configuration
3. Test worker health at `https://your-worker.workers.dev/health`

### Slow connection speeds
**Solution**:
1. Enable connection pooling in Settings
2. Reduce hedge request threshold
3. Consider using Direct mode (MedoVPN-Direct) if GAS is the bottleneck

### "Loop detected" errors
**Solution**: This indicates a misconfiguration. Ensure `WORKER_URL` in `code.gs` points to your Cloudflare Worker, not back to the Google Apps Script.

---

## 🌐 Use Cases

### For Individuals
- Access blocked websites and services
- Bypass geographic restrictions
- Protect privacy from ISP surveillance
- Maintain access during internet shutdowns

### For Organizations
- Secure communication for journalists and activists
- Emergency backup internet access
- Research in restricted environments
- Digital rights advocacy

---

## 📊 Performance Considerations

### Throughput
- **Typical latency**: 300-800ms (depends on GAS response time)
- **Max request size**: 10 MB (client limit)
- **Max response size**: 32 MB (before base64 encoding)
- **Concurrent connections**: Limited by browser (typically 6 per domain)

### Limitations
- Not suitable for video streaming (use MedoVPN-Direct instead)
- Google Apps Script has daily quotas (URL Fetch: 20,000 calls/day for free accounts)
- Base64 encoding adds ~33% overhead to response sizes

---

## 🤝 Contributing

We welcome contributions from the community! This project is vital for maintaining internet freedom in censored regions.

### How to Contribute
1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Areas for Improvement
- [ ] Support for more relay providers (Azure Functions, AWS Lambda)
- [ ] Mobile client (Android/iOS)
- [ ] Protocol obfuscation improvements
- [ ] Performance optimizations
- [ ] Documentation translations

---

## 📜 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## ⚠️ Disclaimer

This software is provided for **legitimate privacy and security purposes** in regions where internet access is restricted. Users are responsible for complying with local laws and regulations. The developers assume no liability for misuse.

---

## 🌍 Supporting Internet Freedom

This project is dedicated to those fighting for digital rights and freedom of information worldwide. If you're in a censored region, stay safe and stay connected.

### Resources
- [Digital Security Resources](https://www.eff.org/pages/digital-security)
- [Circumvention Tools](https://www.accessnow.org/help/)
- [Internet Shutdown Tracker](https://www.accessnow.org/keepiton/)

---

## 📞 Support

- **Issues**: [GitHub Issues](../../issues)
- **Discussions**: [GitHub Discussions](../../discussions)
- **Security**: Report vulnerabilities privately to [security contact]

---

<div align="center">

**Made with ❤️ for internet freedom**

⭐ Star this repo if it helps you stay connected

</div>
