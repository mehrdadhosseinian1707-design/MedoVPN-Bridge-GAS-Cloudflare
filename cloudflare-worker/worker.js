// Cloudflare Worker Endpoint

const WORKER_URL = "Your-Cloudflare-worker-address";

const DEFAULT_UPSTREAM_TIMEOUT_MS = 25000;

const REQUEST_HOP_BY_HOP_HEADERS = new Set([
    "host", "connection", "content-length", "transfer-encoding",
    "proxy-connection", "proxy-authorization", "x-relay-hop", "x-fwd-hop"
]);

const RESPONSE_HOP_BY_HOP_HEADERS = new Set([
    "connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "te", "trailer", "transfer-encoding", "upgrade"
]);

// FIX: WORKER_URL may be configured as a bare hostname OR a full URL
// (e.g. copy-pasted from code.gs, which needs a full URL). Normalize it
// once so hostname comparisons below work either way instead of silently
// never matching.
function _workerHostname() {
    try {
        return new URL(WORKER_URL).hostname;
    } catch (_) {
        return WORKER_URL; // already a bare hostname
    }
}

export default {
    async fetch(request, env) {
        try {
            const hop = request.headers.get("x-relay-hop");
            const fwdHop = request.headers.get("x-fwd-hop");
            if (hop === "1" || fwdHop === "1") {
                return json({ e: "loop detected" }, 508);
            }

            if (request.method == "GET") {
                const actualHost = new URL(request.url).hostname;
                return new Response(getHTML(actualHost), {
                    status: 200,
                    headers: { "content-type": "text/html; charset=utf-8" }
                });
            }

            if (request.method !== "POST") {
                return json({ e: "Method not allowed." }, 405);
            }

            const req = await request.json();

            if (!req.u) {
                return json({ e: "missing url" }, 400);
            }

            const targetUrl = new URL(req.u);

            const workerHostname = _workerHostname();
            const BLOCKED_HOSTS = [
                workerHostname,
            ];

            if (BLOCKED_HOSTS.some(h => targetUrl.hostname.endsWith(h))) {
                return json({ e: "self-fetch blocked" }, 400);
            }

            const headers = buildRequestHeaders(req.h);
            // Keep byte ranges uncompressed where possible; decode supported
            // encodings before placing the body inside the JSON envelope.
            headers.set("accept-encoding", "identity");

            // FIX: set the loop-guard marker BEFORE branching into the
            // upstream-forward path, not just before the direct fetch path.
            // Previously a request forwarded to UPSTREAM_FORWARDER_URL carried
            // no x-relay-hop marker at all, so if that forwarder ever called
            // back into this same worker, the loop check at the top of this
            // function would never trip.
            headers.set("x-relay-hop", "1");

            const upstreamUrl = (env && env.UPSTREAM_FORWARDER_URL) || "";
            if (upstreamUrl) {
                // FIX: x-fwd-hop was checked at the top of fetch() but never
                // actually set anywhere, making that half of the loop guard
                // dead code. Set it here so a request that went out through
                // the upstream forwarder is distinguishable if it loops back.
                const upstreamHeaders = Object.fromEntries(headers.entries());
                upstreamHeaders["x-fwd-hop"] = "1";
                const upstreamReq = { ...req, h: upstreamHeaders };
                const upstreamResp = await forwardViaUpstream(upstreamReq, env, upstreamUrl, workerHostname);
                if (upstreamResp) return upstreamResp;
                // fall through to direct fetch only when fail-mode is open
            }

            const fetchOptions = {
                method: (req.m || "GET").toUpperCase(),
                headers,
                redirect: req.r === false ? "manual" : "follow"
            };

            if (req.b) {
                const binary = Uint8Array.from(atob(req.b), c => c.charCodeAt(0));
                fetchOptions.body = binary;
            }

            const resp = await fetch(targetUrl.toString(), fetchOptions);

            const uint8 = await readResponseBytes(resp);
            const base64 = bytesToBase64(uint8);

            const responseHeaders = {};
            resp.headers.forEach((v, k) => {
                const lower = k.toLowerCase();
                if (RESPONSE_HOP_BY_HOP_HEADERS.has(lower) ||
                    lower === "content-length" || lower === "content-encoding") {
                    return;
                }
                responseHeaders[lower] = v;
            });

            return json({
                s: resp.status,
                h: responseHeaders,
                b: base64
            });

        } catch (err) {
            return json({ e: String(err) }, 500);
        }
    }
};

function buildRequestHeaders(input) {
    const headers = new Headers();
    if (input && typeof input === "object") {
        for (const [key, value] of Object.entries(input)) {
            if (!REQUEST_HOP_BY_HOP_HEADERS.has(key.toLowerCase())) {
                headers.set(key, String(value));
            }
        }
    }
    return headers;
}

async function readResponseBytes(resp) {
    if (!resp.body) return new Uint8Array(0);

    let body = resp.body;
    const encodings = (resp.headers.get("content-encoding") || "")
        .split(",")
        .map(value => value.trim().toLowerCase())
        .filter(value => value && value !== "identity")
        .reverse();

    for (const encoding of encodings) {
        if (encoding !== "gzip" && encoding !== "deflate") {
            throw new Error("unsupported upstream content-encoding: " + encoding);
        }
        if (typeof DecompressionStream === "undefined") {
            throw new Error("DecompressionStream is unavailable for " + encoding);
        }
        body = body.pipeThrough(new DecompressionStream(encoding));
    }

    return new Uint8Array(await new Response(body).arrayBuffer());
}

function bytesToBase64(bytes) {
    const parts = [];
    const chunkSize = 0x6000; // divisible by 3 so chunks concatenate cleanly

    for (let offset = 0; offset < bytes.length; offset += chunkSize) {
        const chunk = bytes.subarray(offset, Math.min(offset + chunkSize, bytes.length));
        let binary = "";
        for (let i = 0; i < chunk.length; i += 0x6000) {
            binary += String.fromCharCode.apply(null, chunk.subarray(i, Math.min(i + 0x6000, chunk.length)));
        }
        parts.push(btoa(binary));
    }

    return parts.join("");
}

async function forwardViaUpstream(req, env, upstreamUrl, workerHostname) {
    const failMode = (env.UPSTREAM_FAIL_MODE || "closed").toLowerCase();
    const timeoutMs = parseInt(env.UPSTREAM_TIMEOUT_MS, 10) || DEFAULT_UPSTREAM_TIMEOUT_MS;
    const authKey = env.UPSTREAM_AUTH_KEY || "";

    let parsed;
    try {
        parsed = new URL(upstreamUrl);
    } catch (_) {
        return upstreamFailure("invalid UPSTREAM_FORWARDER_URL", failMode);
    }
    if (parsed.protocol !== "https:") {
        return upstreamFailure("UPSTREAM_FORWARDER_URL must be https://", failMode);
    }
    // FIX: compare against the normalized worker hostname (no scheme),
    // matching the same fix applied to the direct self-fetch check above.
    if (parsed.hostname.endsWith(workerHostname)) {
        return upstreamFailure("self-forward blocked", failMode);
    }
    if (!authKey) {
        return upstreamFailure("UPSTREAM_AUTH_KEY missing", failMode);
    }

    const payload = {
        u: req.u,
        m: req.m,
        h: req.h,
        b: req.b,
        ct: req.ct,
        r: req.r
    };

    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);

    try {
        const resp = await fetch(upstreamUrl, {
            method: "POST",
            headers: {
                "content-type": "application/json",
                "x-upstream-auth": authKey
            },
            body: JSON.stringify(payload),
            signal: controller.signal
        });

        if (!resp.ok) {
            return upstreamFailure("forwarder status " + resp.status, failMode);
        }

        // Pass body straight through without parsing — saves CPU and memory.
        const body = await resp.text();
        return new Response(body, {
            status: 200,
            headers: { "content-type": "application/json" }
        });
    } catch (err) {
        return upstreamFailure(String(err && err.message || err), failMode);
    } finally {
        clearTimeout(timer);
    }
}

function upstreamFailure(reason, failMode) {
    if (failMode === "open") {
        console.warn("upstream forwarder failed (falling back to direct):", reason);
        return null; // signals caller to fall through to direct fetch
    }
    return json({ e: "upstream forwarder failed: " + reason }, 502);
}

function json(obj, status = 200) {
    return new Response(JSON.stringify(obj), {
        status,
        headers: {
            "content-type": "application/json"
        }
    });
}

function getHTML(actualHost) {
    const expectedHost = WORKER_URL;
    const hostMismatch = actualHost && expectedHost && actualHost !== expectedHost;
    return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Secure Endpoint</title>
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Inter', 'Roboto', sans-serif;
    background: #0a0e27;
    min-height: 100vh;
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 20px;
    overflow: hidden;
    position: relative;
  }
  body::before {
    content: '';
    position: absolute;
    width: 300px;
    height: 300px;
    background: radial-gradient(circle, rgba(16, 185, 129, 0.15) 0%, transparent 70%);
    top: -100px;
    right: -100px;
    border-radius: 50%;
    animation: float 8s ease-in-out infinite;
  }
  body::after {
    content: '';
    position: absolute;
    width: 400px;
    height: 400px;
    background: radial-gradient(circle, rgba(59, 130, 246, 0.1) 0%, transparent 70%);
    bottom: -150px;
    left: -150px;
    border-radius: 50%;
    animation: float 10s ease-in-out infinite reverse;
  }
  @keyframes float {
    0%, 100% { transform: translateY(0px) scale(1); }
    50% { transform: translateY(-20px) scale(1.05); }
  }
  .card {
    background: rgba(15, 23, 42, 0.8);
    backdrop-filter: blur(20px);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 16px;
    padding: 50px 40px;
    max-width: 480px;
    width: 100%;
    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.5);
    position: relative;
    z-index: 10;
  }
  .icon-wrapper {
    width: 64px;
    height: 64px;
    margin: 0 auto 24px;
    background: linear-gradient(135deg, #10b981 0%, #059669 100%);
    border-radius: 12px;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 8px 24px rgba(16, 185, 129, 0.3);
  }
  .icon {
    width: 32px;
    height: 32px;
    border: 3px solid #fff;
    border-radius: 8px;
    position: relative;
    animation: pulse 2s cubic-bezier(0.4, 0, 0.6, 1) infinite;
  }
  .icon::before {
    content: '';
    position: absolute;
    width: 8px;
    height: 8px;
    background: #fff;
    border-radius: 50%;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
  }
  @keyframes pulse {
    0%, 100% { transform: scale(1); opacity: 1; }
    50% { transform: scale(1.1); opacity: 0.8; }
  }
  h1 {
    font-size: 28px;
    font-weight: 700;
    color: #f8fafc;
    text-align: center;
    margin-bottom: 8px;
    letter-spacing: -0.5px;
  }
  .desc {
    font-size: 15px;
    color: #94a3b8;
    text-align: center;
    margin-bottom: 32px;
  }
  .status-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px 20px;
    background: rgba(16, 185, 129, 0.1);
    border: 1px solid rgba(16, 185, 129, 0.2);
    border-radius: 10px;
    margin-bottom: 16px;
  }
  .status-label {
    font-size: 14px;
    color: #cbd5e1;
    font-weight: 500;
  }
  .status-value {
    display: flex;
    align-items: center;
    gap: 8px;
    font-size: 14px;
    color: #10b981;
    font-weight: 600;
  }
  .indicator {
    width: 8px;
    height: 8px;
    background: #10b981;
    border-radius: 50%;
    animation: glow 2s ease-in-out infinite;
  }
  @keyframes glow {
    0%, 100% { box-shadow: 0 0 8px #10b981; }
    50% { box-shadow: 0 0 16px #10b981, 0 0 24px rgba(16, 185, 129, 0.5); }
  }
  .info-grid {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
    margin-top: 16px;
  }
  .info-item {
    padding: 12px;
    background: rgba(255, 255, 255, 0.02);
    border: 1px solid rgba(255, 255, 255, 0.05);
    border-radius: 8px;
    text-align: center;
  }
  .info-label {
    font-size: 11px;
    color: #64748b;
    text-transform: uppercase;
    letter-spacing: 0.5px;
    margin-bottom: 4px;
  }
  .info-value {
    font-size: 13px;
    color: #e2e8f0;
    font-weight: 600;
  }
  .alert {
    background: rgba(239, 68, 68, 0.1);
    border: 1px solid rgba(239, 68, 68, 0.3);
    border-radius: 10px;
    padding: 16px;
    margin-top: 20px;
  }
  .alert-title {
    font-size: 14px;
    color: #fca5a5;
    font-weight: 600;
    margin-bottom: 8px;
    display: flex;
    align-items: center;
    gap: 6px;
  }
  .alert-text {
    font-size: 12px;
    color: #fecaca;
    line-height: 1.5;
    word-break: break-all;
  }
  .footer {
    text-align: center;
    margin-top: 24px;
    font-size: 12px;
    color: #475569;
  }
</style>
</head>
<body>
  <div class="card">
    <div class="icon-wrapper">
      <div class="icon"></div>
    </div>
    <h1>MedoVPN Service</h1>
    <div class="desc">Secure Connection Gateway</div>
    <div class="status-row">
      <span class="status-label">Service Status</span>
      <span class="status-value">
        <span class="indicator"></span>
        ONLINE
      </span>
    </div>
    <div class="info-grid">
      <div class="info-item">
        <div class="info-label">Type</div>
        <div class="info-value">Endpoint</div>
      </div>
      <div class="info-item">
        <div class="info-label">Protocol</div>
        <div class="info-value">HTTPS</div>
      </div>
    </div>
    ${hostMismatch ? `
    <div class="alert">
      <div class="alert-title">
        <span>⚠</span>
        Configuration Warning
      </div>
      <div class="alert-text">
        Worker hostname mismatch detected<br>
        Current: ${actualHost}<br>
        Expected: ${expectedHost}
      </div>
    </div>` : ''}
    <div class="footer">Worker endpoint is operational</div>
  </div>
</body>
</html>`;
}
