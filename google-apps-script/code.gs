// Google Apps Script Bridge

const AUTH_KEY = "PUT_YOUR_PASSWORD_HERE";
const WORKER_URL = "https://your.workers.dev";

const SKIP_HEADERS = {
  host: 1, connection: 1, "content-length": 1, "accept-encoding": 1,
  "transfer-encoding": 1, "proxy-connection": 1, "proxy-authorization": 1,
};

function doPost(e) {
  try {
    var req = JSON.parse(e.postData.contents);
    if (req.k !== AUTH_KEY) return _json({ e: "unauthorized" });

    if (Array.isArray(req.q)) return _doBatch(req.q);
    return _doSingle(req);

  } catch (err) {
    return _json({ e: String(err) });
  }
}

function _doSingle(req) {
  if (!req.u || typeof req.u !== "string" || !req.u.match(/^https?:\/\//i)) {
    return _json({ e: "bad url" });
  }

  try {
    var payload = _buildWorkerPayload(req);

    var resp = UrlFetchApp.fetch(WORKER_URL, {
      method: "post",
      contentType: "application/json",
      payload: JSON.stringify(payload),
      muteHttpExceptions: true,
      followRedirects: true
    });

    return _json(JSON.parse(resp.getContentText()));
  } catch (err) {
    return _json({ e: String(err) });
  }
}

function _doBatch(items) {
  var fetchArgs = [];
  var errorMap = {};

  for (var i = 0; i < items.length; i++) {
    var item = items[i];

    if (!item.u || typeof item.u !== "string" || !item.u.match(/^https?:\/\//i)) {
      errorMap[i] = "bad url";
      continue;
    }

    var payload = _buildWorkerPayload(item);

    fetchArgs.push({
      _i: i,
      _o: {
        url: WORKER_URL,
        method: "post",
        contentType: "application/json",
        payload: JSON.stringify(payload),
        muteHttpExceptions: true,
        followRedirects: true
      }
    });
  }

  // FIX: UrlFetchApp.fetchAll() throws for the WHOLE batch if any single
  // request hits a network-level failure (DNS error, unreachable host, etc).
  // muteHttpExceptions only suppresses non-2xx HTTP statuses, not that.
  // So we try the fast parallel path first, and if it throws, fall back to
  // fetching each item individually so one bad URL can't take down the rest.
  var responses;
  var perItemErrors = null;

  if (fetchArgs.length > 0) {
    try {
      responses = UrlFetchApp.fetchAll(fetchArgs.map(function(x) { return x._o; }));
    } catch (err) {
      responses = [];
      perItemErrors = {};
      for (var j = 0; j < fetchArgs.length; j++) {
        try {
          responses.push(UrlFetchApp.fetch(fetchArgs[j]._o.url, fetchArgs[j]._o));
        } catch (itemErr) {
          responses.push(null);
          perItemErrors[j] = String(itemErr);
        }
      }
    }
  } else {
    responses = [];
  }

  var results = [];
  var rIdx = 0;

  for (var i = 0; i < items.length; i++) {
    if (errorMap.hasOwnProperty(i)) {
      results.push({ e: errorMap[i] });
      continue;
    }

    if (perItemErrors && perItemErrors.hasOwnProperty(rIdx)) {
      results.push({ e: perItemErrors[rIdx] });
      rIdx++;
      continue;
    }

    var resp = responses[rIdx++];
    try {
      results.push(JSON.parse(resp.getContentText()));
    } catch (e) {
      results.push({ e: "invalid worker response", raw: resp ? resp.getContentText() : "" });
    }
  }

  return _json({ q: results });
}

function _buildWorkerPayload(req) {
  var headers = {};

  // FIX: normalize all header keys to lowercase on the way in, so a
  // differently-cased duplicate (e.g. "Accept-Encoding" alongside our own
  // forced-lowercase "accept-encoding") can never both end up in the object.
  if (req.h && typeof req.h === "object") {
    for (var k in req.h) {
      if (req.h.hasOwnProperty(k)) {
        var lowerKey = k.toLowerCase();
        if (!SKIP_HEADERS[lowerKey]) {
          headers[lowerKey] = req.h[k];
        }
      }
    }
  }

  // The local relay reconstructs response bodies from bytes; request identity
  // encoding to avoid unnecessary upstream compression and range mismatches.
  headers["accept-encoding"] = "identity";

  return {
    u: req.u,
    m: (req.m || "GET").toUpperCase(),
    h: headers,
    b: req.b || null,
    ct: req.ct || null,
    r: req.r !== false
  };
}

function doGet(e) {
  return HtmlService.createHtmlOutput(
    "<!DOCTYPE html><html><head><title>Gateway Service</title>" +
      "<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Arial',sans-serif;" +
      "background:#1a1a2e;color:#eee;min-height:100vh;display:flex;align-items:center;" +
      "justify-content:center;padding:20px}.box{background:#16213e;border:2px solid #0f3460;" +
      "border-radius:12px;padding:40px;max-width:500px;text-align:center;box-shadow:0 10px 40px rgba(0,0,0,0.5)}" +
      ".badge{display:inline-block;background:#0f4;color:#000;padding:6px 16px;border-radius:20px;" +
      "font-size:12px;font-weight:bold;margin-bottom:16px;text-transform:uppercase}h1{font-size:32px;" +
      "margin-bottom:12px;color:#fff}p{color:#aaa;line-height:1.6;font-size:15px}.dot{display:inline-block;" +
      "width:8px;height:8px;background:#0f4;border-radius:50%;margin-right:8px;animation:b 1.5s infinite}" +
      "@keyframes b{0%,100%{opacity:1}50%{opacity:.3}}</style></head>" +
      '<body><div class="box"><span class="badge"><span class="dot"></span>Active</span>' +
      "<h1>MedoVPN Bridge</h1><p>Gateway service is running. All connections are routed securely.</p>" +
      "</div></body></html>"
  );
}

function _json(obj) {
  return ContentService
    .createTextOutput(JSON.stringify(obj))
    .setMimeType(ContentService.MimeType.JSON);
}
