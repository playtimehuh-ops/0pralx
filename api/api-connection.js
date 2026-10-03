const buckets = new Map();
const MAX_BODY_BYTES = 64 * 1024;
const IP_LIMIT = 120;
const KEY_LIMIT = 60;

function limit(key, max) {
  const now = Date.now();
  const current = buckets.get(key);
  if (!current || now - current.start >= 60000) {
    buckets.set(key, { start: now, count: 1 });
    if (buckets.size > 5000) buckets.delete(buckets.keys().next().value);
    return true;
  }
  current.count++;
  return current.count <= max;
}

function securityHeaders(res) {
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "strict-origin-when-cross-origin");
  res.setHeader("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()");
  res.setHeader("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
  res.setHeader("Cache-Control", "no-store");
}

export default async function handler(req, res) {
  securityHeaders(res);
  res.setHeader("Content-Type", "application/json");

  if (req.method !== "POST") {
    res.status(405).json({ error: { code: "method_not_allowed", message: "Use POST." } });
    return;
  }

  const forwarded = req.headers["x-forwarded-for"];
  const ip = String(Array.isArray(forwarded) ? forwarded[0] : forwarded || "unknown").split(",")[0].trim();

  if (!limit("ip:" + ip, IP_LIMIT)) {
    res.status(429).json({ error: { code: "rate_limited", message: "Too many requests. Try again later." } });
    return;
  }

  const auth = String(req.headers.authorization || "");
  const keyMatch = /^Bearer (nova_sk_[A-Za-z0-9_-]{20,})$/.exec(auth);
  const rateKey = keyMatch ? "key:" + keyMatch[1].slice(0, 16) : "anon:" + ip;

  if (!limit(rateKey, KEY_LIMIT)) {
    res.status(429).json({ error: { code: "rate_limited", message: "Too many requests. Try again later." } });
    return;
  }

  const contentLength = Number(req.headers["content-length"] || 0);
  if (contentLength > MAX_BODY_BYTES) {
    res.status(413).json({ error: { code: "payload_too_large", message: "Request body is too large." } });
    return;
  }

  let body;
  try {
    if (typeof req.body === "string") body = JSON.parse(req.body);
    else body = req.body || {};
  } catch {
    res.status(400).json({ error: { code: "bad_json", message: "Body must be JSON." } });
    return;
  }

  try {
    const upstream = "https://jtstdajaaasucialvsfs.supabase.co/functions/v1/v1";
    const response = await fetch(upstream, {
      method: "POST",
      headers: {
        "Authorization": auth,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(body),
      redirect: "manual"
    });

    const text = await response.text();
    res.status(response.status);
    res.send(text);
  } catch {
    res.status(502).json({
      error: {
        code: "upstream_unavailable",
        message: "API connection is temporarily unavailable."
      }
    });
  }
}
