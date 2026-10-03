import { NovaModel, BPETokenizer } from "../supabase/functions/_shared/engine.js";

const buckets = new Map();
const MAX_BODY_BYTES = 64 * 1024;
const IP_LIMIT = 120;
const KEY_LIMIT = 60;
const IP_BURST = 12;
const KEY_BURST = 8;
const BURST_WINDOW_MS = 10_000;

function limit(key, max, windowMs = 60_000) {
  const now = Date.now();
  const current = buckets.get(key);
  if (!current || now - current.start >= windowMs) {
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

function reject(res, status, code, message) {
  res.status(status).json({ error: { code, message } });
}

export default async function handler(req, res) {
  securityHeaders(res);
  res.setHeader("Content-Type", "application/json");

  // Firewall 1: method + content-type + request-shape filtering.
  if (req.method !== "POST") {
    reject(res, 405, "method_not_allowed", "Use POST.");
    return;
  }

  const contentType = String(req.headers["content-type"] || "").split(";")[0].trim().toLowerCase();
  if (contentType !== "application/json") {
    reject(res, 415, "unsupported_media_type", "Content-Type must be application/json.");
    return;
  }

  const forwarded = req.headers["x-forwarded-for"];
  const ip = String(Array.isArray(forwarded) ? forwarded[0] : forwarded || "").split(",")[0].trim();
  if (!ip || ip === "unknown" || ip === "localhost" || ip === "undefined") {
    reject(res, 400, "invalid_client", "Invalid client address.");
    return;
  }

  // Firewall 2: per-IP and burst limits.
  if (!limit("ip:" + ip, IP_LIMIT) || !limit("ip-burst:" + ip, IP_BURST, BURST_WINDOW_MS)) {
    reject(res, 429, "rate_limited", "Too many requests. Try again later.");
    return;
  }

  // Firewall 3: exact API-key gateway. Anonymous requests never reach the upstream.
  const chatMode = req.headers["x-nova-chat"] === "1";
  const auth = String(req.headers.authorization || "");
  if (chatMode) {
    if (!/^Bearer\s+eyJ[A-Za-z0-9_-]+\./.test(auth)) { reject(res,401,"unauthenticated","Sign in first."); return; }
  }
  const keyMatch = chatMode ? null : /^Bearer (nova_sk_[A-Za-z0-9_-]{20,128})$/.exec(auth);
  if (!chatMode && !keyMatch) {
    reject(res, 401, "invalid_api_key", "Missing or malformed API key.");
    return;
  }

  const key = keyMatch ? keyMatch[1] : "";
  if (!limit("key:" + key.slice(0, 32), KEY_LIMIT) || !limit("key-burst:" + key.slice(0, 32), KEY_BURST, BURST_WINDOW_MS)) {
    reject(res, 429, "rate_limited", "Too many requests. Try again later.");
    return;
  }

  const contentLength = Number(req.headers["content-length"] || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
    reject(res, 413, "payload_too_large", "Request body is too large.");
    return;
  }

  let body;
  try {
    if (typeof req.body === "string") body = JSON.parse(req.body);
    else body = req.body || {};
  } catch {
    reject(res, 400, "bad_json", "Body must be JSON.");
    return;
  }

  const serialized = JSON.stringify(body);
  if (Buffer.byteLength(serialized, "utf8") > MAX_BODY_BYTES) {
    reject(res, 413, "payload_too_large", "Request body is too large.");
    return;
  }

  if (chatMode && body.action === "chat") {
    const runtime = async (payload) => {
      const rr = await fetch("https://jtstdajaaasucialvsfs.supabase.co/functions/v1/runtime", {
        method:"POST", headers:{"Authorization":auth,"Content-Type":"application/json"}, body:JSON.stringify(payload)
      });
      const dd = await rr.json().catch(()=>({error:"Runtime returned invalid JSON."}));
      if(!rr.ok){const x=new Error(dd.error||"Runtime request failed.");x.code=dd.code;throw x;}
      return dd;
    };
    let prep;
    try { prep=await runtime({action:"prepare",modelId:String(body.modelId||""),messages:body.messages,maxTokens:body.maxTokens,temperature:body.temperature}); }
    catch(x){ reject(res,x.code==="subscription_required"?402:400,x.code||"runtime_error",x.message); return; }
    try {
      const r=await fetch(prep.signedUrl,{cache:"no-store"});
      if(!r.ok)throw new Error("weights_download_failed");
      const compressed=new Uint8Array(await r.arrayBuffer());
      const digest=[...new Uint8Array(await crypto.subtle.digest("SHA-256",compressed))].map(b=>b.toString(16).padStart(2,"0")).join("");
      if(digest!==prep.sha)throw new Error("integrity");
      const raw=await new Response(new Blob([compressed]).stream().pipeThrough(new DecompressionStream("gzip"))).arrayBuffer();
      const o=JSON.parse(new TextDecoder().decode(raw));
      const t=BPETokenizer.fromJSON(o.tokenizer),m=new NovaModel(o.vocabSize,o.config),d=m.cfg.dModel;
      if(t.size!==o.vocabSize||o.weights.wte?.length!==o.vocabSize*d||o.weights.wpe?.length!==m.cfg.ctxLen*d||o.weights.layers?.length!==m.cfg.nLayers)throw new Error("weight_shapes");
      m.loadWeights(o.weights);m.eosId=t.vocab["<EOS>"];
      const ids=t.encode(prep.prompt),t0=performance.now(),out=m.generate(ids,prep.maxTok,prep.temp,prep.settings?.topK||30,prep.settings?.topP||.9,{stop:false}),ms=Math.round(performance.now()-t0);
      let reply=t.decode(out.slice(ids.length)),cut=reply.indexOf("\nUser:");if(cut>=0)reply=reply.slice(0,cut);
      const outTok=out.length-ids.length,actual=ids.length*prep.creditsIn+outTok*prep.creditsOut;
      const settled=await runtime({action:"settle",alloc:prep.alloc,reserve:prep.reserve,actual,modelId:prep.modelId,inputTokens:ids.length,outputTokens:outTok,ms});
      res.status(200).send(JSON.stringify({reply:reply.trim()||"(empty output)",usage:{prompt_tokens:ids.length,completion_tokens:outTok,credits_used:Math.min(actual,prep.reserve),credits_remaining:settled.credits_remaining}}));
    } catch(x) {
      try{await runtime({action:"release",alloc:prep.alloc,reserve:prep.reserve});}catch{}
      const msg=x.message==="integrity"?"Stored model failed its integrity check.":x.message==="weights_download_failed"?"Model weights could not be downloaded.":x.message==="weight_shapes"?"This model export is invalid.":"Model execution failed.";
      reject(res,500,"execution_failed",msg);
    }
    return;
  }

  if (!body || typeof body !== "object" || Array.isArray(body)) {
    reject(res, 400, "bad_request", "Request body must be an object.");
    return;
  }

  if (typeof body.model !== "string" || !/^mdl_[A-Za-z0-9_-]{3,128}$/.test(body.model)) {
    reject(res, 400, "invalid_model_id", "Invalid model ID.");
    return;
  }

  if (!Array.isArray(body.messages) || body.messages.length < 1 || body.messages.length > 50) {
    reject(res, 400, "bad_messages", "messages must contain 1 to 50 items.");
    return;
  }

  if (body.max_tokens !== undefined && (!Number.isInteger(body.max_tokens) || body.max_tokens < 1 || body.max_tokens > 300)) {
    reject(res, 400, "invalid_max_tokens", "max_tokens must be an integer from 1 to 300.");
    return;
  }

  if (body.temperature !== undefined && (typeof body.temperature !== "number" || !Number.isFinite(body.temperature) || body.temperature < 0.1 || body.temperature > 2)) {
    reject(res, 400, "invalid_temperature", "temperature must be between 0.1 and 2.");
    return;
  }

  try {
    const upstream = "https://jtstdajaaasucialvsfs.supabase.co/functions/v1/v1";
    const response = await fetch(upstream, {
      method: "POST",
      headers: {
        "Authorization": "Bearer " + key,
        "Content-Type": "application/json"
      },
      body: serialized,
      redirect: "manual"
    });

    const text = await response.text();
    res.status(response.status);
    res.send(text);
  } catch {
    reject(res, 502, "upstream_unavailable", "API connection is temporarily unavailable.");
  }
}

