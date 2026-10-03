// Authenticated app backend (JWT required). Every action re-checks identity, subscription and ownership on the server.
// Secrets: SELLAUTH_CHECKOUT_URL, SELLAUTH_PORTAL_URL (optional), SITE_URL
import { createClient } from "npm:@supabase/supabase-js@2";
import { admin, buildModel, config, HttpErr, runChat, sha256 } from "./_shared/run.ts";

const cors = { "Access-Control-Allow-Origin": "*", "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type, x-nova-action, x-nova-storage-path", "Access-Control-Allow-Methods": "POST, OPTIONS" };
const json = (b: unknown, s = 200) => new Response(JSON.stringify(b), { status: s, headers: { ...cors, "Content-Type": "application/json" } });
const sub402 = () => new HttpErr(402, "subscription_required", "An active subscription is required.");

async function requireAccess(uid: string) { const { data } = await admin.rpc("deploy_has_access", { p: uid }); if (!data) throw sub402(); }
async function ownModel(uid: string, id: string) {
  const { data } = await admin.from("deploy_models").select("*").eq("id", String(id)).maybeSingle();
  if (!data || data.owner !== uid) throw new HttpErr(404, "model_not_found", "Model not found.");
  return data;
}
const cleanSettings = (s: any) => ({
  desc: String(s?.desc ?? "").slice(0, 140), temp: Math.min(2, Math.max(0.1, Number(s?.temp) || 0.8)), topK: Math.min(200, Math.max(1, Math.round(Number(s?.topK) || 30))),
  topP: Math.min(1, Math.max(0.1, Number(s?.topP) || 0.9)), maxTok: Math.min(300, Math.max(8, Math.round(Number(s?.maxTok) || 80))),
});

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  try {
    const userClient = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!, { global: { headers: { Authorization: req.headers.get("Authorization") ?? "" } } });
    const { data: { user } } = await userClient.auth.getUser();
    if (!user) throw new HttpErr(401, "unauthenticated", "Sign in first.");
    const uid = user.id;
    const uploadAction = req.headers.get("x-nova-action");
    if (req.method === "POST" && uploadAction === "upload_model") {
      await requireAccess(uid);
      const storagePath = String(req.headers.get("x-nova-storage-path") ?? "");
      if (!/^[0-9a-f]{8}-[0-9a-f-]{27}\/mdl_[0-9a-f]{10}\.json\.gz$/.test(storagePath) || !storagePath.startsWith(uid + "/"))
        throw new HttpErr(400, "bad_source", "Invalid model storage path.");
      const bytes = new Uint8Array(await req.arrayBuffer());
      if (!bytes.byteLength) throw new HttpErr(400, "empty_upload", "The model upload is empty.");
      if (bytes.byteLength > 50 * 1024 * 1024) throw new HttpErr(413, "model_too_large", "Model file is too large.");
      const { error } = await admin.storage.from("nova-deploy-models").upload(storagePath, bytes, { contentType: "application/gzip", cacheControl: "3600", upsert: false });
      if (error) throw new HttpErr(400, "storage_upload_failed", error.message);
      return json({ path: storagePath, bytes: bytes.byteLength });
    }
    const b = await req.json();

    switch (b.action) {
      case "register_model": {
        await requireAccess(uid);
        const id = String(b.id ?? ""); if (!/^mdl_[0-9a-f]{10}$/.test(id)) throw new HttpErr(400, "bad_id", "Bad model id.");
        const name = String(b.name ?? "").trim().slice(0, 40); if (!name) throw new HttpErr(400, "bad_name", "Give your AI a name.");
        const storagePath = String(b.source?.path ?? "");
        if (!/^[0-9a-f]{8}-[0-9a-f-]{27}\/mdl_[0-9a-f]{10}\.json\.gz$/.test(storagePath) || !storagePath.startsWith(uid + "/"))
          throw new HttpErr(400, "bad_source", "Model must be stored in your private Supabase Storage folder.");
        const { data: object, error: objectError } = await admin.storage.from("nova-deploy-models").download(storagePath);
        if (objectError || !object) throw new HttpErr(400, "no_upload", "The model file could not be downloaded from Supabase Storage.");
        const compressed = new Uint8Array(await object.arrayBuffer());
        if (compressed.byteLength > 250 * 1024 * 1024) throw new HttpErr(413, "model_too_large", "Model file is too large.");
        // Keep registration lightweight. Supabase Edge Functions have a strict memory ceiling,
        // so constructing/testing a full model here can kill the function for real exports.
        // The private artifact remains in Storage and is loaded by the inference runtime when used.
        const head = compressed.subarray(0, 2);
        if (head[0] !== 0x1f || head[1] !== 0x8b)
          throw new HttpErr(400, "bad_upload", "The uploaded model is not a valid gzip export.");
        const { error: e2 } = await admin.from("deploy_models").insert({
          id, owner: uid, name, version: "1.0.0",
          sha: await sha256(String.fromCharCode(...compressed.subarray(0, Math.min(compressed.byteLength, 1024)))),
          settings: cleanSettings(b.settings),
          source: {
            path: storagePath,
            bytes: compressed.byteLength,
            params: Math.max(0, Number(b.source?.params) || 0),
            steps: Math.max(0, Number(b.source?.steps) || 0),
            epochs: Math.max(0, Number(b.source?.epochs) || 0)
          }
        });
        if (e2) {
          await admin.storage.from("nova-deploy-models").remove([storagePath]);
          throw new HttpErr(500, "db", e2.message);
        }
        return json({ id });
      }
      case "update_model": {
        const m = await ownModel(uid, b.id), patch: Record<string, unknown> = {};
        if (typeof b.name === "string" && b.name.trim()) patch.name = b.name.trim().slice(0, 40);
        if (b.settings) patch.settings = cleanSettings(b.settings);
        if (typeof b.listed === "boolean") patch.listed = b.listed;
        if (typeof b.deployed === "boolean") { if (b.deployed) await requireAccess(uid); patch.deployed = b.deployed; }
        if (Object.keys(patch).length) await admin.from("deploy_models").update(patch).eq("id", m.id);
        return json({ ok: true });
      }
      case "delete_model": {
        const m = await ownModel(uid, b.id);
        const storedPath = String(m.source?.path ?? "");
        if (storedPath && storedPath.startsWith(uid + "/")) await admin.storage.from("nova-deploy-models").remove([storedPath]);
        await admin.from("deploy_models").delete().eq("id", m.id);
        return json({ ok: true });
      }
      case "runtime_prepare": {
        await requireAccess(uid);
        const m = await ownModel(uid, b.modelId);
        if (!m.deployed) throw new HttpErr(403, "not_deployed", "This model is not deployed.");
        const msgs = b.messages;
        if (!Array.isArray(msgs) || !msgs.length || msgs.length > 50 || msgs[msgs.length - 1]?.role !== "user" || msgs.some((x) => typeof x?.content !== "string" || (x.role !== "user" && x.role !== "assistant"))) throw new HttpErr(400, "bad_messages", "messages must be a list ending with a user message.");
        const last = msgs[msgs.length - 1].content.trim().slice(0, 2000);
        if (!last) throw new HttpErr(400, "bad_messages", "Empty message.");
        const st = m.settings ?? {}, cfg = await config();
        const maxTok = Math.max(1, Math.min(Number(b.maxTokens) || st.maxTok || 80, 300));
        const temp = Math.max(0.1, Math.min(Number(b.temperature) || st.temp || 0.8, 2));
        const prompt = msgs.slice(0, -1).slice(-6).map((x:any) => (x.role === "user" ? "User: " : "Nova: ") + x.content.slice(0, 2000)).join("\n") + "\nUser: " + last + "\nNova:";
        const cin = Number(cfg.credits_per_input_token ?? 1), cout = Number(cfg.credits_per_output_token ?? 1);
        const reserve = prompt.length * cin + maxTok * cout;
        const { data: alloc } = await admin.rpc("deploy_reserve_credits", { p_user: uid, p_amount: reserve });
        if (alloc == null) throw new HttpErr(402, "insufficient_credits", "Not enough credits for this request.");
        const path = String(m.source?.path ?? "");
        if (!path.startsWith(uid + "/") || !path.endsWith(".json.gz")) { await admin.rpc("deploy_release_credits", { p_alloc: alloc, p_amount: reserve }); throw new HttpErr(500, "weights_unavailable", "Model storage path is invalid."); }
        const { data: signed, error: signError } = await admin.storage.from("nova-deploy-models").createSignedUrl(path, 600);
        if (signError || !signed?.signedUrl) { await admin.rpc("deploy_release_credits", { p_alloc: alloc, p_amount: reserve }); throw new HttpErr(500, "weights_unavailable", "Model weights could not be signed for inference."); }
        return json({ alloc, reserve, signedUrl: signed.signedUrl, sha: m.sha, settings: st, prompt, maxTok, temp, creditsIn: cin, creditsOut: cout });
      }
      case "runtime_settle": {
        const alloc = String(b.alloc ?? ""), reserve = Number(b.reserve), actual = Number(b.actual);
        if (!alloc || !Number.isFinite(reserve) || !Number.isFinite(actual) || reserve < 0 || actual < 0 || actual > reserve) throw new HttpErr(400, "bad_settlement", "Invalid runtime settlement.");
        const { data: remaining } = await admin.rpc("deploy_settle_credits", { p_alloc: alloc, p_user: uid, p_reserved: reserve, p_actual: actual, p_model: String(b.modelId ?? ""), p_via: "playground", p_key: null, p_in: Math.max(0, Number(b.inputTokens) || 0), p_out: Math.max(0, Number(b.outputTokens) || 0), p_ms: Math.max(0, Number(b.ms) || 0) });
        return json({ credits_remaining: remaining });
      }
      case "runtime_release": {
        const alloc = String(b.alloc ?? ""), reserve = Number(b.reserve);
        if (!alloc || !Number.isFinite(reserve) || reserve < 0) throw new HttpErr(400, "bad_release", "Invalid runtime release.");
        await admin.rpc("deploy_release_credits", { p_alloc: alloc, p_amount: reserve });
        return json({ ok: true });
      }
      case "chat":   // playground: runs the real model on the server, same credits as the API
        return json(await runChat({ userId: uid, modelId: String(b.modelId ?? ""), messages: b.messages, via: "playground" }));
      case "create_api_key": {
        await requireAccess(uid);
        const { count } = await admin.from("deploy_api_keys").select("id", { count: "exact", head: true }).eq("user_id", uid).is("revoked_at", null);
        if ((count ?? 0) >= 10) throw new HttpErr(400, "too_many_keys", "Revoke an old key first (max 10 active).");
        const key = "nova_sk_" + btoa(String.fromCharCode(...crypto.getRandomValues(new Uint8Array(32)))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
        const { error } = await admin.from("deploy_api_keys").insert({ user_id: uid, name: String(b.name ?? "").trim().slice(0, 40) || "Untitled key", prefix: key.slice(0, 16), key_hash: await sha256(key) });
        if (error) throw new HttpErr(500, "db", error.message);
        return json({ key });   // the only time the secret is ever shown; only its hash is stored
      }
      case "revoke_api_key":
        await admin.from("deploy_api_keys").update({ revoked_at: new Date().toISOString() }).eq("id", String(b.id)).eq("user_id", uid).is("revoked_at", null);
        return json({ ok: true });
      case "checkout": {   // SellAuth hosted checkout. The server decides access; the browser never supplies price/credits.
        const checkoutUrl = Deno.env.get("SELLAUTH_CHECKOUT_URL");
        if (!checkoutUrl?.trim()) throw new HttpErr(503, "sellauth_not_configured", "SellAuth is not configured. Add SELLAUTH_CHECKOUT_URL to the Supabase Edge Function secrets.");
        let url: URL;
        try { url = new URL(checkoutUrl); } catch { throw new HttpErr(503, "sellauth_not_configured", "SELLAUTH_CHECKOUT_URL must be a valid URL."); }
        const cfg = await config();
        url.searchParams.set("nova_user", uid);
        url.searchParams.set("nova_email", user.email ?? "");
        url.searchParams.set("nova_credits", String(cfg.credits_per_period));
        return json({ url: url.toString() });
      }
      case "set_renewal": {   // Subscription lifecycle is managed by SellAuth; optionally open its customer portal.
        const portal = Deno.env.get("SELLAUTH_PORTAL_URL");
        if (!portal?.trim()) throw new HttpErr(503, "sellauth_portal_not_configured", "Subscription management is handled by SellAuth. Add SELLAUTH_PORTAL_URL to enable the management button.");
        return json({ url: portal });
      }
      default: throw new HttpErr(400, "unknown_action", "Unknown action.");
    }
  } catch (e) {
    if (e instanceof HttpErr) return json({ error: e.message, code: e.code }, e.status);
    console.error(e); return json({ error: "Internal error", code: "server_error" }, 500);
  }
});
