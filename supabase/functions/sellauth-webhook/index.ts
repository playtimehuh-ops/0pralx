import { createClient } from "npm:@supabase/supabase-js@2";

const admin = createClient(
  Deno.env.get("SUPABASE_URL")!,
  Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,
  { auth: { persistSession: false } }
);

const cors = {
  "Access-Control-Allow-Origin": "*",
  "Content-Type": "application/json"
};

const text = (v: unknown) => v == null ? "" : String(v);
const first = (...v: unknown[]) => v.find(x => x != null && String(x).trim() !== "");
const pick = (o: any, ...paths: string[]) => {
  for (const path of paths) {
    let x = o;
    for (const k of path.split(".")) x = x?.[k];
    if (x != null && String(x).trim() !== "") return x;
  }
  return undefined;
};

function authorized(req: Request) {
  const secret = Deno.env.get("SELLAUTH_WEBHOOK_SECRET")?.trim();
  if (!secret) return false;
  const candidates = [
    req.headers.get("x-sellauth-secret"),
    req.headers.get("x-webhook-secret"),
    req.headers.get("x-sellauth-signature"),
    req.headers.get("authorization")?.replace(/^Bearer\s+/i, "")
  ].filter(Boolean);
  return candidates.some(x => x === secret);
}

async function resolveUser(payload: any) {
  const uid = first(
    pick(payload, "nova_user", "user_id", "customer.metadata.nova_user", "metadata.nova_user", "data.nova_user"),
    pick(payload, "customer.metadata.user_id", "metadata.user_id", "data.user_id")
  );
  if (uid) {
    const { data } = await admin.auth.admin.getUserById(String(uid));
    if (data?.user) return data.user;
  }

  const email = first(
    pick(payload, "email", "customer.email", "buyer.email", "customer_email", "data.email", "data.customer.email")
  );
  if (!email) return null;
  const { data } = await admin.auth.admin.listUsers({ page: 1, perPage: 1000 });
  return data.users.find(u => (u.email ?? "").toLowerCase() === String(email).toLowerCase()) ?? null;
}

function eventName(payload: any) {
  return text(first(payload.event, payload.type, payload.name, payload.action, payload.status)).toLowerCase();
}

function isPaid(payload: any) {
  const s = eventName(payload);
  return /paid|completed|complete|success|active|renewed|renewal|subscription_created|subscription_active/.test(s)
    || payload.paid === true || payload.success === true || payload.status === "paid";
}

function isFailed(payload: any) {
  const s = eventName(payload);
  return /failed|failure|declined|past_due|unpaid/.test(s);
}

function isCancelled(payload: any) {
  const s = eventName(payload);
  return /cancel|canceled|cancelled|deleted|expired|revoked/.test(s);
}

function epochOrDate(v: any) {
  if (v == null || v === "") return null;
  const n = Number(v);
  if (Number.isFinite(n) && n > 1000000000) return new Date(n < 10000000000 ? n * 1000 : n).toISOString();
  const d = new Date(String(v));
  return Number.isNaN(d.getTime()) ? null : d.toISOString();
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });
  if (req.method !== "POST") return new Response("Method Not Allowed", { status: 405, headers: cors });
  if (!authorized(req)) return new Response(JSON.stringify({ error: "Invalid webhook secret" }), { status: 401, headers: cors });

  let payload: any;
  try { payload = await req.json(); }
  catch { return new Response(JSON.stringify({ error: "Invalid JSON" }), { status: 400, headers: cors }); }

  try {
    const user = await resolveUser(payload);
    if (!user) throw new Error("Could not resolve Nova Deploy user.");

    const subId = text(first(
      pick(payload, "subscription_id", "subscription.id", "subscription_id", "data.subscription.id"),
      pick(payload, "id", "order_id", "order.id", "data.id")
    ));
    const invoiceId = text(first(
      pick(payload, "invoice_id", "invoice.id", "order_id", "order.id", "id", "data.id")
    ));
    const amount = Number(first(
      pick(payload, "amount_paid", "amount", "total", "price", "data.amount"),
      0
    )) || 0;
    const currency = text(first(pick(payload, "currency", "data.currency"), "usd")).toLowerCase();

    if (isPaid(payload)) {
      const start = epochOrDate(first(
        pick(payload, "period_start", "subscription.current_period_start", "current_period_start", "data.period_start"),
        new Date()
      ))!;
      const end = epochOrDate(first(
        pick(payload, "period_end", "subscription.current_period_end", "current_period_end", "data.period_end"),
        new Date(Date.now() + 30 * 86400000)
      ))!;
      const cfg = await (async () => {
        const { data } = await admin.from("app_config").select("credits_per_period").limit(1).maybeSingle();
        return Number(data?.credits_per_period) || 6000000;
      })();

      await admin.rpc("deploy_grant_period", {
        p_user: user.id,
        p_invoice: invoiceId || ("sellauth_" + crypto.randomUUID()),
        p_pi: null,
        p_sub: subId || null,
        p_cents: Math.round(amount > 1000 ? amount : amount * 100),
        p_cur: currency,
        p_start: start,
        p_end: end,
        p_renewal: /renew|renewal|cycle/.test(eventName(payload))
      });

      return new Response(JSON.stringify({ received: true, granted: cfg }), { status: 200, headers: cors });
    }

    if (isFailed(payload)) {
      if (subId) await admin.rpc("deploy_record_failed_payment", {
        p_user: user.id,
        p_invoice: invoiceId || ("sellauth_failed_" + crypto.randomUUID()),
        p_pi: null,
        p_sub: subId,
        p_cents: Math.round(amount > 1000 ? amount : amount * 100),
        p_cur: currency
      });
      return new Response(JSON.stringify({ received: true }), { status: 200, headers: cors });
    }

    if (isCancelled(payload)) {
      if (subId) await admin.rpc("deploy_sync_renewal", { p_sub: subId, p_auto: false });
      return new Response(JSON.stringify({ received: true }), { status: 200, headers: cors });
    }

    return new Response(JSON.stringify({ received: true, ignored: true }), { status: 200, headers: cors });
  } catch (e) {
    console.error("sellauth webhook processing failed", e);
    return new Response(JSON.stringify({ error: "Webhook processing failed" }), { status: 500, headers: cors });
  }
});
