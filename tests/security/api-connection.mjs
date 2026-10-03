const BASE = process.env.API_BASE_URL || "https://0pralx.vercel.app/api-connection";

async function post(body, headers = {}) {
  return fetch(BASE, {
    method: "POST",
    headers: { "Content-Type": "application/json", ...headers },
    body,
    redirect: "manual",
  });
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

async function run(name, fn) {
  try {
    await fn();
    console.log(`PASS  ${name}`);
  } catch (e) {
    console.error(`FAIL  ${name}: ${e.message}`);
    process.exitCode = 1;
  }
}

await run("unauthenticated POST is rejected", async () => {
  const r = await post(JSON.stringify({
    model: "mdl_nonexistent",
    messages: [{ role: "user", content: "security-test" }],
  }));
  assert(r.status === 401, `expected 401, got ${r.status}`);
});

await run("fake API key cannot authenticate", async () => {
  const r = await post(JSON.stringify({
    model: "mdl_nonexistent",
    messages: [{ role: "user", content: "security-test" }],
  }), {
    Authorization: "Bearer nova_sk_security_test_invalid_00000000000000000000",
  });
  assert(r.status === 401, `expected 401, got ${r.status}`);
});

await run("malformed JSON is rejected", async () => {
  const r = await post("{ definitely-not-json");
  assert(r.status === 400, `expected 400, got ${r.status}`);
});

await run("oversized payload is rejected", async () => {
  const oversized = "x".repeat(70 * 1024);
  const r = await post(JSON.stringify({
    model: "mdl_nonexistent",
    messages: [{ role: "user", content: oversized }],
  }));
  assert(r.status === 413 || r.status === 400, `expected 413/400, got ${r.status}`);
});

await run("unsupported methods are rejected", async () => {
  const r = await fetch(BASE, { method: "GET", redirect: "manual" });
  assert(r.status === 405, `expected 405, got ${r.status}`);
});

if (process.exitCode) process.exit(1);
console.log("Security smoke tests completed.");
