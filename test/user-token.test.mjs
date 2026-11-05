/**
 * Offline tests of the per-user BO token (X-BO-User-Token). No network: fetch is stubbed,
 * the real HTTP handler runs on a local port.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";

const MCP_TOKEN = "test-mcp-bearer";
process.env.UBCAB_BO_MCP_AUTH_TOKEN = MCP_TOKEN;
process.env.UBCAB_BO_CLIENT_ID = "bo-mcp-test";
process.env.UBCAB_BO_CLIENT_SECRET = "server-secret";
process.env.UBCAB_EXPRESS_CLIENT_ID = "express-test";
process.env.UBCAB_EXPRESS_CLIENT_SECRET = "express-secret";
process.env.UBEATS_CLIENT_ID = "ubeats-test";
process.env.UBEATS_CLIENT_SECRET = "ubeats-secret";
delete process.env.UBCAB_BO_USER_ORIGIN;

const { default: handler, parseUserTokenHeader, redactSecrets } = await import("../dist/api/index.js");
const realFetch = globalThis.fetch;

const b64 = (o) => Buffer.from(JSON.stringify(o)).toString("base64url");
const jwt = (tag) => `eyJ${b64({ alg: "RS256" }).slice(3)}.${b64({ sub: tag })}.${Buffer.from("sig-" + tag).toString("base64url")}`;
const USER_A = jwt("alice");
const USER_B = jwt("bob");

let server;
let base;
before(async () => {
  server = http.createServer((req, res) => void handler(req, res));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => new Promise((r) => server.close(r)));

/** Stub every outbound call except the local server. Returns recorded calls. */
function stubOutbound(t, apiReply) {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (url, init = {}) => {
    const u = String(url);
    if (u.startsWith(base)) return realFetch(url, init);
    if (u.endsWith("/protocol/openid-connect/token")) {
      calls.push({ kind: "token", url: u, form: Object.fromEntries(new URLSearchParams(init.body)) });
      return new Response(JSON.stringify({ access_token: "server-at", expires_in: 300 }), { status: 200 });
    }
    const call = { kind: "api", url: u, headers: init.headers };
    calls.push(call);
    const r = apiReply ? await apiReply(call) : { status: 200, body: { success: true, data: {} } };
    return new Response(JSON.stringify(r.body), { status: r.status });
  });
  return calls;
}

async function callTool(name, args, headers = {}) {
  const res = await realFetch(`${base}/mcp`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Accept: "application/json, text/event-stream",
      Authorization: `Bearer ${MCP_TOKEN}`,
      ...headers,
    },
    body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "tools/call", params: { name, arguments: args } }),
  });
  const json = await res.json();
  assert.ok(json.result, JSON.stringify(json));
  return { text: json.result.content.map((c) => c.text).join("\n"), isError: !!json.result.isError };
}

const REG = ["ubcab_bo_driver_get", { driverId: "d1" }];
const MKT = ["ubcab_marketing_help_group_list", {}];
const EXPRESS = ["ubcab_express_order_search", { trackingNumber: "T1" }];
const UBEATS = ["ubeats_order_get", { orderId: "o1" }];

test("registration + marketing tools call BO with the user's token, no Keycloak request", async (t) => {
  const calls = stubOutbound(t);
  for (const [name, args] of [REG, MKT]) {
    const r = await callTool(name, args, { "X-BO-User-Token": `  ${USER_A}  ` });
    assert.equal(r.isError, false, r.text);
  }
  assert.equal(calls.filter((c) => c.kind === "token").length, 0);
  const api = calls.filter((c) => c.kind === "api");
  assert.equal(api.length, 2);
  for (const c of api) {
    assert.equal(c.headers.Authorization, `Bearer ${USER_A}`);
    assert.equal(c.headers.Origin, "https://operator.ubcab.mn");
    assert.equal(c.headers.Referer, "https://operator.ubcab.mn/");
  }
});

test("header parsing: absent/blank ignored, whitespace stripped, size and shape enforced", () => {
  assert.equal(parseUserTokenHeader(undefined), undefined);
  assert.equal(parseUserTokenHeader("   "), undefined);
  assert.deepEqual(parseUserTokenHeader(` ${USER_A}\t`), { kind: "token", token: USER_A });
  assert.equal(parseUserTokenHeader(["a.b.c", "a.b.c"]).kind, "invalid");
  const atLimit = "A".repeat(16384 - 4) + ".b.c";
  assert.equal(parseUserTokenHeader(atLimit).kind, "token");
  assert.equal(parseUserTokenHeader(atLimit + "x").kind, "invalid");
});

test("express and ubeats keep their own credentials even when the header is present", async (t) => {
  const calls = stubOutbound(t);
  for (const [name, args] of [EXPRESS, UBEATS]) {
    const r = await callTool(name, args, { "X-BO-User-Token": USER_A });
    assert.equal(r.isError, false, r.text);
  }
  const tokens = calls.filter((c) => c.kind === "token");
  assert.deepEqual(tokens.map((c) => c.form.client_id).sort(), ["express-test", "ubeats-test"]);
  for (const c of calls.filter((c) => c.kind === "api")) {
    assert.equal(c.headers.Authorization, "Bearer server-at");
    assert.ok(!JSON.stringify(c.headers).includes(USER_A));
  }
});

test("concurrent requests with different tokens never cross", async (t) => {
  const calls = stubOutbound(t, async (call) => {
    // interleave: the first request finishes last
    await new Promise((r) => setTimeout(r, call.url.includes("/slow") ? 60 : 5));
    return { status: 200, body: { success: true, data: {} } };
  });
  const [a, b] = await Promise.all([
    callTool("ubcab_bo_driver_get", { driverId: "slow" }, { "X-BO-User-Token": USER_A }),
    callTool("ubcab_bo_driver_get", { driverId: "fast" }, { "X-BO-User-Token": USER_B }),
  ]);
  assert.equal(a.isError || b.isError, false);
  const byPath = Object.fromEntries(calls.map((c) => [c.url.split("/").pop(), c.headers.Authorization]));
  assert.equal(byPath.slow, `Bearer ${USER_A}`);
  assert.equal(byPath.fast, `Bearer ${USER_B}`);
});

for (const [status, marker, other] of [
  [401, "BO_USER_TOKEN_REJECTED", "BO_USER_FORBIDDEN"],
  [403, "BO_USER_FORBIDDEN", "BO_USER_TOKEN_REJECTED"],
]) {
  test(`BO ${status} → ${marker} marker, one attempt, no Keycloak, no fallback`, async (t) => {
    const calls = stubOutbound(t, async () => ({ status, body: { success: false, echo: USER_A } }));
    const r = await callTool(...REG, { "X-BO-User-Token": USER_A });
    assert.equal(r.isError, true);
    assert.ok(r.text.startsWith(`${marker} (HTTP ${status})`), r.text);
    assert.ok(!r.text.includes(other));
    assert.match(r.text, /user_token=yes/);
    assert.ok(!r.text.includes(USER_A));
    assert.equal(calls.length, 1);
    assert.equal(calls[0].kind, "api");
  });
}

test("malformed and oversized headers → tool error, no BO call", async (t) => {
  const calls = stubOutbound(t);
  for (const bad of ["not-a-jwt", "a.b", "a.b.c.d", "a.b.c d"]) {
    const r = await callTool(...REG, { "X-BO-User-Token": bad });
    assert.equal(r.isError, true);
    assert.ok(r.text.startsWith("BO_USER_TOKEN_INVALID"), r.text);
    assert.match(r.text, /Invalid X-BO-User-Token/);
    assert.ok(!r.text.includes(bad.slice(0, 50)) || bad.length < 20);
  }
  assert.equal(calls.length, 0);
});

test("header is ignored on unauthenticated requests", async (t) => {
  const calls = stubOutbound(t);
  const res = await realFetch(`${base}/mcp`, {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-BO-User-Token": USER_A },
    body: "{}",
  });
  assert.equal(res.status, 401);
  assert.equal(calls.length, 0);
});

test("token never reaches error text or console output", async (t) => {
  const logged = [];
  for (const m of ["log", "error", "warn", "info", "debug"]) t.mock.method(console, m, (...a) => logged.push(a.join(" ")));
  stubOutbound(t, async () => ({ status: 500, body: { message: `boom ${USER_A}`, nested: { t: USER_A } } }));
  const r = await callTool(...REG, { "X-BO-User-Token": USER_A });
  assert.equal(r.isError, true);
  assert.ok(!r.text.includes(USER_A) && !r.text.includes("eyJ"), r.text);
  assert.match(r.text, /\*\*\*/);
  assert.ok(!logged.join("\n").includes(USER_A));
});

test("redactSecrets masks any JWT-looking string", () => {
  assert.equal(redactSecrets(`x ${USER_B} y`), "x *** y");
});

test("header absent → server-credential path unchanged", async (t) => {
  const calls = stubOutbound(t);
  const r = await callTool(...REG);
  assert.equal(r.isError, false, r.text);
  const tokens = calls.filter((c) => c.kind === "token");
  assert.equal(tokens.length, 1);
  assert.equal(tokens[0].form.grant_type, "client_credentials");
  const api = calls.find((c) => c.kind === "api");
  assert.equal(api.headers.Authorization, "Bearer server-at");
  assert.equal(api.headers.Origin, "https://operator.ubcab.mn");
});

const UPLOAD = ["ubcab_marketing_upload_image", { filename: "c.jpg", fileBase64: Buffer.from("img").toString("base64") }];

test("image upload uses the user's token and user origin; no Keycloak call", async (t) => {
  process.env.UBCAB_BO_USER_ORIGIN = "https://ops.example.test/";
  t.after(() => delete process.env.UBCAB_BO_USER_ORIGIN);
  const calls = stubOutbound(t, async () => ({ status: 200, body: { result: [{ fileUrl: "u" }] } }));
  const r = await callTool(...UPLOAD, { "X-BO-User-Token": USER_A });
  assert.equal(r.isError, false, r.text);
  assert.equal(calls.filter((c) => c.kind === "token").length, 0);
  const api = calls.filter((c) => c.kind === "api");
  assert.equal(api.length, 1);
  assert.match(api[0].url, /\/v2\/upload/);
  assert.equal(api[0].headers.Authorization, `Bearer ${USER_A}`);
  assert.equal(api[0].headers.Origin, "https://ops.example.test");
  assert.equal(api[0].headers.Referer, "https://ops.example.test/");
});

test("image upload with an invalid header fails with BO_USER_TOKEN_INVALID and makes no call", async (t) => {
  const calls = stubOutbound(t);
  const r = await callTool(...UPLOAD, { "X-BO-User-Token": "not-a-jwt" });
  assert.equal(r.isError, true);
  assert.ok(r.text.startsWith("BO_USER_TOKEN_INVALID"), r.text);
  assert.equal(calls.length, 0);
});

for (const [status, marker] of [[401, "BO_USER_TOKEN_REJECTED"], [403, "BO_USER_FORBIDDEN"]]) {
  test(`image upload ${status} with user token → ${marker}, redacted, no retry`, async (t) => {
    const calls = stubOutbound(t, async () => ({ status, body: { echo: USER_A } }));
    const r = await callTool(...UPLOAD, { "X-BO-User-Token": USER_A });
    assert.equal(r.isError, true);
    assert.ok(r.text.startsWith(`${marker} (HTTP ${status})`), r.text);
    assert.ok(!r.text.includes(USER_A));
    assert.equal(calls.length, 1);
  });
}

test("image upload without header uses server credentials", async (t) => {
  const calls = stubOutbound(t, async () => ({ status: 200, body: { result: [] } }));
  const r = await callTool(...UPLOAD);
  assert.equal(r.isError, false, r.text);
  assert.equal(calls.filter((c) => c.kind === "token").length, 1);
  assert.equal(calls.find((c) => c.kind === "api").headers.Authorization, "Bearer server-at");
});

test("user origin is read per request and shown in the auth-context suffix", async (t) => {
  stubOutbound(t, async () => ({ status: 401, body: {} }));
  t.after(() => delete process.env.UBCAB_BO_USER_ORIGIN);
  process.env.UBCAB_BO_USER_ORIGIN = "https://one.example.test";
  let r = await callTool(...REG, { "X-BO-User-Token": USER_A });
  assert.match(r.text, /origin=https:\/\/one\.example\.test,/);
  process.env.UBCAB_BO_USER_ORIGIN = "https://two.example.test";
  r = await callTool(...REG, { "X-BO-User-Token": USER_A });
  assert.match(r.text, /origin=https:\/\/two\.example\.test,/);
  assert.ok(!r.text.includes("operator.ubcab.mn"));
});
