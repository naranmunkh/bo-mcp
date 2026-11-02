/**
 * Offline tests of the Keycloak auth in api/index.ts (no network: fetch is stubbed).
 *   npm test        (compiles to dist/ first)
 *
 * 2026-11-02: the BO realm disabled the password grant on every client, so the
 * server authenticates as a service account (client_credentials) or with a
 * refresh token. These tests pin what is sent to the token endpoint.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  UBCabBOClient,
  boAuthConfig,
  expressAuthConfig,
  marketingAuthConfig,
  ubeatsAuthConfig,
} from "../dist/api/index.js";

const TOKEN_URL = "https://sso.example.test/realms/ubcab-bo/protocol/openid-connect/token";

function config(overrides = {}) {
  return {
    envPrefix: "UBCAB_BO",
    clientId: "bo-mcp-test",
    clientSecret: "",
    refreshToken: "",
    ssoUrl: "https://sso.example.test",
    realm: "ubcab-bo",
    apiUrl: "https://api.example.test",
    origin: "https://operator.example.test",
    ...overrides,
  };
}

/** Token endpoint answers from `replies` in order; any other URL is an API call answered 200. */
function stubFetch(t, replies) {
  const calls = [];
  t.mock.method(globalThis, "fetch", async (url, init = {}) => {
    if (String(url) === TOKEN_URL) {
      calls.push({ kind: "token", form: Object.fromEntries(new URLSearchParams(init.body)) });
      const reply = replies.shift() ?? { status: 500, body: { error: "unexpected_token_call" } };
      return new Response(JSON.stringify(reply.body), { status: reply.status });
    }
    calls.push({ kind: "api", url: String(url), headers: init.headers });
    return new Response(JSON.stringify({ success: true, data: {} }), { status: 200 });
  });
  return calls;
}

const issued = (access_token, extra = {}) => ({
  status: 200,
  body: { access_token, expires_in: 300, token_type: "Bearer", ...extra },
});

test("client secret set → client_credentials grant with client_id + client_secret only", async (t) => {
  const calls = stubFetch(t, [issued("at-1")]);
  const client = new UBCabBOClient(config({ clientSecret: "s3cret" }));
  assert.equal(await client.getToken(), "at-1");
  assert.deepEqual(calls.map((c) => c.form), [
    { grant_type: "client_credentials", client_id: "bo-mcp-test", client_secret: "s3cret" },
  ]);
});

test("service-account token is reused while valid", async (t) => {
  const calls = stubFetch(t, [issued("at-1")]);
  const client = new UBCabBOClient(config({ clientSecret: "s3cret" }));
  await client.getToken();
  assert.equal(await client.getToken(), "at-1");
  assert.equal(calls.length, 1);
});

test("expiring service-account token is replaced by a new client_credentials grant", async (t) => {
  // expires_in 30 falls inside the 30 s safety buffer → stale at once.
  const calls = stubFetch(t, [issued("at-1", { expires_in: 30 }), issued("at-2")]);
  const client = new UBCabBOClient(config({ clientSecret: "s3cret" }));
  assert.equal(await client.getToken(), "at-1");
  assert.equal(await client.getToken(), "at-2");
  assert.deepEqual(
    calls.map((c) => c.form.grant_type),
    ["client_credentials", "client_credentials"]
  );
});

test("refresh token on a public client → refresh_token grant without a secret; rotated token reused", async (t) => {
  const calls = stubFetch(t, [issued("at-1", { expires_in: 30, refresh_token: "rt-2" }), issued("at-2")]);
  const client = new UBCabBOClient(config({ clientId: "ubcab-registration-bo", refreshToken: "rt-1" }));
  await client.getToken();
  await client.getToken();
  assert.deepEqual(calls[0].form, {
    grant_type: "refresh_token",
    refresh_token: "rt-1",
    client_id: "ubcab-registration-bo",
  });
  assert.equal(calls[1].form.refresh_token, "rt-2");
});

test("refresh token + secret → refresh grant authenticates the client, falls back to client_credentials", async (t) => {
  t.mock.method(console, "error", () => {});
  const calls = stubFetch(t, [
    { status: 400, body: { error: "invalid_grant", error_description: "Token is not active" } },
    issued("at-cc"),
  ]);
  const client = new UBCabBOClient(config({ clientSecret: "s3cret", refreshToken: "rt-old" }));
  assert.equal(await client.getToken(), "at-cc");
  assert.deepEqual(calls[0].form, {
    grant_type: "refresh_token",
    refresh_token: "rt-old",
    client_id: "bo-mcp-test",
    client_secret: "s3cret",
  });
  assert.equal(calls[1].form.grant_type, "client_credentials");
});

test("retired username/password/TOTP env alone → no token request, error names the new env", async (t) => {
  const calls = stubFetch(t, []);
  const client = new UBCabBOClient(
    boAuthConfig({
      UBCAB_BO_USERNAME: "someone@ubcab.mn",
      UBCAB_BO_PASSWORD: "pw",
      UBCAB_BO_TOTP_SECRET: "not-a-real-totp-secret",
    })
  );
  await assert.rejects(client.getToken(), (err) => {
    assert.match(err.message, /UBCAB_BO_CLIENT_SECRET/);
    assert.match(err.message, /2026-11-02/);
    return true;
  });
  assert.equal(calls.length, 0);
});

test("Keycloak rejection is logged with grant, client and error code — never the secret", async (t) => {
  stubFetch(t, [
    { status: 401, body: { error: "unauthorized_client", error_description: "Invalid client or Invalid client credentials" } },
  ]);
  const logged = [];
  t.mock.method(console, "error", (...args) => logged.push(args.join(" ")));
  const client = new UBCabBOClient(config({ clientSecret: "s3cret-value" }));
  await assert.rejects(client.getToken(), /HTTP 401/);
  assert.equal(logged.length, 1);
  assert.match(logged[0], /client_credentials/);
  assert.match(logged[0], /bo-mcp-test/);
  assert.match(logged[0], /unauthorized_client/);
  assert.doesNotMatch(logged[0], /s3cret-value/);
});

test("API calls carry the service-account bearer token and the BO Origin/Referer", async (t) => {
  const calls = stubFetch(t, [issued("at-1")]);
  const client = new UBCabBOClient(config({ clientSecret: "s3cret" }));
  await client.request("GET", "/v1/driver/select-options/services");
  const api = calls.find((c) => c.kind === "api");
  assert.equal(api.url, "https://api.example.test/v1/driver/select-options/services");
  assert.equal(api.headers.Authorization, "Bearer at-1");
  assert.equal(api.headers.Origin, "https://operator.example.test");
  assert.equal(api.headers.Referer, "https://operator.example.test/");
});

test("registration env: UBCAB_BO_CLIENT_ID + UBCAB_BO_CLIENT_SECRET select the service account", () => {
  const cfg = boAuthConfig({ UBCAB_BO_CLIENT_ID: "bo-mcp-registration", UBCAB_BO_CLIENT_SECRET: "s1" });
  assert.equal(cfg.clientId, "bo-mcp-registration");
  assert.equal(cfg.clientSecret, "s1");
  assert.equal(cfg.apiUrl, "https://registration-bo-api.ubcabtech.com");
  assert.equal(cfg.origin, "https://operator.ubcab.mn");
});

test("marketing reuses the registration service account unless it has its own client id", () => {
  const env = {
    UBCAB_BO_CLIENT_ID: "bo-mcp-registration",
    UBCAB_BO_CLIENT_SECRET: "s1",
    UBCAB_BO_REFRESH_TOKEN: "rt-registration",
  };
  const shared = marketingAuthConfig(env);
  assert.equal(shared.clientId, "bo-mcp-registration");
  assert.equal(shared.clientSecret, "s1");
  assert.equal(shared.refreshToken, "rt-registration");
  const own = marketingAuthConfig({ ...env, UBCAB_MARKETING_CLIENT_ID: "bo-mcp-marketing" });
  assert.equal(own.clientId, "bo-mcp-marketing");
  // Keycloak binds secrets and refresh tokens to their client.
  assert.equal(own.clientSecret, "", "the registration secret must not be sent with another client id");
  assert.equal(own.refreshToken, "", "the registration refresh token must not be sent with another client id");
});

test("express reads its own client id + secret and never borrows the registration secret", () => {
  const env = {
    UBCAB_BO_CLIENT_SECRET: "s1",
    UBCAB_EXPRESS_CLIENT_ID: "bo-mcp-express",
    UBCAB_EXPRESS_CLIENT_SECRET: "s2",
  };
  assert.deepEqual(
    [expressAuthConfig(env).clientId, expressAuthConfig(env).clientSecret],
    ["bo-mcp-express", "s2"]
  );
  assert.equal(expressAuthConfig({ UBCAB_BO_CLIENT_SECRET: "s1" }).clientSecret, "");
});

test("ubeats reuses the registration service account unless it has its own client id", () => {
  const env = {
    UBCAB_BO_CLIENT_ID: "bo-mcp-registration",
    UBCAB_BO_CLIENT_SECRET: "s1",
    UBCAB_BO_REFRESH_TOKEN: "rt-registration",
  };
  const shared = ubeatsAuthConfig(env);
  assert.deepEqual(
    [shared.clientId, shared.clientSecret, shared.refreshToken],
    ["bo-mcp-registration", "s1", "rt-registration"]
  );
  const own = ubeatsAuthConfig({ ...env, UBEATS_CLIENT_ID: "bo-mcp-ubeats", UBEATS_CLIENT_SECRET: "s3" });
  assert.deepEqual([own.clientId, own.clientSecret, own.refreshToken], ["bo-mcp-ubeats", "s3", ""]);
});

test("ubeats calls carry the UBEats BO web app origin", () => {
  // office.ubeats.mn is what the UBEats BO client allows (#1, verified 2026-10-16).
  assert.equal(ubeatsAuthConfig({}).origin, "https://office.ubeats.mn");
});

test("auth error names build, client, origin, grant and credential env — never the secret", async (t) => {
  t.mock.method(console, "error", () => {});
  stubFetch(t, [{ status: 401, body: { error: "invalid_client" } }]);
  const client = new UBCabBOClient(config({ clientSecret: "s3cret-value" }));
  await assert.rejects(client.getToken(), (err) => {
    assert.match(
      err.message,
      /\[build [^,\]]+, client=bo-mcp-test, origin=https:\/\/operator\.example\.test, grant=client_credentials, creds=UBCAB_BO_\*\]/
    );
    assert.doesNotMatch(err.message, /s3cret-value/);
    return true;
  });
});
