#!/usr/bin/env node
/**
 * Live smoke test of the BO logins through the SAME client code as the server.
 * For every API whose credentials are in the env (client secret or refresh token)
 * it gets a token and makes one read-only call. Prints only status / success /
 * row count — no BO data, no tokens.
 *   npm run test:login            (compiles, loads .env when present)
 */
import {
  UBCabBOClient,
  boAuthConfig,
  marketingAuthConfig,
  expressAuthConfig,
  ubeatsAuthConfig,
} from "../dist/api/index.js";

const page = { page: 1, limit: 1, includeTotal: true };
const checks = [
  ["registration-bo-api", boAuthConfig, "GET", "/v1/driver/select-options/services"],
  ["marketing-bo-api", marketingAuthConfig, "GET", "/v1/content/api/help/select-options/language"],
  ["operator-api (express)", expressAuthConfig, "POST", "/v1/api/address-ready-shipments/list", page],
  ["ubeats-bo-api", ubeatsAuthConfig, "POST", "/v1/api/orders/list", page],
];

let failed = 0;
let ran = 0;
for (const [name, toConfig, method, path, body] of checks) {
  const cfg = toConfig(process.env);
  if (!cfg.clientSecret && !cfg.refreshToken) {
    console.log(`– ${name}: skipped (no ${cfg.envPrefix}_CLIENT_SECRET or _REFRESH_TOKEN)`);
    continue;
  }
  ran++;
  try {
    const res = await new UBCabBOClient(cfg).request(method, path, body ? { body } : {});
    const data = res.body?.data ?? res.body;
    const rows = Array.isArray(data) ? data.length : (data?.docs ?? data?.items)?.length ?? "?";
    console.log(`✓ ${name}: HTTP ${res.status} success=${res.body?.success} rows=${rows} (client ${cfg.clientId})`);
  } catch (err) {
    failed++;
    const detail = err.body ? ` ${JSON.stringify(err.body).slice(0, 300)}` : "";
    console.log(`✗ ${name} (client ${cfg.clientId}): ${err.message}${detail}`);
  }
}
if (!ran) console.log("Nothing configured — set UBCAB_BO_CLIENT_ID + UBCAB_BO_CLIENT_SECRET (see .env.example).");
process.exit(failed || !ran ? 1 : 0);
