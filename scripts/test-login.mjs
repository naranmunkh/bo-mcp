#!/usr/bin/env node
/**
 * Quick live test: authenticate against Keycloak, then run a driver search.
 * Usage:
 *   1. cp .env.example .env  &&  fill creds
 *   2. node --env-file=.env scripts/test-login.mjs [searchQuery]
 *
 * (Node 20.6+ supports --env-file. Otherwise export the vars manually.)
 */

const SSO_URL = process.env.UBCAB_BO_SSO_URL || "https://sso.ubcabtech.com";
const REALM = process.env.UBCAB_BO_REALM || "ubcab-bo";
const API_URL = process.env.UBCAB_BO_API_URL || "https://registration-bo-api.ubcabtech.com";
const CLIENT_ID = process.env.UBCAB_BO_CLIENT_ID || "ubcab-registration-bo";
const ORIGIN = process.env.UBCAB_BO_ORIGIN || "https://operator.ubcab.mn";
const TOKEN_URL = `${SSO_URL}/realms/${REALM}/protocol/openid-connect/token`;
const query = process.argv[2] || "99054120";

// Same RFC 6238 generator as api/index.ts (2026-10-05, Keycloak 2FA).
async function totpNow(secret) {
  const { createHmac } = await import("node:crypto");
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = 0, value = 0; const bytes = [];
  for (const ch of secret.toUpperCase().replace(/[\s=-]/g, "")) {
    const i = alphabet.indexOf(ch); if (i < 0) throw new Error("TOTP secret is not base32");
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { bytes.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  const counter = Math.floor(Date.now() / 30000);
  const msg = Buffer.alloc(8); msg.writeUInt32BE(Math.floor(counter / 0x100000000), 0); msg.writeUInt32BE(counter >>> 0, 4);
  const h = createHmac("sha1", Buffer.from(bytes)).update(msg).digest();
  const o = h[h.length - 1] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 1e6).padStart(6, "0");
}

async function getToken() {
  let params;
  if (process.env.UBCAB_BO_REFRESH_TOKEN) {
    params = {
      grant_type: "refresh_token",
      refresh_token: process.env.UBCAB_BO_REFRESH_TOKEN,
      client_id: CLIENT_ID,
    };
  } else if (process.env.UBCAB_BO_USERNAME && process.env.UBCAB_BO_PASSWORD) {
    params = {
      grant_type: "password",
      client_id: CLIENT_ID,
      username: process.env.UBCAB_BO_USERNAME,
      password: process.env.UBCAB_BO_PASSWORD,
      scope: "openid",
    };
    if (process.env.UBCAB_BO_TOTP_SECRET) params.totp = await totpNow(process.env.UBCAB_BO_TOTP_SECRET);
  } else {
    throw new Error("Set UBCAB_BO_USERNAME+PASSWORD or UBCAB_BO_REFRESH_TOKEN");
  }
  const res = await fetch(TOKEN_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
      Origin: ORIGIN,
      Referer: `${ORIGIN}/`,
    },
    body: new URLSearchParams(params).toString(),
  });
  const text = await res.text();
  if (!res.ok) throw new Error(`Auth failed HTTP ${res.status}: ${text}`);
  const json = JSON.parse(text);
  console.log(`✓ Token OK (expires_in=${json.expires_in}s, grant=${params.grant_type})`);
  return json.access_token;
}

async function main() {
  const token = await getToken();
  const res = await fetch(`${API_URL}/v1/driver/drivers/list`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json, text/plain, */*",
      "Accept-Language": "mn",
      "Content-Type": "application/json",
      Origin: ORIGIN,
      Referer: `${ORIGIN}/`,
    },
    body: JSON.stringify({ limit: 5, includeTotal: true, page: 1, filter: { query } }),
  });
  const text = await res.text();
  console.log(`\nDriver search "${query}" → HTTP ${res.status}`);
  try {
    const json = JSON.parse(text);
    const list = json?.data?.items ?? json?.data?.list ?? json?.data ?? json;
    console.log(JSON.stringify(json.success !== undefined ? { success: json.success } : {}, null, 2));
    console.log("rows:", Array.isArray(list) ? list.length : "(see shape below)");
    console.log(JSON.stringify(json, null, 2).slice(0, 2000));
  } catch {
    console.log(text.slice(0, 1000));
  }
}

main().catch((e) => {
  console.error("✗", e.message);
  process.exit(1);
});
