#!/usr/bin/env node
/**
 * UBCab Backoffice (registration-bo) MCP server — single self-contained entry point.
 *
 * Runs two ways from this one file:
 *   - HTTP mode  (Vercel): serves the MCP over Streamable HTTP at /mcp,
 *     guarded by a bearer token + OAuth 2.1 (PKCE).
 *   - stdio mode (local / Claude Desktop): when run directly.
 *
 * SELF-CONTAINED ON PURPOSE: no relative imports, so neither Vercel's bundler
 * nor Node's ESM loader has to resolve sibling ".ts"/".js" files.
 *
 * UBCab BO auth flow (Keycloak SSO, realm "ubcab-bo"):
 *   Token endpoint: {SSO_URL}/realms/{REALM}/protocol/openid-connect/token
 *   The BO web app (operator.ubcab.mn) uses the public client
 *   "ubcab-registration-bo". This server gets an access token two ways:
 *     1. password grant   -> UBCAB_BO_USERNAME + UBCAB_BO_PASSWORD
 *     2. refresh_token     -> UBCAB_BO_REFRESH_TOKEN
 *   Access tokens are short-lived (~5 min); we cache until ~30s before expiry
 *   and silently re-auth. If a refresh_token comes back, we keep using it.
 *   Every API call also sends Origin/Referer = operator.ubcab.mn to satisfy
 *   the BO's allowed-origins check.
 *
 * Env:
 *   UBCAB_BO_USERNAME, UBCAB_BO_PASSWORD   password-grant creds (recommended)
 *   UBCAB_BO_REFRESH_TOKEN                 alternative to username/password
 *   UBCAB_BO_CLIENT_ID                     OIDC client (default ubcab-registration-bo)
 *   UBCAB_BO_SSO_URL                       Keycloak base (default https://sso.ubcabtech.com)
 *   UBCAB_BO_REALM                         realm (default ubcab-bo)
 *   UBCAB_BO_API_URL                       API base (default https://registration-bo-api.ubcabtech.com)
 *   UBCAB_BO_ORIGIN                        Origin/Referer (default https://operator.ubcab.mn)
 *   UBCAB_BO_MCP_AUTH_TOKEN                required in HTTP mode (fails closed)
 */

import type { IncomingMessage, ServerResponse } from "node:http";
import { timingSafeEqual, createHmac, createHash } from "node:crypto";
import { pathToFileURL } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";

// ===========================================================================
// UBCab BO API client (Keycloak auth)
// ===========================================================================

const DEFAULT_SSO_URL = "https://sso.ubcabtech.com";
const DEFAULT_REALM = "ubcab-bo";
const DEFAULT_API_URL = "https://registration-bo-api.ubcabtech.com";
const DEFAULT_CLIENT_ID = "ubcab-registration-bo";
const DEFAULT_ORIGIN = "https://operator.ubcab.mn";

type HttpMethod = "GET" | "POST" | "PATCH" | "PUT" | "DELETE";

interface BOResult {
  status: number;
  ok: boolean;
  /** Parsed JSON body (or raw text / null). */
  body: unknown;
}

class BOError extends Error {
  constructor(message: string, public status?: number, public body?: unknown) {
    super(message);
    this.name = "BOError";
  }
}

interface RequestOptions {
  query?: Record<string, unknown>;
  body?: unknown;
  /** Override Accept-Language (default "mn"). */
  lang?: string;
}

interface AuthConfig {
  username: string;
  password: string;
  refreshToken: string;
  clientId: string;
  ssoUrl: string;
  realm: string;
  apiUrl: string;
  origin: string;
}

class UBCabBOClient {
  private readonly apiUrl: string;
  private readonly tokenUrl: string;
  private readonly origin: string;
  private readonly clientId: string;
  private token: string | null = null;
  private tokenExpiresAt = 0;
  private refreshToken: string;
  private loginInFlight: Promise<string> | null = null;

  constructor(private readonly cfg: AuthConfig) {
    this.apiUrl = (cfg.apiUrl || DEFAULT_API_URL).replace(/\/+$/, "");
    const sso = (cfg.ssoUrl || DEFAULT_SSO_URL).replace(/\/+$/, "");
    const realm = cfg.realm || DEFAULT_REALM;
    this.tokenUrl = `${sso}/realms/${encodeURIComponent(realm)}/protocol/openid-connect/token`;
    this.origin = (cfg.origin || DEFAULT_ORIGIN).replace(/\/+$/, "");
    this.clientId = cfg.clientId || DEFAULT_CLIENT_ID;
    this.refreshToken = cfg.refreshToken || "";
  }

  get apiBaseUrl(): string {
    return this.apiUrl;
  }

  /** Get a valid access token, re-authenticating when expired. */
  async getToken(force = false): Promise<string> {
    if (!force && this.token && Date.now() < this.tokenExpiresAt) return this.token;
    if (this.loginInFlight) return this.loginInFlight;
    this.loginInFlight = this.authenticate().finally(() => {
      this.loginInFlight = null;
    });
    return this.loginInFlight;
  }

  private async authenticate(): Promise<string> {
    const hasPassword = !!(this.cfg.username && this.cfg.password);
    // Prefer refresh_token (cheaper, avoids re-sending creds); fall back to password.
    if (this.refreshToken) {
      try {
        return await this.tokenRequest({
          grant_type: "refresh_token",
          refresh_token: this.refreshToken,
          client_id: this.clientId,
        });
      } catch (err) {
        if (!hasPassword) throw err; // nothing else to try
        // refresh expired/rotated — fall through to password grant
      }
    }
    if (hasPassword) {
      return this.tokenRequest({
        grant_type: "password",
        client_id: this.clientId,
        username: this.cfg.username,
        password: this.cfg.password,
        scope: "openid",
      });
    }
    throw new BOError(
      "No credentials. Set UBCAB_BO_USERNAME + UBCAB_BO_PASSWORD, or UBCAB_BO_REFRESH_TOKEN."
    );
  }

  private async tokenRequest(params: Record<string, string>): Promise<string> {
    const res = await fetch(this.tokenUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/x-www-form-urlencoded",
        Accept: "application/json",
        Origin: this.origin,
        Referer: `${this.origin}/`,
      },
      body: new URLSearchParams(params).toString(),
    });
    const body = await safeJson(res);
    if (!res.ok) {
      throw new BOError(`Keycloak auth failed (HTTP ${res.status})`, res.status, body);
    }
    const obj = (body ?? {}) as Record<string, any>;
    const token = obj.access_token;
    if (typeof token !== "string" || !token) {
      throw new BOError("Auth succeeded but no access_token in response.", res.status, body);
    }
    this.token = token;
    const expiresIn = typeof obj.expires_in === "number" ? obj.expires_in : 300;
    // 30s safety buffer.
    this.tokenExpiresAt = Date.now() + Math.max(0, expiresIn - 30) * 1000;
    // Keep the freshest refresh token if Keycloak rotated it.
    if (typeof obj.refresh_token === "string" && obj.refresh_token) {
      this.refreshToken = obj.refresh_token;
    }
    return token;
  }

  async request(method: HttpMethod, path: string, opts: RequestOptions = {}): Promise<BOResult> {
    const url = new URL(`${this.apiUrl}${path}`);
    if (opts.query) {
      for (const [k, v] of Object.entries(opts.query)) {
        if (v !== undefined && v !== null && v !== "") url.searchParams.set(k, String(v));
      }
    }

    const buildHeaders = (token: string): Record<string, string> => {
      const h: Record<string, string> = {
        Authorization: `Bearer ${token}`,
        Accept: "application/json, text/plain, */*",
        "Accept-Language": opts.lang || "mn",
        Origin: this.origin,
        Referer: `${this.origin}/`,
      };
      if (opts.body !== undefined) h["Content-Type"] = "application/json";
      return h;
    };

    const doRequest = (token: string) =>
      fetch(url.toString(), {
        method,
        headers: buildHeaders(token),
        body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
      });

    let token = await this.getToken();
    let res = await doRequest(token);
    if (res.status === 401 || res.status === 403) {
      token = await this.getToken(true);
      res = await doRequest(token);
    }
    const body = await safeJson(res);
    if (!res.ok) {
      throw new BOError(`UBCab BO API error on ${method} ${path} (HTTP ${res.status})`, res.status, body);
    }
    return { status: res.status, ok: true, body };
  }
}

async function safeJson(res: Response): Promise<unknown> {
  const text = await res.text();
  if (!text) return null;
  try {
    return JSON.parse(text);
  } catch {
    return text;
  }
}

// ===========================================================================
// MCP server + tools
// ===========================================================================

let cachedClient: UBCabBOClient | null = null;
function getClient(): UBCabBOClient {
  if (!cachedClient) {
    cachedClient = new UBCabBOClient({
      username: process.env.UBCAB_BO_USERNAME ?? "",
      password: process.env.UBCAB_BO_PASSWORD ?? "",
      refreshToken: process.env.UBCAB_BO_REFRESH_TOKEN ?? "",
      clientId: process.env.UBCAB_BO_CLIENT_ID ?? DEFAULT_CLIENT_ID,
      ssoUrl: process.env.UBCAB_BO_SSO_URL ?? DEFAULT_SSO_URL,
      realm: process.env.UBCAB_BO_REALM ?? DEFAULT_REALM,
      apiUrl: process.env.UBCAB_BO_API_URL ?? DEFAULT_API_URL,
      origin: process.env.UBCAB_BO_ORIGIN ?? DEFAULT_ORIGIN,
    });
  }
  return cachedClient;
}

type ToolResult = { content: { type: "text"; text: string }[]; isError?: boolean };

function toToolResult(result: BOResult): ToolResult {
  if (result.status === 204 || result.body === null) {
    return {
      content: [
        { type: "text", text: JSON.stringify({ note: `HTTP ${result.status} — empty response.` }, null, 2) },
      ],
    };
  }
  // The BO API wraps responses as {success, data} / {success:false, error}.
  const body = result.body as any;
  const isErr = body && typeof body === "object" && body.success === false;
  return {
    content: [{ type: "text", text: JSON.stringify(body, null, 2) }],
    isError: isErr || undefined,
  };
}

async function guarded(fn: () => Promise<BOResult>): Promise<ToolResult> {
  try {
    return toToolResult(await fn());
  } catch (err) {
    if (err instanceof BOError) {
      const detail = err.body != null ? `\n${JSON.stringify(err.body, null, 2)}` : "";
      return { content: [{ type: "text", text: `${err.message}${detail}` }], isError: true };
    }
    const message = err instanceof Error ? err.message : String(err);
    return { content: [{ type: "text", text: message }], isError: true };
  }
}

const driverIdSchema = z
  .string()
  .min(1)
  .describe("Жолоочийн ID (Mongo ObjectId, ж: 641021242019b355fdda8686). driver_search-аас _id-г ав.");

const tripIdSchema = z
  .string()
  .min(1)
  .describe("Аяллын ID (Mongo ObjectId, ж: 6a36a0a734b3fd628db888c6). trip_get хариуны _id.");

function createMcpServer(): McpServer {
  const server = new McpServer({ name: "ubcab-bo-mcp", version: "1.0.0" });
  const client = getClient();

  const reg = (
    name: string,
    description: string,
    shape: z.ZodRawShape,
    handler: (args: any) => Promise<ToolResult>
  ) => server.tool(name, description, shape, handler);

  // -------------------------------------------------------------------------
  // Driver search — POST /v1/driver/drivers/list
  // -------------------------------------------------------------------------
  reg(
    "ubcab_bo_driver_search",
    "Жолоочийг утас/регистр/нэр/shortId зэрэг чөлөөт хайлтаар хайх. " +
      "POST /v1/driver/drivers/list. Хариунд жолоочдын жагсаалт ба тус бүрийн _id ирнэ; " +
      "тэр _id-г driver_get / driver_rating / driver_set_state-д driverId болгон ашигла.",
    {
      query: z
        .string()
        .min(1)
        .describe("Хайх утга — утасны дугаар, регистр, нэр, эсвэл shortId (ж: \"99054120\")."),
      page: z.number().int().positive().optional().describe("Хуудасны дугаар (default 1)."),
      limit: z.number().int().positive().max(100).optional().describe("Нэг хуудасны мөр (default 20)."),
      includeTotal: z.boolean().optional().describe("Нийт тоог буцаах эсэх (default true)."),
    },
    ({ query, page, limit, includeTotal }) =>
      guarded(() =>
        client.request("POST", "/v1/driver/drivers/list", {
          body: {
            limit: limit ?? 20,
            includeTotal: includeTotal ?? true,
            page: page ?? 1,
            filter: { query },
          },
        })
      )
  );

  // -------------------------------------------------------------------------
  // Driver detail — GET /v1/driver/drivers/{driverId}
  // -------------------------------------------------------------------------
  reg(
    "ubcab_bo_driver_get",
    "Нэг жолоочийн дэлгэрэнгүй мэдээлэл (profile, vehicle, kyc, ebarimt, services, төлөв г.м). " +
      "GET /v1/driver/drivers/{driverId}. ⚠ Хувийн мэдээлэл (нэр, утас, регистр, иргэний үнэмлэх) агуулна.",
    { driverId: driverIdSchema },
    ({ driverId }) =>
      guarded(() => client.request("GET", `/v1/driver/drivers/${encodeURIComponent(driverId)}`))
  );

  // -------------------------------------------------------------------------
  // Driver rating — GET /v1/driver/rating/{driverId}
  // -------------------------------------------------------------------------
  reg(
    "ubcab_bo_driver_rating",
    "Жолоочийн үнэлгээ. GET /v1/driver/rating/{driverId}.",
    { driverId: driverIdSchema },
    ({ driverId }) =>
      guarded(() => client.request("GET", `/v1/driver/rating/${encodeURIComponent(driverId)}`))
  );

  // -------------------------------------------------------------------------
  // Driver state change — PUT /v1/driver/drivers/{driverId}/state
  // -------------------------------------------------------------------------
  reg(
    "ubcab_bo_driver_set_state",
    "Жолоочийн төлөв солих: 'normal' (Хэвийн) эсвэл 'suspended' (Түр хаасан). " +
      "PUT /v1/driver/drivers/{driverId}/state. reason нь ЗААВАЛ 10-аас дээш тэмдэгт. " +
      "Жолооч аль хэдийн тухайн төлөвт байвал 996 алдаа буцна. ⚠ Бичих/өөрчлөх үйлдэл — болгоомжтой.",
    {
      driverId: driverIdSchema,
      state: z.enum(["normal", "suspended"]).describe("Шинэ төлөв: normal=Хэвийн, suspended=Түр хаасан."),
      reason: z.string().min(10, "reason 10-аас дээш тэмдэгт байх ёстой.").describe("Шалтгаан (≥10 тэмдэгт)."),
    },
    ({ driverId, state, reason }) =>
      guarded(() =>
        client.request("PUT", `/v1/driver/drivers/${encodeURIComponent(driverId)}/state`, {
          body: { state, reason },
        })
      )
  );

  // -------------------------------------------------------------------------
  // Service select-options — GET /v1/driver/select-options/services
  // -------------------------------------------------------------------------
  reg(
    "ubcab_bo_service_options",
    "Үйлчилгээний сонголтын жагсаалт (select-options). GET /v1/driver/select-options/services.",
    {},
    () => guarded(() => client.request("GET", "/v1/driver/select-options/services"))
  );

  // =========================================================================
  // TRIPS — GET /v1/taxi/api/trips/{tripId}[/...]
  // =========================================================================
  const tripBase = "/v1/taxi/api/trips";

  // --- main trip detail ---
  reg(
    "ubcab_bo_trip_get",
    "Аяллын ҮНДСЭН бүх мэдээлэл. GET /v1/taxi/api/trips/{tripId}. " +
      "Хариуны data-д: trackingNumber, region/subRegion, service/variation, status, " +
      "pickup/dropoff/finalDropoff, rider, driver, serviceProjection, fee, charge, metrics, " +
      "tariff, config, billingConfig, invoices, timeline, history, route, riderLoyalty, rate, " +
      "fraud, createdAt/By, updatedAt/By г.м. ⚠ Жолооч/зорчигчийн хувийн мэдээлэл агуулж болзошгүй.",
    { tripId: tripIdSchema },
    ({ tripId }) => guarded(() => client.request("GET", `${tripBase}/${encodeURIComponent(tripId)}`))
  );

  // --- routes (GPS path) ---
  reg(
    "ubcab_bo_trip_routes",
    "Аяллын маршрут (GPS зам). GET /v1/taxi/api/trips/{tripId}/routes. Хариу: { type, routes }.",
    { tripId: tripIdSchema },
    ({ tripId }) => guarded(() => client.request("GET", `${tripBase}/${encodeURIComponent(tripId)}/routes`))
  );

  // --- invoices ---
  reg(
    "ubcab_bo_trip_invoices",
    "Аяллын нэхэмжлэл. GET /v1/taxi/api/trips/{tripId}/invoices. " +
      "Массив: invoiceNumber, paymentType, status, paidAmount, totalAmount, payments…",
    { tripId: tripIdSchema },
    ({ tripId }) => guarded(() => client.request("GET", `${tripBase}/${encodeURIComponent(tripId)}/invoices`))
  );

  // --- charges (price breakdown) ---
  reg(
    "ubcab_bo_trip_charges",
    "Аяллын төлбөр тооцооны задаргаа. GET /v1/taxi/api/trips/{tripId}/charges. " +
      "Хариу: { charges, serviceProjection, fee, total }.",
    { tripId: tripIdSchema },
    ({ tripId }) => guarded(() => client.request("GET", `${tripBase}/${encodeURIComponent(tripId)}/charges`))
  );

  // --- complaints ---
  reg(
    "ubcab_bo_trip_complaints",
    "Аялалтай холбоотой гомдол. GET /v1/taxi/api/trips/{tripId}/complaints. " +
      "Массив: ticketStatus, ticketType, description, recordings…",
    { tripId: tripIdSchema },
    ({ tripId }) =>
      guarded(() => client.request("GET", `${tripBase}/${encodeURIComponent(tripId)}/complaints`))
  );

  // --- penalties ---
  reg(
    "ubcab_bo_trip_penalties",
    "Аялалтай холбоотой торгууль. GET /v1/taxi/api/trips/{tripId}/penalties. (Ихэвчлэн хоосон массив.)",
    { tripId: tripIdSchema },
    ({ tripId }) =>
      guarded(() => client.request("GET", `${tripBase}/${encodeURIComponent(tripId)}/penalties`))
  );

  // --- loyalty ---
  reg(
    "ubcab_bo_trip_loyalty",
    "Аяллын урамшуулал. GET /v1/taxi/api/trips/{tripId}/loyalty. Хариу: { loyalty }.",
    { tripId: tripIdSchema },
    ({ tripId }) => guarded(() => client.request("GET", `${tripBase}/${encodeURIComponent(tripId)}/loyalty`))
  );

  return server;
}

// ===========================================================================
// HTTP mode (Vercel) — bearer-guarded Streamable HTTP + OAuth 2.1 (PKCE)
// ===========================================================================

function tokenMatches(provided: string | null | undefined): boolean {
  const expected = process.env.UBCAB_BO_MCP_AUTH_TOKEN;
  if (!expected || !provided) return false; // fail closed
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function bearerToken(req: IncomingMessage): string | null {
  const raw = req.headers["authorization"] ?? "";
  const header = Array.isArray(raw) ? raw[0] : raw;
  const match = /^Bearer\s+(.+)$/i.exec(header);
  return match ? match[1] : null;
}

/** Token embedded in the path, e.g. /mcp/<token>. */
function pathToken(url: URL): string | null {
  const segments = url.pathname.split("/").filter(Boolean);
  if (segments.length >= 2 && segments[0] === "mcp") return segments[1];
  return null;
}

function sendJson(res: ServerResponse, status: number, body: unknown): void {
  res.writeHead(status, { "Content-Type": "application/json" });
  res.end(JSON.stringify(body));
}

function sendHtml(res: ServerResponse, status: number, html: string): void {
  res.writeHead(status, { "Content-Type": "text/html; charset=utf-8" });
  res.end(html);
}

async function readBody(req: IncomingMessage): Promise<unknown> {
  const chunks: Buffer[] = [];
  for await (const c of req) chunks.push(c as Buffer);
  const raw = Buffer.concat(chunks).toString("utf8");
  if (!raw) return undefined;
  try {
    return JSON.parse(raw);
  } catch {
    return undefined;
  }
}

async function readForm(req: IncomingMessage): Promise<Record<string, string>> {
  const pre = (req as IncomingMessage & { body?: unknown }).body;
  if (pre && typeof pre === "object" && !Buffer.isBuffer(pre)) {
    return pre as Record<string, string>;
  }
  let raw = typeof pre === "string" ? pre : "";
  if (!raw) {
    const chunks: Buffer[] = [];
    for await (const c of req) chunks.push(c as Buffer);
    raw = Buffer.concat(chunks).toString("utf8");
  }
  const out: Record<string, string> = {};
  for (const [k, v] of new URLSearchParams(raw)) out[k] = v;
  return out;
}

function hmac(data: string): string {
  return createHmac("sha256", process.env.UBCAB_BO_MCP_AUTH_TOKEN ?? "").update(data).digest("base64url");
}

function signPayload(obj: unknown): string {
  const p = Buffer.from(JSON.stringify(obj)).toString("base64url");
  return `${p}.${hmac(p)}`;
}

function verifySigned(token: string): Record<string, any> | null {
  const dot = token.lastIndexOf(".");
  if (dot < 0) return null;
  const p = token.slice(0, dot);
  const sig = token.slice(dot + 1);
  const expected = hmac(p);
  const a = Buffer.from(sig);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  try {
    const obj = JSON.parse(Buffer.from(p, "base64url").toString("utf8"));
    if (typeof obj.exp === "number" && Date.now() > obj.exp) return null;
    return obj;
  } catch {
    return null;
  }
}

function mintAuthCode(redirectUri: string, codeChallenge: string): string {
  return signPayload({ t: "code", ru: redirectUri, cc: codeChallenge, exp: Date.now() + 5 * 60 * 1000 });
}

function mintAccessToken(): string {
  return signPayload({ t: "at", sub: "ubcab-bo", exp: Date.now() + 30 * 24 * 60 * 60 * 1000 });
}

function isValidAccessToken(token: string | null | undefined): boolean {
  if (!token) return false;
  const obj = verifySigned(token);
  return !!obj && obj.t === "at";
}

function pkceOk(verifier: string, challenge: string): boolean {
  const h = createHash("sha256").update(verifier).digest("base64url");
  const a = Buffer.from(h);
  const b = Buffer.from(challenge);
  return a.length === b.length && timingSafeEqual(a, b);
}

function baseUrl(req: IncomingMessage): string {
  const proto = (req.headers["x-forwarded-proto"] as string) || "https";
  const host = req.headers.host ?? "localhost";
  return `${proto}://${host}`;
}

function escapeHtml(s: string): string {
  return s.replace(/[&<>"']/g, (c) =>
    ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c] as string)
  );
}

function authorizePage(params: URLSearchParams, error?: string): string {
  const hidden = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "response_type"]
    .map((k) => `<input type="hidden" name="${k}" value="${escapeHtml(params.get(k) ?? "")}">`)
    .join("\n");
  return `<!doctype html><html lang="mn"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1"><title>UBCab BO MCP — Нэвтрэх</title>
<style>body{font-family:ui-sans-serif,system-ui,-apple-system,sans-serif;max-width:380px;margin:5rem auto;padding:0 1.25rem;color:#1a1a1a}
h1{font-size:1.25rem}label{display:block;margin:1rem 0 .35rem;font-size:.9rem}
input[type=password]{width:100%;padding:.6rem;border:1px solid #ccc;border-radius:8px;font-size:1rem;box-sizing:border-box}
button{margin-top:1rem;width:100%;padding:.65rem;border:0;border-radius:8px;background:#1a1a1a;color:#fff;font-size:1rem;cursor:pointer}
.err{color:#b00020;font-size:.9rem;margin-top:.75rem}.muted{color:#666;font-size:.85rem;margin-top:1rem}</style></head>
<body><h1>UBCab BO MCP холболт</h1><p class="muted">UBCab Backoffice MCP сервер рүү холбогдохын тулд хандах түлхүүрээ оруулна уу.</p>
<form method="POST" action="/authorize">${hidden}
<label for="pw">Хандах түлхүүр (access token)</label>
<input id="pw" type="password" name="password" autocomplete="off" autofocus required>
${error ? `<div class="err">${escapeHtml(error)}</div>` : ""}
<button type="submit">Зөвшөөрөх</button></form></body></html>`;
}

export default async function handler(req: IncomingMessage, res: ServerResponse): Promise<void> {
  const url = new URL(req.url ?? "/", `http://${req.headers.host ?? "localhost"}`);
  const path = url.pathname;
  const method = req.method ?? "GET";

  if (method === "GET" && path === "/health") {
    sendJson(res, 200, { status: "ok", server: "ubcab-bo-mcp" });
    return;
  }

  // ---- OAuth discovery metadata ----
  if (method === "GET" && path === "/.well-known/oauth-protected-resource") {
    const base = baseUrl(req);
    sendJson(res, 200, { resource: `${base}/mcp`, authorization_servers: [base] });
    return;
  }
  if (
    method === "GET" &&
    (path === "/.well-known/oauth-authorization-server" || path === "/.well-known/openid-configuration")
  ) {
    const base = baseUrl(req);
    sendJson(res, 200, {
      issuer: base,
      authorization_endpoint: `${base}/authorize`,
      token_endpoint: `${base}/token`,
      registration_endpoint: `${base}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      code_challenge_methods_supported: ["S256"],
      token_endpoint_auth_methods_supported: ["none"],
      scopes_supported: ["mcp"],
    });
    return;
  }

  // ---- OAuth dynamic client registration ----
  if (method === "POST" && path === "/register") {
    let reg = (req as IncomingMessage & { body?: unknown }).body as Record<string, unknown> | string | undefined;
    if (reg === undefined || typeof reg === "string") reg = (await readBody(req)) as Record<string, unknown>;
    const redirectUris = Array.isArray((reg as any)?.redirect_uris) ? (reg as any).redirect_uris : [];
    sendJson(res, 201, {
      client_id: "ubcab-bo-mcp",
      token_endpoint_auth_method: "none",
      grant_types: ["authorization_code"],
      response_types: ["code"],
      redirect_uris: redirectUris,
    });
    return;
  }

  // ---- OAuth authorize ----
  if (path === "/authorize") {
    if (!process.env.UBCAB_BO_MCP_AUTH_TOKEN) {
      sendJson(res, 500, { error: "server_error", error_description: "UBCAB_BO_MCP_AUTH_TOKEN not set" });
      return;
    }
    if (method === "GET") {
      sendHtml(res, 200, authorizePage(url.searchParams));
      return;
    }
    if (method === "POST") {
      const form = await readForm(req);
      const params = new URLSearchParams();
      for (const k of ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "response_type"]) {
        if (form[k] !== undefined) params.set(k, form[k]);
      }
      const redirectUri = form.redirect_uri ?? "";
      const codeChallenge = form.code_challenge ?? "";
      if (!redirectUri || !codeChallenge || form.code_challenge_method !== "S256") {
        sendHtml(res, 400, authorizePage(params, "Буруу хүсэлт (PKCE S256 шаардлагатай)."));
        return;
      }
      if (!tokenMatches(form.password)) {
        sendHtml(res, 401, authorizePage(params, "Хандах түлхүүр буруу байна."));
        return;
      }
      const code = mintAuthCode(redirectUri, codeChallenge);
      const sep = redirectUri.includes("?") ? "&" : "?";
      let location = `${redirectUri}${sep}code=${encodeURIComponent(code)}`;
      if (form.state) location += `&state=${encodeURIComponent(form.state)}`;
      res.writeHead(302, { Location: location });
      res.end();
      return;
    }
  }

  // ---- OAuth token exchange ----
  if (method === "POST" && path === "/token") {
    const form = await readForm(req);
    if (form.grant_type !== "authorization_code") {
      sendJson(res, 400, { error: "unsupported_grant_type" });
      return;
    }
    const decoded = form.code ? verifySigned(form.code) : null;
    if (!decoded || decoded.t !== "code") {
      sendJson(res, 400, { error: "invalid_grant" });
      return;
    }
    if (form.redirect_uri && form.redirect_uri !== decoded.ru) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "redirect_uri mismatch" });
      return;
    }
    if (!form.code_verifier || !pkceOk(form.code_verifier, decoded.cc)) {
      sendJson(res, 400, { error: "invalid_grant", error_description: "PKCE verification failed" });
      return;
    }
    sendJson(res, 200, {
      access_token: mintAccessToken(),
      token_type: "Bearer",
      expires_in: 30 * 24 * 60 * 60,
      scope: "mcp",
    });
    return;
  }

  // ---- Non-MCP GETs → 404 ----
  if (method === "GET") {
    sendJson(res, 404, { error: "Not found. POST to /mcp for the MCP endpoint." });
    return;
  }
  if (method !== "POST") {
    sendJson(res, 405, { jsonrpc: "2.0", error: { code: -32000, message: "Method not allowed" }, id: null });
    return;
  }

  // ---- MCP endpoint (POST /mcp or /mcp/<token>) ----
  if (!process.env.UBCAB_BO_MCP_AUTH_TOKEN) {
    sendJson(res, 500, {
      jsonrpc: "2.0",
      error: { code: -32001, message: "Server misconfigured: UBCAB_BO_MCP_AUTH_TOKEN not set." },
      id: null,
    });
    return;
  }
  const bearer = bearerToken(req);
  const authed = isValidAccessToken(bearer) || tokenMatches(bearer) || tokenMatches(pathToken(url));
  if (!authed) {
    res.writeHead(401, {
      "Content-Type": "application/json",
      "WWW-Authenticate": `Bearer resource_metadata="${baseUrl(req)}/.well-known/oauth-protected-resource"`,
    });
    res.end(JSON.stringify({ jsonrpc: "2.0", error: { code: -32001, message: "Unauthorized" }, id: null }));
    return;
  }

  let body = (req as IncomingMessage & { body?: unknown }).body;
  if (typeof body === "string") {
    try {
      body = JSON.parse(body);
    } catch {
      body = undefined;
    }
  }
  if (body === undefined) body = await readBody(req);

  try {
    const mcp = createMcpServer();
    const transport = new StreamableHTTPServerTransport({
      sessionIdGenerator: undefined,
      enableJsonResponse: true,
    });
    res.on("close", () => {
      void transport.close();
      void mcp.close();
    });
    await mcp.connect(transport);
    await transport.handleRequest(req, res, body);
  } catch (err) {
    if (!res.headersSent) {
      sendJson(res, 500, {
        jsonrpc: "2.0",
        error: { code: -32603, message: err instanceof Error ? err.message : String(err) },
        id: null,
      });
    }
  }
}

// ===========================================================================
// stdio mode (local)
// ===========================================================================

async function startStdio(): Promise<void> {
  const server = createMcpServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("ubcab-bo-mcp server running on stdio");
}

function isRunDirectly(): boolean {
  const entry = process.argv[1];
  if (!entry) return false;
  try {
    return import.meta.url === pathToFileURL(entry).href;
  } catch {
    return false;
  }
}

if (isRunDirectly()) {
  startStdio().catch((err) => {
    console.error("Fatal error starting ubcab-bo-mcp:", err);
    process.exit(1);
  });
}
