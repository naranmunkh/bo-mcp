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

// UBExpress operator API — SAME Keycloak realm (ubcab-bo) but client_id "express-bo",
// different API host (operator-api.ubcabexpress.mn). Needs its own operator account.
const DEFAULT_EXPRESS_API_URL = "https://operator-api.ubcabexpress.mn";
const DEFAULT_EXPRESS_CLIENT_ID = "express-bo";
const DEFAULT_EXPRESS_ORIGIN = "https://office.ubcabexpress.mn";

let cachedExpressClient: UBCabBOClient | null = null;
function getExpressClient(): UBCabBOClient {
  if (!cachedExpressClient) {
    cachedExpressClient = new UBCabBOClient({
      username: process.env.UBCAB_EXPRESS_USERNAME ?? "",
      password: process.env.UBCAB_EXPRESS_PASSWORD ?? "",
      refreshToken: process.env.UBCAB_EXPRESS_REFRESH_TOKEN ?? "",
      clientId: process.env.UBCAB_EXPRESS_CLIENT_ID ?? DEFAULT_EXPRESS_CLIENT_ID,
      ssoUrl: process.env.UBCAB_EXPRESS_SSO_URL ?? DEFAULT_SSO_URL,
      realm: process.env.UBCAB_EXPRESS_REALM ?? DEFAULT_REALM,
      apiUrl: process.env.UBCAB_EXPRESS_API_URL ?? DEFAULT_EXPRESS_API_URL,
      origin: process.env.UBCAB_EXPRESS_ORIGIN ?? DEFAULT_EXPRESS_ORIGIN,
    });
  }
  return cachedExpressClient;
}

// Marketing backoffice API — own host, but the SAME Keycloak realm and (per the
// BO token's audience list) the same login works. Falls back to UBCAB_BO_* creds
// so no extra env is needed; override only if marketing needs its own account.
const DEFAULT_MARKETING_API_URL = "https://marketing-bo-api.ubcabtech.com";

let cachedMarketingClient: UBCabBOClient | null = null;
function getMarketingClient(): UBCabBOClient {
  if (!cachedMarketingClient) {
    cachedMarketingClient = new UBCabBOClient({
      username: process.env.UBCAB_MARKETING_USERNAME ?? process.env.UBCAB_BO_USERNAME ?? "",
      password: process.env.UBCAB_MARKETING_PASSWORD ?? process.env.UBCAB_BO_PASSWORD ?? "",
      refreshToken:
        process.env.UBCAB_MARKETING_REFRESH_TOKEN ?? process.env.UBCAB_BO_REFRESH_TOKEN ?? "",
      clientId:
        process.env.UBCAB_MARKETING_CLIENT_ID ?? process.env.UBCAB_BO_CLIENT_ID ?? DEFAULT_CLIENT_ID,
      ssoUrl: process.env.UBCAB_BO_SSO_URL ?? DEFAULT_SSO_URL,
      realm: process.env.UBCAB_BO_REALM ?? DEFAULT_REALM,
      apiUrl: process.env.UBCAB_MARKETING_API_URL ?? DEFAULT_MARKETING_API_URL,
      origin: process.env.UBCAB_BO_ORIGIN ?? DEFAULT_ORIGIN,
    });
  }
  return cachedMarketingClient;
}

// UBEats backoffice API — again its own host. Same Keycloak realm (ubcab-bo);
// client id / origin are overridable because they differ per BO app.
const DEFAULT_UBEATS_API_URL = "https://ubeats-bo-api.ubcabtech.com";
const DEFAULT_UBEATS_CLIENT_ID = "ubeats-bo";
const DEFAULT_UBEATS_ORIGIN = "https://ubeats-bo.ubcab.mn";

let cachedUbeatsClient: UBCabBOClient | null = null;
function getUbeatsClient(): UBCabBOClient {
  if (!cachedUbeatsClient) {
    cachedUbeatsClient = new UBCabBOClient({
      username: process.env.UBEATS_USERNAME ?? "",
      password: process.env.UBEATS_PASSWORD ?? "",
      refreshToken: process.env.UBEATS_REFRESH_TOKEN ?? "",
      clientId: process.env.UBEATS_CLIENT_ID ?? DEFAULT_UBEATS_CLIENT_ID,
      ssoUrl: process.env.UBEATS_SSO_URL ?? DEFAULT_SSO_URL,
      realm: process.env.UBEATS_REALM ?? DEFAULT_REALM,
      apiUrl: process.env.UBEATS_API_URL ?? DEFAULT_UBEATS_API_URL,
      origin: process.env.UBEATS_ORIGIN ?? DEFAULT_UBEATS_ORIGIN,
    });
  }
  return cachedUbeatsClient;
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

  // Reusable paging fragments (POST list endpoints share this body shape).
  const pagingShape = {
    page: z.number().int().positive().optional().describe("Хуудасны дугаар (default 1)."),
    limit: z.number().int().positive().max(100).optional().describe("Нэг хуудасны мөр (default 20)."),
    includeTotal: z.boolean().optional().describe("Нийт тоог буцаах эсэх (default true)."),
  };
  const pagingBody = (a: { page?: number; limit?: number; includeTotal?: boolean }) => ({
    page: a.page ?? 1,
    limit: a.limit ?? 20,
    includeTotal: a.includeTotal ?? true,
  });

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
  // AUDIT LOG — POST /v1/audit-log/list (хэн, хэзээ, юуг өөрчилсөн)
  // =========================================================================
  reg(
    "ubcab_bo_audit_log_list",
    "AUDIT LOG — объект дээр хийгдсэн үйлдлүүдийн түүх (хэн, хэзээ, юуг өөрчилсөн). " +
      "POST /v1/audit-log/list. Body: limit, page, includeTotal, target{type,_id}. " +
      "target нь ШҮҮЛТҮҮР: жолоочийн лог харахад type='driver', _id=жолоочийн id " +
      "(бусад төрөл: rider, trip г.м. — системээс хамаарна). " +
      "Хариу docs[] бүрт: createdAt (Огноо), by{type,_id,name} (Гүйцэтгэсэн), action (Үйлдэл, " +
      "ж: 'driver-state-update'), level (Түвшин: info г.м.), description (Тайлбар), " +
      "change{before,after} (ЯГ ямар талбар юунаас юу болсон), client{type,code}, origin, " +
      "context{sourceIp,userAgent}. " +
      "📌 'Хэн жолоочийг хаасан/сэргээсэн?', 'Хэн юу өөрчилсөн?' гэх мэт асуултад ЭНЭ tool-ыг ашигла.",
    {
      targetType: z
        .string()
        .min(1)
        .describe("Объектын төрөл — жолоочийн хувьд 'driver' (мөн rider, trip г.м.)."),
      targetId: z.string().min(1).describe("Объектын _id (ж: жолоочийн id)."),
      page: z.number().int().positive().optional().describe("Хуудас (default 1)."),
      limit: z.number().int().positive().max(100).optional().describe("Мөр (default 20)."),
      includeTotal: z.boolean().optional().describe("Нийт тоо (default true)."),
      payload: z
        .record(z.string(), z.any())
        .optional()
        .describe("Заавал биш: body-г бүрэн дарж бичих (нэмэлт шүүлтүүр шаардвал)."),
    },
    ({ targetType, targetId, page, limit, includeTotal, payload }) =>
      guarded(() =>
        client.request("POST", "/v1/audit-log/list", {
          body:
            payload ?? {
              limit: limit ?? 20,
              page: page ?? 1,
              includeTotal: includeTotal ?? true,
              target: { type: targetType, _id: targetId },
            },
        })
      )
  );

  // =========================================================================
  // Тээврийн хэрэгслийн ҮЗЛЭГ — /v1/driver/vehicle-inspections/{inspectionId}
  // =========================================================================
  const inspectionIdSchema = z
    .string()
    .min(1)
    .describe("Үзлэгийн ID (Mongo ObjectId, ж: 6a6ad1330cf415b7e77fef74).");

  reg(
    "ubcab_bo_vehicle_inspection_get",
    "Тээврийн хэрэгслийн техникийн ҮЗЛЭГИЙН дэлгэрэнгүй. " +
      "GET /v1/driver/vehicle-inspections/{inspectionId}. Хариу: source (ж: autosync), inspectedAt, " +
      "expiresAt (дуусах хугацаа), vehicle{plateNumber, cabinNumber, model}, company{name} (үзлэг хийсэн " +
      "газар), result ('passed'/…), meta.status (ж: APPROVED), createdAt/By, updatedAt/By, ба " +
      "inspections[] — хэсэг тус бүр (type '1'=гадна/кабин, '2'=явах анги/хөдөлгүүр) values[]{question, " +
      "answer, description}. 📌 answer='default' нь 'Шаардлага хангасан' гэсэн утга (ялангуяа " +
      "autosync-webhook-оор автоматаар бүртгэгдсэн үзлэгт).",
    { inspectionId: inspectionIdSchema },
    ({ inspectionId }) =>
      guarded(() =>
        client.request("GET", `/v1/driver/vehicle-inspections/${encodeURIComponent(inspectionId)}`)
      )
  );

  reg(
    "ubcab_bo_vehicle_inspection_drivers",
    "Тухайн үзлэгт хамаарах ЖОЛООЧДЫН жагсаалт. " +
      "POST /v1/driver/vehicle-inspections/{inspectionId}/drivers/list. Body: page, limit, includeTotal. " +
      "Хариу: data{ docs[]{_id, shortId, state, serviceStatus, profile{name, phone, registerNumber, " +
      "civilId, birthDate, avatar…}, createdAt, updatedAt}, page, limit, total, totalPage }. " +
      "docs[]._id → driver_get/driver_history-д ашиглана. ⚠ Хувийн мэдээлэл агуулна.",
    { inspectionId: inspectionIdSchema, ...pagingShape },
    ({ inspectionId, page, limit, includeTotal }) =>
      guarded(() =>
        client.request(
          "POST",
          `/v1/driver/vehicle-inspections/${encodeURIComponent(inspectionId)}/drivers/list`,
          { body: pagingBody({ page, limit, includeTotal }) }
        )
      )
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

  // --- DELIVERY trip detail (backlog #18, 2026-08-15) ---
  //
  // Delivery trips are invisible through the taxi path: the resolver measured a live
  // delivery complaint (trip 6a77e342, "70,800₮ гэж мэдэгдсэн") where trip_get returned
  // 996 "Өгөгдөл олдсонгүй" and the rider was absent from the taxi rider DB — so EVERY
  // delivery-penalty complaint arrived fact-less and went to a human blind. The BO web
  // app's own UI path is operator.ubcab.mn/services/delivery/trips/{id}; this mirrors
  // the parallel API family. Additive tool — nothing existing changes.
  reg(
    "ubcab_bo_delivery_trip_get",
    "ХҮРГЭЛТИЙН аяллын үндсэн мэдээлэл. GET /v1/delivery/api/trips/{tripId}. " +
      "operator.ubcab.mn/services/delivery/trips/... линктэй аялалд ЭНИЙГ ашиглана " +
      "(taxi-гийн trip_get нь 996 'Өгөгдөл олдсонгүй' буцаана).",
    { tripId: tripIdSchema },
    ({ tripId }) => guarded(() => client.request("GET", `/v1/delivery/api/trips/${encodeURIComponent(tripId)}`))
  );

  reg(
    "ubcab_bo_delivery_trip_penalties",
    "ХҮРГЭЛТИЙН аяллын торгууль. GET /v1/delivery/api/trips/{tripId}/penalties.",
    { tripId: tripIdSchema },
    ({ tripId }) => guarded(() => client.request("GET", `/v1/delivery/api/trips/${encodeURIComponent(tripId)}/penalties`))
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

  // --- penalties (list) ---
  reg(
    "ubcab_bo_trip_penalties",
    "Аялалтай холбоотой торгууль. GET /v1/taxi/api/trips/{tripId}/penalties. (Ихэвчлэн хоосон массив.)",
    { tripId: tripIdSchema },
    ({ tripId }) =>
      guarded(() => client.request("GET", `${tripBase}/${encodeURIComponent(tripId)}/penalties`))
  );

  // --- penalty cancel (POST) — ЗӨВ зам нь .../penalties/{penaltyId}/cancel ---
  reg(
    "ubcab_bo_trip_penalty_cancel",
    "Аяллын тодорхой торгуулийг ЦУЦЛАХ. " +
      "POST /v1/taxi/api/trips/{tripId}/penalties/{penaltyId}/cancel, body { reason }. " +
      "Хариу: { success: true, data: { message: 'OK' } }; дараа нь торгуулийн төлөв " +
      "status='cancelled', type='cancellation' болно (2026-08-23 бодит дуудлагаар баталгаажсан). " +
      "📌 penaltyId-г ЭХЛЭЭД ubcab_bo_trip_penalties (GET .../penalties)-ээр авна. " +
      "⚠ БИЧИХ/ӨӨРЧЛӨХ үйлдэл — хэрэглэгчийн тодорхой зөвшөөрөлгүйгээр дуудахгүй.",
    {
      tripId: tripIdSchema,
      penaltyId: z
        .string()
        .min(1)
        .describe("Цуцлах торгуулийн id (ubcab_bo_trip_penalties хариунаас)."),
      reason: z.string().min(1).describe("Цуцлах шалтгаан (ж: \"Хэрэглэгчийн гомдлыг үндэслэн цуцаллаа\")."),
      payload: z
        .record(z.string(), z.any())
        .optional()
        .describe("Заавал биш: request body-г бүрэн дарж бичих (өгвөл reason-ийг орлоно)."),
    },
    ({ tripId, penaltyId, reason, payload }) =>
      guarded(() =>
        client.request(
          "POST",
          `${tripBase}/${encodeURIComponent(tripId)}/penalties/${encodeURIComponent(penaltyId)}/cancel`,
          { body: payload ?? { reason } }
        )
      )
  );

  // --- delivery penalty cancel (same shape, delivery module) ---
  reg(
    "ubcab_bo_delivery_penalty_cancel",
    "ХҮРГЭЛТИЙН аяллын торгуулийг ЦУЦЛАХ. " +
      "POST /v1/delivery/api/trips/{tripId}/penalties/{penaltyId}/cancel, body { reason }. " +
      "Такситай ижил бүтэц (delivery модуль). penaltyId-г ubcab_bo_delivery_trip_penalties-ээс ав. " +
      "⚠ БИЧИХ үйлдэл — зөвшөөрөлгүй дуудахгүй.",
    {
      tripId: tripIdSchema,
      penaltyId: z.string().min(1).describe("Цуцлах торгуулийн id."),
      reason: z.string().min(1).describe("Цуцлах шалтгаан."),
      payload: z.record(z.string(), z.any()).optional().describe("Body-г бүрэн дарж бичих."),
    },
    ({ tripId, penaltyId, reason, payload }) =>
      guarded(() =>
        client.request(
          "POST",
          `/v1/delivery/api/trips/${encodeURIComponent(tripId)}/penalties/${encodeURIComponent(
            penaltyId
          )}/cancel`,
          { body: payload ?? { reason } }
        )
      )
  );

  // --- loyalty ---
  reg(
    "ubcab_bo_trip_loyalty",
    "Аяллын урамшуулал. GET /v1/taxi/api/trips/{tripId}/loyalty. Хариу: { loyalty }.",
    { tripId: tripIdSchema },
    ({ tripId }) => guarded(() => client.request("GET", `${tripBase}/${encodeURIComponent(tripId)}/loyalty`))
  );

  // =========================================================================
  // Driver activity / service history — POST /v1/activity/api/drivers/{id}/history
  // =========================================================================
  reg(
    "ubcab_bo_driver_history",
    "Жолоочийн үйлчилгээний (activity) түүх. POST /v1/activity/api/drivers/{driverId}/history. " +
      "⚠ POST бөгөөд page, limit (number) ЗААВАЛ body-д явна — дутуу бол 400 (code 996). " +
      "phone өгвөл filter.phone-оор (зорчигчийн утас) ШҮҮНЭ — тухайн жолоочийн уг хэрэглэгчтэй хийсэн " +
      "аяллуудыг олно. Хариу: { success, data: { page, totalPage, limit, docs[] } }. docs бичлэг бүр: " +
      "_id, accountId, sourceApp, serviceId, serviceType, createdAt, data{ type, status, serviceName, " +
      "driver{name, phone, vehicle{plateNumber, mark, model, color…}} …}. " +
      "📌 docs[].serviceId = тухайн аяллын ID → ubcab_bo_trip_get/_charges/_routes-д ашиглаж " +
      "аяллын бүрэн дэлгэрэнгүйг авна. Гинж: driver_search → driver_history(phone) → trip_get(serviceId).",
    {
      driverId: driverIdSchema,
      phone: z
        .string()
        .optional()
        .describe("Зорчигчийн утас — өгвөл filter.phone-оор шүүнэ (ж: \"95186337\"). Хоосон бол бүх түүх."),
      page: z.number().int().positive().optional().describe("Хуудасны дугаар (default 1)."),
      limit: z.number().int().positive().max(100).optional().describe("Нэг хуудасны мөр (default 20)."),
      includeTotal: z.boolean().optional().describe("Нийт тоог буцаах эсэх (default true)."),
    },
    ({ driverId, phone, page, limit, includeTotal }) =>
      guarded(() =>
        client.request("POST", `/v1/activity/api/drivers/${encodeURIComponent(driverId)}/history`, {
          body: {
            page: page ?? 1,
            limit: limit ?? 20,
            includeTotal: includeTotal ?? true,
            ...(phone ? { filter: { phone } } : {}),
          },
        })
      )
  );

  // =========================================================================
  // Rider search — POST /v1/rider/riders/list
  // =========================================================================
  reg(
    "ubcab_bo_rider_search",
    "Хэрэглэгч (rider/зорчигч)-ийг утас/нэр зэрэг чөлөөт хайлтаар хайх. " +
      "POST /v1/rider/riders/list (driver_search-тэй ижил бүтэц). Хариунд хэрэглэгчдийн жагсаалт " +
      "ба тус бүрийн _id ирнэ. ⚠ Хувийн мэдээлэл агуулна.",
    {
      query: z.string().min(1).describe("Хайх утга — утасны дугаар, нэр г.м."),
      page: z.number().int().positive().optional().describe("Хуудасны дугаар (default 1)."),
      limit: z.number().int().positive().max(100).optional().describe("Нэг хуудасны мөр (default 20)."),
      includeTotal: z.boolean().optional().describe("Нийт тоог буцаах эсэх (default true)."),
    },
    ({ query, page, limit, includeTotal }) =>
      guarded(() =>
        client.request("POST", "/v1/rider/riders/list", {
          body: {
            limit: limit ?? 20,
            includeTotal: includeTotal ?? true,
            page: page ?? 1,
            filter: { query },
          },
        })
      )
  );

  // =========================================================================
  // Rider activity / trip history — POST /v1/activity/api/riders/{id}/history
  // =========================================================================
  reg(
    "ubcab_bo_rider_history",
    "Хэрэглэгчийн (зорчигчийн) аяллын (activity) түүх. POST /v1/activity/api/riders/{riderId}/history. " +
      "driver_history-тэй ИЖИЛ бүтэц (зам нь riders). ⚠ POST, page+limit (number) ЗААВАЛ — дутуу бол 400/996. " +
      "phone өгвөл filter.phone-оор (жолоочийн утас) ШҮҮНЭ — тухайн хэрэглэгчийн уг жолоочтой хийсэн " +
      "аяллуудыг олно. Хариу: { success, data: { page, totalPage, limit, docs[] } }. docs бичлэг бүр: " +
      "_id, serviceId, serviceType, createdAt, data{ status, driver{name, phone…}, rider… }. " +
      "📌 docs[].serviceId = аяллын ID → ubcab_bo_trip_get/_charges/_routes-д ашиглана. " +
      "Гинж: rider_search → rider_history(phone) → trip_get(serviceId).",
    {
      riderId: z
        .string()
        .min(1)
        .describe("Хэрэглэгчийн ID (Mongo ObjectId). rider_search-аас _id-г ав."),
      phone: z
        .string()
        .optional()
        .describe("Жолоочийн утас — өгвөл filter.phone-оор шүүнэ. Хоосон бол бүх түүх."),
      page: z.number().int().positive().optional().describe("Хуудасны дугаар (default 1)."),
      limit: z.number().int().positive().max(100).optional().describe("Нэг хуудасны мөр (default 20)."),
      includeTotal: z.boolean().optional().describe("Нийт тоог буцаах эсэх (default true)."),
    },
    ({ riderId, phone, page, limit, includeTotal }) =>
      guarded(() =>
        client.request("POST", `/v1/activity/api/riders/${encodeURIComponent(riderId)}/history`, {
          body: {
            page: page ?? 1,
            limit: limit ?? 20,
            includeTotal: includeTotal ?? true,
            ...(phone ? { filter: { phone } } : {}),
          },
        })
      )
  );

  // =========================================================================
  // Driver wallet / vehicles / feedback / loyalty
  // =========================================================================

  // --- wallet balance (GET) ---
  reg(
    "ubcab_bo_driver_wallet",
    "Жолоочийн хэтэвчний үлдэгдэл. GET /v1/driver/drivers/{driverId}/wallet.",
    { driverId: driverIdSchema },
    ({ driverId }) =>
      guarded(() => client.request("GET", `/v1/driver/drivers/${encodeURIComponent(driverId)}/wallet`))
  );

  // --- wallet transaction history (POST, paged, date-filterable) ---
  const dateSchema = z
    .string()
    .regex(/^\d{4}-\d{2}-\d{2}$/, "YYYY-MM-DD форматтай байх ёстой");
  reg(
    "ubcab_bo_driver_wallet_history",
    "Жолоочийн хэтэвчний гүйлгээний түүх. POST /v1/driver/drivers/{driverId}/wallet/history. " +
      "Body: page, limit, includeTotal, заавал биш filter{beginDate,endDate}. " +
      "beginDate/endDate (YYYY-MM-DD) өгвөл тухайн хугацааны гүйлгээг шүүнэ — " +
      "сарын орлого/зарлагыг тооцоход ашигла (ж: 2026-07-01 → 2026-07-31). " +
      "Бүх гүйлгээ авахын тулд limit-ийг том (ж: 100) болго. " +
      "Хариу: { success, data: { page, totalPage, limit, docs[] } }; docs бүр дүн/чиглэл (орлого/зарлага), огноо агуулна.",
    {
      driverId: driverIdSchema,
      beginDate: dateSchema.optional().describe("Эхлэх огноо YYYY-MM-DD (filter.beginDate)."),
      endDate: dateSchema.optional().describe("Дуусах огноо YYYY-MM-DD (filter.endDate)."),
      ...pagingShape,
    },
    ({ driverId, beginDate, endDate, page, limit, includeTotal }) =>
      guarded(() =>
        client.request("POST", `/v1/driver/drivers/${encodeURIComponent(driverId)}/wallet/history`, {
          body: {
            ...pagingBody({ page, limit, includeTotal }),
            ...(beginDate || endDate
              ? {
                  filter: {
                    ...(beginDate ? { beginDate } : {}),
                    ...(endDate ? { endDate } : {}),
                  },
                }
              : {}),
          },
        })
      )
  );

  // --- vehicles list (GET) ---
  reg(
    "ubcab_bo_driver_vehicles",
    "Жолоочийн тээврийн хэрэгслүүдийн жагсаалт. GET /v1/driver/drivers/{driverId}/vehicles/list. " +
      "Машин бүрийн plateNumber, mark, model, color, type г.м.",
    { driverId: driverIdSchema },
    ({ driverId }) =>
      guarded(() =>
        client.request("GET", `/v1/driver/drivers/${encodeURIComponent(driverId)}/vehicles/list`)
      )
  );

  // --- vehicle services update (PUT) ---
  reg(
    "ubcab_bo_driver_vehicle_services_update",
    "Тээврийн хэрэгслийн ҮЙЛЧИЛГЭЭНҮҮДИЙГ нэмэх/хасах. " +
      "PUT /v1/driver/drivers/{driverId}/vehicles/update. Body: { approvedServices: [...] }. " +
      "⚠⚠ ЗАМЫН ДҮРЭМ: Энэ нь массивыг БҮХЭЛД НЬ ДАРЖ БИЧДЭГ (replace, delta биш). Тиймээс " +
      "ЭХЛЭЭД ubcab_bo_driver_get (эсвэл _driver_vehicles)-ээр одоогийн approvedServices-ийг УНШ, " +
      "дараа нь тэр жагсаалтад код нэмж/хасаад БҮТЭН жагсаалтыг илгээ. Дутуу илгээвэл үйлчилгээ " +
      "санамсаргүй хаагдана. " +
      "Кодын жишээ: just_cab, sos_taxi, official_taxi, vip_taxi, xl_taxi, delivery_express, " +
      "ubeats_delivery, flash_delivery, call_driver, rent_car, rent_suv, rent_suv_plus, rent_xl " +
      "(бүрэн сонголтыг ubcab_bo_service_options-оос ав). " +
      "⚠ БИЧИХ/ӨӨРЧЛӨХ үйлдэл — хэрэглэгчийн тодорхой зөвшөөрөлгүйгээр дуудаж болохгүй. " +
      "Тэмдэглэл: JS бандлд /driver/drivers/{id}/service/update гэсэн ӨӨР endpoint байдаг ч " +
      "тээврийн хэрэгслийн үйлчилгээг удирддаг зөв нь ЭНЭ (vehicles/update).",
    {
      driverId: driverIdSchema,
      approvedServices: z
        .array(z.string())
        .describe("Зөвшөөрөх үйлчилгээний кодуудын БҮТЭН жагсаалт (одоогийнх + нэмэлт − хассан)."),
      payload: z
        .record(z.string(), z.any())
        .optional()
        .describe("Заавал биш: request body-г бүрэн дарж бичих (нэмэлт талбар шаардвал)."),
    },
    ({ driverId, approvedServices, payload }) =>
      guarded(() =>
        client.request("PUT", `/v1/driver/drivers/${encodeURIComponent(driverId)}/vehicles/update`, {
          body: payload ?? { approvedServices },
        })
      )
  );

  // --- feedback / rating list (POST, paged) ---
  reg(
    "ubcab_bo_driver_feedback",
    "Жолоочид өгсөн сэтгэгдэл/үнэлгээний жагсаалт. POST /v1/driver/rating/{driverId}/list. " +
      "Body: page, limit, includeTotal. (Дундаж үнэлгээ нь ubcab_bo_driver_rating-д.)",
    { driverId: driverIdSchema, ...pagingShape },
    ({ driverId, page, limit, includeTotal }) =>
      guarded(() =>
        client.request("POST", `/v1/driver/rating/${encodeURIComponent(driverId)}/list`, {
          body: pagingBody({ page, limit, includeTotal }),
        })
      )
  );

  // --- loyalty level history (POST, paged) ---
  reg(
    "ubcab_bo_driver_loyalty_history",
    "Жолоочийн цол (loyalty level)-ны өөрчлөлтийн түүх. " +
      "POST /v1/loyalty/driver/drivers/{driverId}/level-history/list. Body: page, limit, includeTotal.",
    { driverId: driverIdSchema, ...pagingShape },
    ({ driverId, page, limit, includeTotal }) =>
      guarded(() =>
        client.request(
          "POST",
          `/v1/loyalty/driver/drivers/${encodeURIComponent(driverId)}/level-history/list`,
          { body: pagingBody({ page, limit, includeTotal }) }
        )
      )
  );

  // =========================================================================
  // Express (TEMU / чиглэлийн) илгээмж хянах — ӨӨР host, нэвтрэлтгүй нийтийн API
  // GET https://express-tracking.ubcabtech.com/v1/trackings/{trackingNumber}
  // =========================================================================
  reg(
    "ubcab_express_track",
    "TEMU / чиглэлийн (express) илгээмжийг tracking кодоор хянах. " +
      "GET https://express-tracking.ubcabtech.com/v1/trackings/{trackingNumber}?level=debug. " +
      "⚠ Энэ нь BO биш ТУСДАА нийтийн API — Keycloak нэвтрэлт ШААРДАХГҮЙ. " +
      "Хариу: data{ origin{country,city}, originTrackingNumber, destination{country,city}, status, " +
      "subStatus, trackingEvents[]{ status, subStatus, description, createdAt, location{country,city} } }.",
    {
      trackingNumber: z.string().min(1).describe("Илгээмжийн tracking код (ж: YC001032554CN)."),
      level: z.string().optional().describe("Дэлгэрэнгүйн түвшин (default \"debug\")."),
    },
    async ({ trackingNumber, level }) => {
      try {
        const url =
          `https://express-tracking.ubcabtech.com/v1/trackings/${encodeURIComponent(trackingNumber)}` +
          `?level=${encodeURIComponent(level ?? "debug")}`;
        const res = await fetch(url, { headers: { Accept: "application/json" } });
        const body = await safeJson(res);
        if (!res.ok) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Express tracking error (HTTP ${res.status})\n${JSON.stringify(body, null, 2)}`,
              },
            ],
            isError: true,
          };
        }
        return { content: [{ type: "text" as const, text: JSON.stringify(body, null, 2) }] };
      } catch (err) {
        return {
          content: [{ type: "text" as const, text: err instanceof Error ? err.message : String(err) }],
          isError: true,
        };
      }
    }
  );

  // =========================================================================
  // UBExpress OPERATOR захиалга (ТУСДАА host operator-api.ubcabexpress.mn,
  // Keycloak realm ubcab-bo / client express-bo — operator дансаар нэвтэрнэ)
  // Tracking Number-ийг list endpoint-ийн body filter-т дамжуулна.
  // ⚠ filter талбарын нэр таамаг ("trackingNumber") — шаардвал payload-оор дарж бич.
  // =========================================================================
  const expressClient = getExpressClient();
  const expressListBody = (a: {
    trackingNumber?: string;
    page?: number;
    limit?: number;
    includeTotal?: boolean;
    payload?: Record<string, any>;
  }) =>
    a.payload ?? {
      limit: a.limit ?? 20,
      includeTotal: a.includeTotal ?? true,
      page: a.page ?? 1,
      ...(a.trackingNumber ? { filter: { trackingNumber: a.trackingNumber } } : {}),
    };
  const expressListShape = {
    trackingNumber: z
      .string()
      .optional()
      .describe("Хайх tracking код (ж: YC001032554CN). filter.trackingNumber-т дамжина."),
    page: z.number().int().positive().optional().describe("Хуудас (default 1)."),
    limit: z.number().int().positive().max(100).optional().describe("Мөр (default 20)."),
    includeTotal: z.boolean().optional().describe("Нийт тоо (default true)."),
    payload: z
      .record(z.string(), z.any())
      .optional()
      .describe("Заавал биш: request body-г бүрэн дарж бичих (filter талбарын нэр өөр бол ашигла)."),
  };

  // --- normal orders (Захиалга) ---
  reg(
    "ubcab_express_order_search",
    "UBExpress ЭНГИЙН захиалга (Захиалга)-г tracking кодоор хайх. " +
      "POST https://operator-api.ubcabexpress.mn/v1/api/address-ready-shipments/list. " +
      "operator-api (client express-bo, operator данс). Tracking Number-ийг body filter-т дамжуулна; " +
      "list endpoint нь тухайн захиалгын бүрэн мэдээллийг буцаана (тусдаа get-by-id алга). " +
      "Олдохгүй бол ubcab_express_return_search-ийг үзэх.",
    expressListShape,
    ({ trackingNumber, page, limit, includeTotal, payload }) =>
      guarded(() =>
        expressClient.request("POST", "/v1/api/address-ready-shipments/list", {
          body: expressListBody({ trackingNumber, page, limit, includeTotal, payload }),
        })
      )
  );

  // =========================================================================
  // UBEATS backoffice (ТУСДАА host ubeats-bo-api.ubcabtech.com)
  // Урсгал: {orders|merchant-orders}/list (filter.customerPhone) → id →
  //         GET {orders|merchant-orders}/{id} [+ /state-histories]
  // =========================================================================
  const ubeats = getUbeatsClient();
  const ubeatsBase = "/v1/api";
  const orderIdSchema = z
    .string()
    .min(1)
    .describe("Захиалгын id (ж: 6a64472576915713b9d0f3fc) — list хариунаас ав.");
  const ubeatsListShape = {
    customerPhone: z
      .string()
      .optional()
      .describe("Хэрэглэгчийн утас — filter.customerPhone-д дамжина (ж: \"88221080\")."),
    page: z.number().int().positive().optional().describe("Хуудас (default 1)."),
    limit: z.number().int().positive().max(100).optional().describe("Мөр (default 20)."),
    includeTotal: z.boolean().optional().describe("Нийт тоо (default true)."),
    payload: z
      .record(z.string(), z.any())
      .optional()
      .describe("Заавал биш: request body-г бүрэн дарж бичих (filter бүтэц өөр бол ашигла)."),
  };
  const ubeatsListBody = (a: {
    customerPhone?: string;
    page?: number;
    limit?: number;
    includeTotal?: boolean;
    payload?: Record<string, any>;
  }) =>
    a.payload ?? {
      limit: a.limit ?? 20,
      includeTotal: a.includeTotal ?? true,
      page: a.page ?? 1,
      ...(a.customerPhone ? { filter: { customerPhone: a.customerPhone } } : {}),
    };

  // --- Cloud Kitchen orders ---
  reg(
    "ubeats_order_search",
    "UBEats CLOUD KITCHEN захиалгуудыг хэрэглэгчийн утсаар хайх. POST /v1/api/orders/list " +
      "(host ubeats-bo-api.ubcabtech.com). filter.customerPhone-оор шүүнэ. " +
      "Хариуны мөр бүрт захиалгын id → ubeats_order_get-д ашиглана. " +
      "📌 Merchant талыг ubeats_merchant_order_search-ээр ТУСАД НЬ хайх шаардлагатай.",
    ubeatsListShape,
    (a) => guarded(() => ubeats.request("POST", `${ubeatsBase}/orders/list`, { body: ubeatsListBody(a) }))
  );

  reg(
    "ubeats_order_get",
    "UBEats Cloud Kitchen захиалгын БҮРЭН дэлгэрэнгүй. GET /v1/api/orders/{orderId}. " +
      "Захиалгын дугаар, суваг, хэрэглэгчийн нэр/утас, цэсний төрөл, хүргэх хаяг (хот, давхар, тоот, " +
      "орцны код), урьдчилсан захиалга/цаг, хүргэлтийн ажилтан+утас, зам, ачих/буулгах/хүргэлтийн код, " +
      "төлөв, халбага-сэрээ, хүлээн авах цаг, хүргэлтийн үнэ, хөнгөлөлт, өртөг, нийт төлбөр, төлбөрийн " +
      "төлөв, үүссэн огноо; НЭМЭЛТ: захиалсан бүтээгдэхүүний жагсаалт (нэр, тоо, нэгж/нийт үнэ) ба " +
      "ибаримт (төрөл, дугаар, имэйл). ⚠ Хувийн мэдээлэл агуулна.",
    { orderId: orderIdSchema },
    ({ orderId }) =>
      guarded(() => ubeats.request("GET", `${ubeatsBase}/orders/${encodeURIComponent(orderId)}`))
  );

  reg(
    "ubeats_order_state_histories",
    "UBEats Cloud Kitchen захиалгын төлөвийн түүх. GET /v1/api/orders/{orderId}/state-histories.",
    { orderId: orderIdSchema },
    ({ orderId }) =>
      guarded(() =>
        ubeats.request("GET", `${ubeatsBase}/orders/${encodeURIComponent(orderId)}/state-histories`)
      )
  );

  // --- Merchant orders ---
  reg(
    "ubeats_merchant_order_search",
    "UBEats MERCHANT захиалгуудыг хэрэглэгчийн утсаар хайх. POST /v1/api/merchant-orders/list. " +
      "filter.customerPhone-оор шүүнэ; мөр бүрт id → ubeats_merchant_order_get. " +
      "📌 Cloud Kitchen талыг ubeats_order_search-ээр тусад нь хай (хоёуланг шалгах нь зөв).",
    ubeatsListShape,
    (a) =>
      guarded(() =>
        ubeats.request("POST", `${ubeatsBase}/merchant-orders/list`, { body: ubeatsListBody(a) })
      )
  );

  reg(
    "ubeats_merchant_order_get",
    "UBEats Merchant захиалгын БҮРЭН дэлгэрэнгүй. GET /v1/api/merchant-orders/{orderId}. " +
      "Cloud Kitchen-тэй ижил талбарууд (хэрэглэгч, хаяг, хүргэлт, төлбөр, төлөв г.м.); " +
      "бүтээгдэхүүн нь жагсаалтын мөрөнд, устгах үйлдэл байхгүй. ⚠ Хувийн мэдээлэл агуулна.",
    { orderId: orderIdSchema },
    ({ orderId }) =>
      guarded(() => ubeats.request("GET", `${ubeatsBase}/merchant-orders/${encodeURIComponent(orderId)}`))
  );

  reg(
    "ubeats_merchant_order_state_histories",
    "UBEats Merchant захиалгын төлөвийн түүх. GET /v1/api/merchant-orders/{orderId}/state-histories.",
    { orderId: orderIdSchema },
    ({ orderId }) =>
      guarded(() =>
        ubeats.request(
          "GET",
          `${ubeatsBase}/merchant-orders/${encodeURIComponent(orderId)}/state-histories`
        )
      )
  );

  // =========================================================================
  // MARKETING BO — Гарын авлагын КАТЕГОР (help content-groups)
  // Host: marketing-bo-api.ubcabtech.com, base /v1/content/api/help/content-groups
  // Нэвтрэлт: BO-тэй ижил Keycloak данс (нэмэлт env шаардлагагүй).
  // =========================================================================
  const marketing = getMarketingClient();
  const helpGroupsBase = "/v1/content/api/help/content-groups";
  const helpGroupIdSchema = z.string().min(1).describe("Категорын id (list-ээс ав).");

  reg(
    "ubcab_marketing_help_group_list",
    "Гарын авлагын КАТЕГОРУУДын жагсаалт. POST /v1/content/api/help/content-groups/list " +
      "(host marketing-bo-api.ubcabtech.com). Body: limit, page, includeTotal. " +
      "Хариу: data{ docs[], page, limit, totalPage }. docs[]._id → get/delete-д ашиглана.",
    {
      page: z.number().int().positive().optional().describe("Хуудас (default 1)."),
      limit: z.number().int().positive().max(100).optional().describe("Мөр (default 10)."),
      includeTotal: z.boolean().optional().describe("Нийт тоо (default true)."),
    },
    ({ page, limit, includeTotal }) =>
      guarded(() =>
        marketing.request("POST", `${helpGroupsBase}/list`, {
          body: { limit: limit ?? 10, page: page ?? 1, includeTotal: includeTotal ?? true },
        })
      )
  );

  reg(
    "ubcab_marketing_help_group_create",
    "Гарын авлагын ШИНЭ КАТЕГОР нэмэх. POST /v1/content/api/help/content-groups. " +
      "name (заавал, min 1), order (эерэг тоо — эрэмбэ), localizedNames (заавал биш, key-value " +
      "орчуулга ж: {\"en\":\"Help\"}), isActive. Хариу: { success: true, ... }. " +
      "⚠ БИЧИХ үйлдэл — хэрэглэгчийн зөвшөөрөлгүй дуудаж болохгүй. " +
      "📌 order давхцахгүй байх эсэхийг эхлээд _list-ээр шалгах нь зүйтэй.",
    {
      name: z.string().min(1).describe("Категорын нэр (заавал)."),
      order: z.number().int().positive().describe("Эрэмбэ — эерэг бүхэл тоо."),
      isActive: z.boolean().optional().describe("Идэвхтэй эсэх (default true)."),
      localizedNames: z
        .record(z.string(), z.any())
        .optional()
        .describe("Орчуулгууд, ж: {\"en\":\"Help\"}. Хоосон бол {}."),
      payload: z
        .record(z.string(), z.any())
        .optional()
        .describe("Заавал биш: request body-г бүрэн дарж бичих."),
    },
    ({ name, order, isActive, localizedNames, payload }) =>
      guarded(() =>
        marketing.request("POST", helpGroupsBase, {
          body:
            payload ?? {
              name,
              order,
              localizedNames: localizedNames ?? {},
              isActive: isActive ?? true,
            },
        })
      )
  );

  reg(
    "ubcab_marketing_help_group_get",
    "Гарын авлагын категорын дэлгэрэнгүй. GET /v1/content/api/help/content-groups/{id}.",
    { id: helpGroupIdSchema },
    ({ id }) => guarded(() => marketing.request("GET", `${helpGroupsBase}/${encodeURIComponent(id)}`))
  );

  reg(
    "ubcab_marketing_help_group_delete",
    "Гарын авлагын категор УСТГАХ. DELETE /v1/content/api/help/content-groups/{id}. " +
      "⚠ Устгах үйлдэл — доторх контент нөлөөлж болзошгүй. Зөвшөөрөлгүй дуудахгүй.",
    { id: helpGroupIdSchema },
    ({ id }) => guarded(() => marketing.request("DELETE", `${helpGroupsBase}/${encodeURIComponent(id)}`))
  );

  reg(
    "ubcab_marketing_help_group_meta",
    "Категорын формын META (ямар талбар шаардлагатайг буцаана). " +
      "GET /v1/content/api/help/content-groups/meta?action=create (үүсгэх) эсвэл " +
      "?action=get&resourcesId={id} (засварлах). Body бүтэц эргэлзээтэй үед эхлээд үүнийг дууд.",
    {
      action: z.enum(["create", "get"]).optional().describe("create (default) эсвэл get."),
      resourcesId: z.string().optional().describe("action='get' үед категорын id."),
    },
    ({ action, resourcesId }) =>
      guarded(() =>
        marketing.request("GET", `${helpGroupsBase}/meta`, {
          query: { action: action ?? "create", resourcesId },
        })
      )
  );

  // =========================================================================
  // MARKETING BO — Мэдээний (Press) АНГИЛАЛ /content/api/content/categories
  // help/content-groups-тай ижил бүтэц; ялгаа: засварыг PUT-ээр (зам дээр id-гүй,
  // id нь BODY дотор) хийдэг.
  // =========================================================================
  const contentCatsBase = "/v1/content/api/content/categories";
  const contentCatIdSchema = z.string().min(1).describe("Ангилалын id (list-ээс ав).");

  reg(
    "ubcab_marketing_content_category_list",
    "Мэдээний (Press) АНГИЛЛУУДын жагсаалт. POST /v1/content/api/content/categories/list. " +
      "Body: limit, page, includeTotal. Хариу: data{ docs[], page, limit, totalPage }.",
    {
      page: z.number().int().positive().optional().describe("Хуудас (default 1)."),
      limit: z.number().int().positive().max(100).optional().describe("Мөр (default 10)."),
      includeTotal: z.boolean().optional().describe("Нийт тоо (default true)."),
    },
    ({ page, limit, includeTotal }) =>
      guarded(() =>
        marketing.request("POST", `${contentCatsBase}/list`, {
          body: { limit: limit ?? 10, page: page ?? 1, includeTotal: includeTotal ?? true },
        })
      )
  );

  reg(
    "ubcab_marketing_content_category_create",
    "Мэдээний ШИНЭ АНГИЛАЛ нэмэх. POST /v1/content/api/content/categories. " +
      "Талбарууд: name* (Нэр), order* (Дараалал, эерэг тоо), isActive, нэмэлтээр 'Онцлох төрөл' г.м. " +
      "📌 Формын талбар серверийн meta-аас ДИНАМИК тул эргэлзвэл эхлээд " +
      "ubcab_marketing_content_category_meta(action='create')-г дуудаж яг талбаруудыг шалга, " +
      "шаардлагатай бол payload-оор бүтэн body илгээ. ⚠ БИЧИХ үйлдэл.",
    {
      name: z.string().min(1).describe("Ангилалын нэр (заавал)."),
      order: z.number().int().positive().describe("Дараалал — эерэг бүхэл тоо (заавал)."),
      isActive: z.boolean().optional().describe("Идэвхтэй эсэх (default true)."),
      extra: z
        .record(z.string(), z.any())
        .optional()
        .describe("Нэмэлт талбарууд (ж: онцлох төрөл) — meta-аас харсны дараа."),
      payload: z
        .record(z.string(), z.any())
        .optional()
        .describe("Заавал биш: request body-г бүрэн дарж бичих."),
    },
    ({ name, order, isActive, extra, payload }) =>
      guarded(() =>
        marketing.request("POST", contentCatsBase, {
          body: payload ?? { name, order, isActive: isActive ?? true, ...(extra ?? {}) },
        })
      )
  );

  reg(
    "ubcab_marketing_content_category_get",
    "Мэдээний ангилалын дэлгэрэнгүй. GET /v1/content/api/content/categories/{id}.",
    { id: contentCatIdSchema },
    ({ id }) => guarded(() => marketing.request("GET", `${contentCatsBase}/${encodeURIComponent(id)}`))
  );

  reg(
    "ubcab_marketing_content_category_update",
    "Мэдээний ангилал ЗАСАХ. PUT /v1/content/api/content/categories/{id}. " +
      "⚠ Бүх талбар дарж бичигдэх тул эхлээд _get эсвэл _list-ээр одоогийн утгыг уншаад дутуугүй илгээ. " +
      "⚠ БИЧИХ үйлдэл.",
    {
      id: contentCatIdSchema,
      name: z.string().optional().describe("Шинэ нэр."),
      order: z.number().int().positive().optional().describe("Шинэ дараалал."),
      isActive: z.boolean().optional().describe("Идэвхтэй эсэх."),
      extra: z.record(z.string(), z.any()).optional().describe("Нэмэлт талбарууд."),
      payload: z
        .record(z.string(), z.any())
        .optional()
        .describe("Заавал биш: body-г бүрэн дарж бичих."),
    },
    ({ id, name, order, isActive, extra, payload }) =>
      guarded(() =>
        marketing.request("PUT", `${contentCatsBase}/${encodeURIComponent(id)}`, {
          body:
            payload ?? {
              ...(name !== undefined ? { name } : {}),
              ...(order !== undefined ? { order } : {}),
              ...(isActive !== undefined ? { isActive } : {}),
              ...(extra ?? {}),
            },
        })
      )
  );

  reg(
    "ubcab_marketing_content_category_delete",
    "Мэдээний ангилал УСТГАХ. DELETE /v1/content/api/content/categories/{id}. " +
      "⚠ Устгах үйлдэл — тухайн ангилалд хамаарах мэдээнд нөлөөлж болзошгүй.",
    { id: contentCatIdSchema },
    ({ id }) => guarded(() => marketing.request("DELETE", `${contentCatsBase}/${encodeURIComponent(id)}`))
  );

  reg(
    "ubcab_marketing_content_category_meta",
    "Мэдээний ангилалын формын META. GET /v1/content/api/content/categories/meta" +
      "?action=create (үүсгэх) эсвэл ?action=get&resourcesId={id} (засварлах). " +
      "Талбарууд динамик тул create/update-ийн өмнө үүнийг дуудах нь найдвартай.",
    {
      action: z.enum(["create", "get"]).optional().describe("create (default) эсвэл get."),
      resourcesId: z.string().optional().describe("action='get' үед ангилалын id."),
    },
    ({ action, resourcesId }) =>
      guarded(() =>
        marketing.request("GET", `${contentCatsBase}/meta`, {
          query: { action: action ?? "create", resourcesId },
        })
      )
  );

  // =========================================================================
  // MARKETING BO — Тусламжийн АГУУЛГА (help contents)
  // base /v1/content/api/help/contents  (+ select-options)
  // =========================================================================
  const helpContentsBase = "/v1/content/api/help/contents";
  const helpContentIdSchema = z.string().min(1).describe("Контентын id (list-ээс ав).");

  reg(
    "ubcab_marketing_help_content_list",
    "Тусламжийн АГУУЛГУУДын жагсаалт. POST /v1/content/api/help/contents/list. " +
      "Body: limit, page, includeTotal, filter{slug?, title?}. " +
      "Хариу: data{ docs[]{_id, group, slug, title, languageGroup{mn,en}, language, order, isActive}, " +
      "page, limit, totalPage }.",
    {
      slug: z.string().optional().describe("filter.slug — тодорхой slug-аар шүүх."),
      title: z.string().optional().describe("filter.title — гарчгаар шүүх."),
      page: z.number().int().positive().optional().describe("Хуудас (default 1)."),
      limit: z.number().int().positive().max(100).optional().describe("Мөр (default 10)."),
      includeTotal: z.boolean().optional().describe("Нийт тоо (default true)."),
    },
    ({ slug, title, page, limit, includeTotal }) =>
      guarded(() =>
        marketing.request("POST", `${helpContentsBase}/list`, {
          body: {
            limit: limit ?? 10,
            page: page ?? 1,
            includeTotal: includeTotal ?? true,
            ...(slug || title
              ? { filter: { ...(slug ? { slug } : {}), ...(title ? { title } : {}) } }
              : {}),
          },
        })
      )
  );

  reg(
    "ubcab_marketing_help_content_create",
    "Тусламжийн ШИНЭ АГУУЛГА нэмэх. POST /v1/content/api/help/contents. " +
      "Заавал: group (контент бүлгийн id — ubcab_marketing_help_select_content_groups эсвэл " +
      "_help_group_list-ээс ав), title, language ('mn'|'en'), order (тоо). " +
      "content нь HTML (rich-text). " +
      "📌 slug: ШИНЭ контент бол null; ОРЧУУЛГА нэмэх бол одоо байгаа контентын slug-ийг өг — " +
      "ингэснээр нэг language group-т холбогдоно (mn/en хос болно). " +
      "⚠ БИЧИХ үйлдэл — зөвшөөрөлгүй дуудахгүй.",
    {
      group: z.string().min(1).describe("Контент бүлгийн id (шаардлагатай)."),
      title: z.string().min(1).describe("Гарчиг (шаардлагатай)."),
      language: z.enum(["mn", "en"]).describe("Хэл: mn эсвэл en."),
      order: z.number().int().nonnegative().describe("Эрэмбэ (тоо, 0-оос эхэлж болно)."),
      content: z.string().optional().describe("HTML агуулга (ж: \"<p>...</p>\")."),
      isActive: z.boolean().optional().describe("Идэвхтэй эсэх (default true)."),
      slug: z
        .string()
        .optional()
        .describe("Орчуулга нэмэх бол одоо байгаа slug; шинэ контент бол хоосон орхи (null явна)."),
      payload: z
        .record(z.string(), z.any())
        .optional()
        .describe("Заавал биш: request body-г бүрэн дарж бичих."),
    },
    ({ group, title, language, order, content, isActive, slug, payload }) =>
      guarded(() =>
        marketing.request("POST", helpContentsBase, {
          body:
            payload ?? {
              group,
              title,
              language,
              order,
              isActive: isActive ?? true,
              content: content ?? "",
              slug: slug ?? null,
            },
        })
      )
  );

  reg(
    "ubcab_marketing_help_content_get",
    "Тусламжийн агуулгын дэлгэрэнгүй. GET /v1/content/api/help/contents/{id}.",
    { id: helpContentIdSchema },
    ({ id }) => guarded(() => marketing.request("GET", `${helpContentsBase}/${encodeURIComponent(id)}`))
  );

  reg(
    "ubcab_marketing_help_content_update",
    "Тусламжийн агуулга ЗАСАХ. PUT /v1/content/api/help/contents/{id}. " +
      "⚠ Талбарууд дарж бичигдэх тул эхлээд _get-ээр одоогийн утгыг уншаад дутуугүй илгээ. " +
      "⚠ БИЧИХ үйлдэл.",
    {
      id: helpContentIdSchema,
      group: z.string().optional().describe("Контент бүлгийн id."),
      title: z.string().optional().describe("Гарчиг."),
      language: z.enum(["mn", "en"]).optional().describe("Хэл."),
      order: z.number().int().nonnegative().optional().describe("Эрэмбэ."),
      content: z.string().optional().describe("HTML агуулга."),
      isActive: z.boolean().optional().describe("Идэвхтэй эсэх."),
      slug: z.string().optional().describe("Slug (language group холбоос)."),
      payload: z.record(z.string(), z.any()).optional().describe("Body-г бүрэн дарж бичих."),
    },
    ({ id, group, title, language, order, content, isActive, slug, payload }) =>
      guarded(() =>
        marketing.request("PUT", `${helpContentsBase}/${encodeURIComponent(id)}`, {
          body:
            payload ?? {
              ...(group !== undefined ? { group } : {}),
              ...(title !== undefined ? { title } : {}),
              ...(language !== undefined ? { language } : {}),
              ...(order !== undefined ? { order } : {}),
              ...(content !== undefined ? { content } : {}),
              ...(isActive !== undefined ? { isActive } : {}),
              ...(slug !== undefined ? { slug } : {}),
            },
        })
      )
  );

  reg(
    "ubcab_marketing_help_content_delete",
    "Тусламжийн агуулга УСТГАХ. DELETE /v1/content/api/help/contents/{id}. ⚠ Устгах үйлдэл.",
    { id: helpContentIdSchema },
    ({ id }) =>
      guarded(() => marketing.request("DELETE", `${helpContentsBase}/${encodeURIComponent(id)}`))
  );

  reg(
    "ubcab_marketing_help_content_meta",
    "Тусламжийн агуулгын формын META. GET /v1/content/api/help/contents/meta?action=create " +
      "эсвэл ?action=get&resourcesId={id}. Талбарууд: group (select), title, language (mn/en), " +
      "order (number), isActive (checkbox).",
    {
      action: z.enum(["create", "get"]).optional().describe("create (default) эсвэл get."),
      resourcesId: z.string().optional().describe("action='get' үед контентын id."),
    },
    ({ action, resourcesId }) =>
      guarded(() =>
        marketing.request("GET", `${helpContentsBase}/meta`, {
          query: { action: action ?? "create", resourcesId },
        })
      )
  );

  reg(
    "ubcab_marketing_help_select_content_groups",
    "Контент бүлгийн СОНГОЛТУУД (select options). " +
      "GET /v1/content/api/help/select-options/content-groups. " +
      "📌 help_content_create-ийн 'group' утгыг эндээс ав.",
    {},
    () => guarded(() => marketing.request("GET", "/v1/content/api/help/select-options/content-groups"))
  );

  reg(
    "ubcab_marketing_help_select_language",
    "Хэлний сонголтууд. GET /v1/content/api/help/select-options/language.",
    {},
    () => guarded(() => marketing.request("GET", "/v1/content/api/help/select-options/language"))
  );

  // =========================================================================
  // MARKETING BO — Press / маркетингийн КОНТЕНТ /content/api/content/contents
  // (+ зураг upload: ӨӨР домэйн upload.ubcabtech.com, ижил Bearer токен)
  // =========================================================================
  const contentsBase = "/v1/content/api/content/contents";
  const contentIdSchema = z.string().min(1).describe("Контентын id (list-ээс ав).");

  reg(
    "ubcab_marketing_content_list",
    "Press / маркетингийн КОНТЕНТУУДын жагсаалт. POST /v1/content/api/content/contents/list. " +
      "Body: limit, page, includeTotal. Хариу: data{ docs[], page, limit, totalPage }.",
    {
      page: z.number().int().positive().optional().describe("Хуудас (default 1)."),
      limit: z.number().int().positive().max(100).optional().describe("Мөр (default 10)."),
      includeTotal: z.boolean().optional().describe("Нийт тоо (default true)."),
      filter: z.record(z.string(), z.any()).optional().describe("Нэмэлт шүүлтүүр (байвал)."),
    },
    ({ page, limit, includeTotal, filter }) =>
      guarded(() =>
        marketing.request("POST", `${contentsBase}/list`, {
          body: {
            limit: limit ?? 10,
            page: page ?? 1,
            includeTotal: includeTotal ?? true,
            ...(filter ? { filter } : {}),
          },
        })
      )
  );

  reg(
    "ubcab_marketing_content_create",
    "Press / маркетингийн ШИНЭ КОНТЕНТ нэмэх. POST /v1/content/api/content/contents. " +
      "Заавал: title, cover (зургийн URL), category (ангилалын id), preview (тойм). " +
      "content нь HTML бүтэн агуулга, wordCount нь үгийн тоо (default 200) — эдгээр meta-д " +
      "харагдахгүй ч API хүлээж авдаг. " +
      "📌 Дараалал: (1) ubcab_marketing_upload_image-ээр зураг байршуулж fileUrl ав → cover, " +
      "(2) ubcab_marketing_content_select_categories-ээс category id ав, (3) энэ tool-оор үүсгэ. " +
      "⚠ БИЧИХ үйлдэл — зөвшөөрөлгүй дуудахгүй.",
    {
      title: z.string().min(1).describe("Гарчиг (заавал)."),
      cover: z.string().min(1).describe("Нүүр зургийн URL (upload-аас буцсан fileUrl)."),
      category: z.string().min(1).describe("Ангилалын id (select-options-оос)."),
      preview: z.string().min(1).describe("Тойм агуулга (заавал)."),
      content: z.string().optional().describe("HTML бүтэн агуулга."),
      wordCount: z.number().int().nonnegative().optional().describe("Үгийн тоо (default 200)."),
      isPublished: z.boolean().optional().describe("Нийтлэх эсэх (default true)."),
      extra: z.record(z.string(), z.any()).optional().describe("Нэмэлт талбарууд (meta-аас)."),
      payload: z.record(z.string(), z.any()).optional().describe("Body-г бүрэн дарж бичих."),
    },
    ({ title, cover, category, preview, content, wordCount, isPublished, extra, payload }) =>
      guarded(() =>
        marketing.request("POST", contentsBase, {
          body:
            payload ?? {
              title,
              cover,
              category,
              preview,
              isPublished: isPublished ?? true,
              content: content ?? "",
              wordCount: wordCount ?? 200,
              ...(extra ?? {}),
            },
        })
      )
  );

  reg(
    "ubcab_marketing_content_get",
    "Press контентын дэлгэрэнгүй. GET /v1/content/api/content/contents/{id}.",
    { id: contentIdSchema },
    ({ id }) => guarded(() => marketing.request("GET", `${contentsBase}/${encodeURIComponent(id)}`))
  );

  reg(
    "ubcab_marketing_content_update",
    "Press контент ЗАСАХ. PUT /v1/content/api/content/contents/{id}. " +
      "⚠ Эхлээд _get-ээр одоогийн утгыг уншаад дутуугүй илгээ. ⚠ БИЧИХ үйлдэл.",
    {
      id: contentIdSchema,
      title: z.string().optional(),
      cover: z.string().optional().describe("Шинэ зургийн URL."),
      category: z.string().optional().describe("Ангилалын id."),
      preview: z.string().optional(),
      content: z.string().optional().describe("HTML агуулга."),
      wordCount: z.number().int().nonnegative().optional(),
      isPublished: z.boolean().optional(),
      extra: z.record(z.string(), z.any()).optional(),
      payload: z.record(z.string(), z.any()).optional().describe("Body-г бүрэн дарж бичих."),
    },
    ({ id, title, cover, category, preview, content, wordCount, isPublished, extra, payload }) =>
      guarded(() =>
        marketing.request("PUT", `${contentsBase}/${encodeURIComponent(id)}`, {
          body:
            payload ?? {
              ...(title !== undefined ? { title } : {}),
              ...(cover !== undefined ? { cover } : {}),
              ...(category !== undefined ? { category } : {}),
              ...(preview !== undefined ? { preview } : {}),
              ...(content !== undefined ? { content } : {}),
              ...(wordCount !== undefined ? { wordCount } : {}),
              ...(isPublished !== undefined ? { isPublished } : {}),
              ...(extra ?? {}),
            },
        })
      )
  );

  reg(
    "ubcab_marketing_content_delete",
    "Press контент УСТГАХ. DELETE /v1/content/api/content/contents/{id}. ⚠ Устгах үйлдэл.",
    { id: contentIdSchema },
    ({ id }) => guarded(() => marketing.request("DELETE", `${contentsBase}/${encodeURIComponent(id)}`))
  );

  reg(
    "ubcab_marketing_content_meta",
    "Press контентын формын META. GET /v1/content/api/content/contents/meta?action=create " +
      "эсвэл ?action=get&resourcesId={id}. (content, wordCount нь meta-д ГАРАХГҮЙ ч API хүлээж авдаг.)",
    {
      action: z.enum(["create", "get"]).optional().describe("create (default) эсвэл get."),
      resourcesId: z.string().optional().describe("action='get' үед контентын id."),
    },
    ({ action, resourcesId }) =>
      guarded(() =>
        marketing.request("GET", `${contentsBase}/meta`, {
          query: { action: action ?? "create", resourcesId },
        })
      )
  );

  reg(
    "ubcab_marketing_content_select_categories",
    "Press контентын АНГИЛЛЫН сонголтууд. GET /v1/content/api/content/select-options/categories. " +
      "📌 content_create-ийн 'category' утгыг эндээс ав.",
    {},
    () =>
      guarded(() => marketing.request("GET", "/v1/content/api/content/select-options/categories"))
  );

  // --- image upload (ӨӨР домэйн: upload.ubcabtech.com) ---
  reg(
    "ubcab_marketing_upload_image",
    "Зураг/файл БАЙРШУУЛАХ (cover зурагт). " +
      "POST https://upload.ubcabtech.com/v2/upload?useFileName=false&folderPath=...&prefix=... " +
      "(multipart, field нэр 'files'; Bearer токен нь marketing-тэй ижил). " +
      "Хариу: result[0].fileUrl (эсвэл .url) → үүнийг content_create-ийн 'cover'-т тавина. " +
      "Файлыг base64-ээр дамжуулна.",
    {
      filename: z.string().min(1).describe("Файлын нэр (ж: cover.jpg)."),
      fileBase64: z.string().min(1).describe("Файлын агуулга base64 хэлбэрээр."),
      mimeType: z.string().optional().describe("MIME төрөл (ж: image/jpeg)."),
      folderPath: z.string().optional().describe("Хадгалах хавтас (default 'contents')."),
      prefix: z.string().optional().describe("Нэрийн угтвар (default 'contents')."),
      useFileName: z.boolean().optional().describe("Файлын нэрийг хэвээр ашиглах эсэх (default false)."),
    },
    async ({ filename, fileBase64, mimeType, folderPath, prefix, useFileName }) => {
      try {
        const token = await marketing.getToken();
        let bytes: Buffer;
        try {
          bytes = Buffer.from(fileBase64, "base64");
        } catch {
          throw new BOError("fileBase64 нь буруу base64 байна.");
        }
        if (bytes.length === 0) throw new BOError("Файл хоосон байна (fileBase64 шалга).");
        const base = (process.env.UBCAB_UPLOAD_URL ?? "https://upload.ubcabtech.com").replace(
          /\/+$/,
          ""
        );
        const url = new URL(`${base}/v2/upload`);
        url.searchParams.set("useFileName", String(useFileName ?? false));
        url.searchParams.set("folderPath", folderPath ?? "contents");
        url.searchParams.set("prefix", prefix ?? "contents");
        const form = new FormData();
        form.append(
          "files",
          new Blob([new Uint8Array(bytes)], { type: mimeType || "application/octet-stream" }),
          filename
        );
        const origin = (process.env.UBCAB_BO_ORIGIN ?? DEFAULT_ORIGIN).replace(/\/+$/, "");
        const res = await fetch(url.toString(), {
          method: "POST",
          headers: {
            Authorization: `Bearer ${token}`,
            Accept: "application/json, text/plain, */*",
            Origin: origin,
            Referer: `${origin}/`,
          },
          body: form, // Content-Type-г fetch өөрөө boundary-тай тавина
        });
        const body = await safeJson(res);
        if (!res.ok) {
          return {
            content: [
              {
                type: "text" as const,
                text: `Upload error (HTTP ${res.status})\n${JSON.stringify(body, null, 2)}`,
              },
            ],
            isError: true,
          };
        }
        return { content: [{ type: "text" as const, text: JSON.stringify(body, null, 2) }] };
      } catch (err) {
        return {
          content: [{ type: "text" as const, text: err instanceof Error ? err.message : String(err) }],
          isError: true,
        };
      }
    }
  );

  // --- return orders (Буцах захиалга) ---
  reg(
    "ubcab_express_return_search",
    "UBExpress БУЦАХ захиалга (Буцах захиалга)-г tracking кодоор хайх. " +
      "POST https://operator-api.ubcabexpress.mn/v1/api/ready-return-shipments/list. " +
      "Энгийн захиалгаас олдоогүй үед энд хай. Бусад нь ubcab_express_order_search-тэй ижил.",
    expressListShape,
    ({ trackingNumber, page, limit, includeTotal, payload }) =>
      guarded(() =>
        expressClient.request("POST", "/v1/api/ready-return-shipments/list", {
          body: expressListBody({ trackingNumber, page, limit, includeTotal, payload }),
        })
      )
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
