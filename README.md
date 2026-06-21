# ubcab-bo-mcp

MCP server for the **UBCab Backoffice** (`registration-bo`) API — the same backend
that powers `operator.ubcab.mn`. Lets Claude search drivers, read driver detail
and rating, change driver state, and list service options.

Built on the same pattern as `timely-mcp`: a single self-contained
`api/index.ts` (the Vercel serverless function) that runs over **Streamable HTTP
on Vercel** (bearer + OAuth 2.1 PKCE) or over **stdio** locally.

**Live endpoint:** `https://bo-mcp.vercel.app/mcp` (POST, Bearer auth). Verified: `GET /health` → `{"status":"ok"}`.

## Auth

The BO uses **Keycloak SSO** (realm `ubcab-bo`, client `ubcab-registration-bo`).
The server gets an access token from
`https://sso.ubcabtech.com/realms/ubcab-bo/protocol/openid-connect/token`:

- **password grant** — set `UBCAB_BO_USERNAME` + `UBCAB_BO_PASSWORD` (recommended; durable).
- **refresh_token grant** — set `UBCAB_BO_REFRESH_TOKEN` (use if password grant is disabled; expires).

Access tokens are short-lived (~5 min); the server caches and silently re-auths.
Every API call also sends `Origin`/`Referer = operator.ubcab.mn`.

## Tools

| Tool | Method / Endpoint | Purpose |
| --- | --- | --- |
| `ubcab_bo_driver_search` | `POST /v1/driver/drivers/list` | Жолоочийг утас/регистр/нэр/shortId-аар хайх → `_id` авах |
| `ubcab_bo_driver_get` | `GET /v1/driver/drivers/{driverId}` | Жолоочийн дэлгэрэнгүй (profile, vehicle, kyc…) |
| `ubcab_bo_driver_rating` | `GET /v1/driver/rating/{driverId}` | Жолоочийн үнэлгээ |
| `ubcab_bo_driver_set_state` | `PUT /v1/driver/drivers/{driverId}/state` | Төлөв солих: `normal` / `suspended` (reason ≥10 тэмдэгт) |
| `ubcab_bo_service_options` | `GET /v1/driver/select-options/services` | Үйлчилгээний сонголтын жагсаалт |
| `ubcab_bo_driver_history` | `POST /v1/activity/api/drivers/{id}/history` | Жолоочийн үйлчилгээний түүх (body: page, limit) |
| `ubcab_bo_trip_get` | `GET /v1/taxi/api/trips/{id}` | Аяллын үндсэн бүх мэдээлэл |
| `ubcab_bo_trip_routes` | `GET …/{id}/routes` | Маршрут (GPS зам) |
| `ubcab_bo_trip_invoices` | `GET …/{id}/invoices` | Нэхэмжлэл |
| `ubcab_bo_trip_charges` | `GET …/{id}/charges` | Төлбөр тооцооны задаргаа |
| `ubcab_bo_trip_complaints` | `GET …/{id}/complaints` | Гомдол |
| `ubcab_bo_trip_penalties` | `GET …/{id}/penalties` | Торгууль |
| `ubcab_bo_trip_loyalty` | `GET …/{id}/loyalty` | Урамшуулал |

> ⚠ `driver_get` / `trip_get` return PII (name, phone, register no, civil ID). `driver_set_state` is a write action.

## Local run (stdio)

```bash
npm install
npm run compile
cp .env.example .env   # fill UBCAB_BO_USERNAME + UBCAB_BO_PASSWORD
node --env-file=.env scripts/test-login.mjs 99054120   # live smoke test
```

Claude Desktop config:

```json
{
  "mcpServers": {
    "ubcab-bo": {
      "command": "node",
      "args": ["/abs/path/to/ubcab-bo-mcp/dist/api/index.js"],
      "env": {
        "UBCAB_BO_USERNAME": "...",
        "UBCAB_BO_PASSWORD": "..."
      }
    }
  }
}
```

## Deploy (Vercel)

Connected to GitHub (`naranmunkh/bo-mcp`) — every push to `main` auto-deploys.
Zero-config: `api/index.ts` is auto-built as a serverless function, and
`vercel.json` `rewrites` send every path (`/mcp`, `/health`, `/.well-known/*`) to
it. There is intentionally **no `build` script** — a `build` script makes Vercel
expect a static `public/` output and the deploy fails. Local TypeScript build is
`npm run compile`.

Required env vars on the Vercel project: `UBCAB_BO_USERNAME`, `UBCAB_BO_PASSWORD`,
and `UBCAB_BO_MCP_AUTH_TOKEN` (`openssl rand -hex 32`).

Connect from Claude with `Authorization: Bearer <UBCAB_BO_MCP_AUTH_TOKEN>` at
`https://bo-mcp.vercel.app/mcp`. The endpoint **fails closed** if
`UBCAB_BO_MCP_AUTH_TOKEN` is unset.

## Extending

Add a new endpoint by registering another tool inside `createMcpServer()` in
`api/index.ts` — copy one of the existing `reg(...)` blocks.
