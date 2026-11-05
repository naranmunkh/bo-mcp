# ubcab-bo-mcp

MCP server for the **UBCab Backoffice** (`registration-bo`) API — the same backend
that powers `operator.ubcab.mn`. Lets Claude search drivers, read driver detail
and rating, change driver state, and list service options.

Built on the same pattern as `timely-mcp`: a single self-contained
`api/index.ts` (the Vercel serverless function) that runs over **Streamable HTTP
on Vercel** (bearer + OAuth 2.1 PKCE) or over **stdio** locally.

**Live endpoint:** `https://bo-mcp.vercel.app/mcp` (POST, Bearer auth). Verified: `GET /health` → `{"status":"ok"}`.

## Auth

The BO uses **Keycloak SSO** (realm `ubcab-bo`). Since **2026-11-02** people log in
with Microsoft SSO and the realm rejects the password grant on every client
(`unauthorized_client` «Client not allowed for direct access grants»), so the old
username/password + TOTP login is gone. The server gets an access token from
`https://sso.ubcabtech.com/realms/ubcab-bo/protocol/openid-connect/token`:

- **client_credentials (service account)** — set `UBCAB_BO_CLIENT_ID` + `UBCAB_BO_CLIENT_SECRET`
  of a *confidential* client with **Service accounts** enabled, created by the BO team with the
  roles the tools need. Durable: no user, no 2FA, every serverless instance logs in on its own.
- **refresh_token grant** — set `UBCAB_BO_REFRESH_TOKEN` (e.g. an offline token from a one-time
  browser login). When a client secret is set too, it is sent with the refresh, and a rejected
  refresh token falls back to client_credentials.

Express reads its own client: `UBCAB_EXPRESS_CLIENT_ID` + `_CLIENT_SECRET` (operator-api; set the
same values if the BO team issues one client for everything). Marketing (marketing-bo-api and the
image upload) and UBEats (`ubeats_*` tools, ubeats-bo-api) reuse the `UBCAB_BO_*` client unless
`UBCAB_MARKETING_CLIENT_ID` / `UBEATS_CLIENT_ID` (+ `_CLIENT_SECRET`) is set — the shared client
then needs their roles and origins too. Each also accepts `*_REFRESH_TOKEN`. The public BO clients
(`ubcab-registration-bo`, `express-bo`, `ubeats-bo`, `ubcab-marketing-bo`) cannot have service accounts.

Access tokens are short-lived (~5 min); the server caches and silently re-auths.
Every API call also sends `Origin`/`Referer` (`operator.ubcab.mn`, `office.ubcabexpress.mn`,
`office.ubeats.mn`) — ask the BO team to put that origin in the service-account client's
*Web origins* (Keycloak copies them into the token's `allowed-origins`; anything else gets
403 «Invalid origin», verified for UBEats on 2026-10-16).

A rejected token request is returned to the tool caller and logged as `Keycloak auth failed
(HTTP <status>) [build …, client=…, origin=…, grant=…, creds=…]` (the log line adds Keycloak's
error code) — the only trace in the Vercel logs, because tool errors return HTTP 200.

## Per-user BO token (X-BO-User-Token)

A caller that is already authenticated to this server (bearer token or the built-in OAuth) can
forward the signed-in person's own BO access token in the request header
`X-BO-User-Token: <access token (JWT)>`. Then:

- The **registration** and **marketing** tools call BO with `Authorization: Bearer <that token>`,
  so every action runs with the person's own permissions and shows their name in BO's audit log.
  No Keycloak request is made, and the token is never cached or shared: it exists only for the
  duration of that one HTTP request.
- **Express** and **UBEats** tools ignore the header and keep their own credentials.
- `Origin`/`Referer` for these calls come from `UBCAB_BO_USER_ORIGIN` (default
  `https://operator.ubcab.mn`), read on every request; the auth-context suffix shows the same origin.
- `ubcab_marketing_upload_image` uses the same token and origin (it never falls back to the server
  credentials when the header is present).
- If BO answers **401**, there is no retry and no fallback to the server credentials; the tool error
  starts with `BO_USER_TOKEN_REJECTED (HTTP 401)` (login expired: the caller should get a fresh token
  and retry once). If BO answers **403**, the error starts with `BO_USER_FORBIDDEN (HTTP 403)`: the
  person is signed in but lacks permission, so a fresh token will not help; no retry, no fallback.
- A header that is longer than 16 KB or not three base64url segments gives a tool error starting with
  `BO_USER_TOKEN_INVALID` and no BO call. The header is ignored on requests that fail the server's own
  authentication.
- Without the header nothing changes: the server's own credentials are used.
- The token is never logged or echoed: JWT-looking strings and the exact header value are
  replaced with `***` in errors and logs. Auth errors end with `user_token=yes|no`.

## Tools

| Tool | Method / Endpoint | Purpose |
| --- | --- | --- |
| `ubcab_bo_driver_search` | `POST /v1/driver/drivers/list` | Жолоочийг утас/регистр/нэр/shortId-аар хайх → `_id` авах |
| `ubcab_bo_driver_get` | `GET /v1/driver/drivers/{driverId}` | Жолоочийн дэлгэрэнгүй (profile, vehicle, kyc…) |
| `ubcab_bo_driver_rating` | `GET /v1/driver/rating/{driverId}` | Жолоочийн үнэлгээ |
| `ubcab_bo_driver_set_state` | `PUT /v1/driver/drivers/{driverId}/state` | Төлөв солих: `normal` / `suspended` (reason ≥10 тэмдэгт) |
| `ubcab_bo_service_options` | `GET /v1/driver/select-options/services` | Үйлчилгээний сонголтын жагсаалт |
| `ubcab_bo_driver_history` | `POST /v1/activity/api/drivers/{id}/history` | Жолоочийн үйлчилгээний түүх; `phone` өгвөл зорчигчийн утсаар шүүнэ; `docs[].serviceId` → trip_get |
| `ubcab_bo_driver_wallet` | `GET /v1/driver/drivers/{id}/wallet` | Хэтэвчний үлдэгдэл |
| `ubcab_bo_driver_wallet_history` | `POST /v1/driver/drivers/{id}/wallet/history` | Хэтэвчний гүйлгээний түүх (paged; `beginDate`/`endDate`-аар шүүж сарын орлого/зарлага) |
| `ubcab_bo_driver_vehicles` | `GET /v1/driver/drivers/{id}/vehicles/list` | Тээврийн хэрэгслүүд |
| `ubcab_bo_driver_vehicle_services_update` | `PUT /v1/driver/drivers/{id}/vehicles/update` | ⚠ Машины үйлчилгээ нэмэх/хасах (`approvedServices` бүтнээр дарж бичнэ) |
| `ubcab_bo_driver_feedback` | `POST /v1/driver/rating/{id}/list` | Сэтгэгдэл/үнэлгээний жагсаалт (paged) |
| `ubcab_bo_driver_loyalty_history` | `POST /v1/loyalty/driver/drivers/{id}/level-history/list` | Цолны түүх (paged) |
| `ubcab_bo_audit_log_list` | `POST /v1/audit-log/list` | Audit log — хэн юуг хэзээ өөрчилсөн (`target{type,_id}`) |
| `ubcab_bo_vehicle_inspection_get` | `GET /v1/driver/vehicle-inspections/{id}` | Техникийн үзлэгийн дэлгэрэнгүй (асуулт бүрийн хариу, result, expiresAt) |
| `ubcab_bo_vehicle_inspection_drivers` | `POST /v1/driver/vehicle-inspections/{id}/drivers/list` | Үзлэгт хамаарах жолоочид (paged) |
| `ubcab_bo_rider_search` | `POST /v1/rider/riders/list` | Хэрэглэгч (rider) хайх (body: filter.query) |
| `ubcab_bo_rider_history` | `POST /v1/activity/api/riders/{id}/history` | Хэрэглэгчийн аяллын түүх; `phone` өгвөл жолоочийн утсаар шүүнэ; `docs[].serviceId` → trip_get |
| `ubcab_bo_trip_get` | `GET /v1/taxi/api/trips/{id}` | Аяллын үндсэн бүх мэдээлэл |
| `ubcab_bo_trip_routes` | `GET …/{id}/routes` | Маршрут (GPS зам) |
| `ubcab_bo_trip_invoices` | `GET …/{id}/invoices` | Нэхэмжлэл |
| `ubcab_bo_rider_invoices` | `POST /v1/rider/riders/{id}/invoices` | Хэрэглэгчийн нэхэмжлэхүүд (filter.status, ж: open) |
| `ubcab_bo_invoice_get` | `GET /v1/billing/api/invoices/{id}` | Нэхэмжлэхийн дэлгэрэнгүй |
| `ubcab_bo_service_trip_invoices` | `GET /v1/{service}/api/trips/{id}/invoices` (+ delivery requests) | Аль ч үйлчилгээний аяллын нэхэмжлэх |
| `ubcab_bo_trip_charges` | `GET …/{id}/charges` | Төлбөр тооцооны задаргаа |
| `ubcab_bo_trip_complaints` | `GET …/{id}/complaints` | Гомдол |
| `ubcab_bo_trip_penalties` | `GET …/{id}/penalties` | Торгууль (жагсаалт) |
| `ubcab_bo_trip_penalty_cancel` | `POST …/trips/{tripId}/penalties/{penaltyId}/cancel` | ⚠ Торгууль цуцлах (write) |
| `ubcab_bo_delivery_penalty_cancel` | `POST /v1/delivery/api/trips/{tripId}/penalties/{penaltyId}/cancel` | ⚠ Хүргэлтийн торгууль цуцлах |
| `ubcab_bo_trip_loyalty` | `GET …/{id}/loyalty` | Урамшуулал |
| `ubcab_express_track` | `GET express-tracking.ubcabtech.com/v1/trackings/{code}` | TEMU/чиглэлийн илгээмж хянах (нэвтрэлтгүй нийтийн API) |
| `ubcab_express_order_search` | `POST operator-api.ubcabexpress.mn/v1/api/address-ready-shipments/list` | UBExpress энгийн захиалга хайх (operator, client express-bo) |
| `ubcab_express_return_search` | `POST operator-api.ubcabexpress.mn/v1/api/ready-return-shipments/list` | UBExpress буцах захиалга хайх |
| `ubcab_marketing_help_group_list` | `POST marketing-bo-api…/v1/content/api/help/content-groups/list` | Гарын авлагын категорууд |
| `ubcab_marketing_help_group_create` | `POST …/content-groups` | ⚠ Шинэ категор нэмэх (name, order) |
| `ubcab_marketing_help_group_get` | `GET …/content-groups/{id}` | Категорын дэлгэрэнгүй |
| `ubcab_marketing_help_group_delete` | `DELETE …/content-groups/{id}` | ⚠ Категор устгах |
| `ubcab_marketing_help_group_meta` | `GET …/content-groups/meta?action=create\|get` | Формын meta |
| `ubcab_marketing_content_category_list` | `POST …/v1/content/api/content/categories/list` | Мэдээний (Press) ангиллууд |
| `ubcab_marketing_content_category_create` | `POST …/content/categories` | ⚠ Шинэ мэдээний ангилал |
| `ubcab_marketing_content_category_get` | `GET …/content/categories/{id}` | Ангилалын дэлгэрэнгүй |
| `ubcab_marketing_content_category_update` | `PUT …/content/categories/{id}` | ⚠ Засах |
| `ubcab_marketing_help_content_list` | `POST …/help/contents/list` | Тусламжийн агуулгууд (filter: slug, title) |
| `ubcab_marketing_help_content_create` | `POST …/help/contents` | ⚠ Агуулга нэмэх (`slug`=null шинэ / slug=орчуулга) |
| `ubcab_marketing_help_content_get` | `GET …/help/contents/{id}` | Агуулгын дэлгэрэнгүй |
| `ubcab_marketing_help_content_update` | `PUT …/help/contents/{id}` | ⚠ Агуулга засах |
| `ubcab_marketing_help_content_delete` | `DELETE …/help/contents/{id}` | ⚠ Агуулга устгах |
| `ubcab_marketing_help_content_meta` | `GET …/help/contents/meta` | Формын meta |
| `ubcab_marketing_help_select_content_groups` | `GET …/help/select-options/content-groups` | Бүлгийн сонголт (`group` утга) |
| `ubcab_marketing_help_select_language` | `GET …/help/select-options/language` | Хэлний сонголт |
| `ubcab_marketing_content_list` | `POST …/content/contents/list` | Press контентууд |
| `ubcab_marketing_content_create` | `POST …/content/contents` | ⚠ Контент нэмэх (title, cover, category, preview) |
| `ubcab_marketing_content_get` | `GET …/content/contents/{id}` | Дэлгэрэнгүй |
| `ubcab_marketing_content_update` | `PUT …/content/contents/{id}` | ⚠ Засах |
| `ubcab_marketing_content_delete` | `DELETE …/content/contents/{id}` | ⚠ Устгах |
| `ubcab_marketing_content_meta` | `GET …/content/contents/meta` | Формын meta |
| `ubcab_marketing_content_select_categories` | `GET …/content/select-options/categories` | Ангиллын сонголт (`category`) |
| `ubcab_marketing_upload_image` | `POST upload.ubcabtech.com/v2/upload` | Зураг байршуулах → `cover` URL |
| `ubcab_marketing_content_category_delete` | `DELETE …/content/categories/{id}` | ⚠ Устгах |
| `ubcab_marketing_content_category_meta` | `GET …/content/categories/meta` | Формын meta (талбар динамик) |
| `ubeats_order_search` | `POST ubeats-bo-api…/v1/api/orders/list` | UBEats Cloud Kitchen захиалга хайх (filter.customerPhone) |
| `ubeats_order_get` | `GET …/v1/api/orders/{id}` | Cloud Kitchen захиалгын бүрэн дэлгэрэнгүй |
| `ubeats_order_state_histories` | `GET …/v1/api/orders/{id}/state-histories` | Cloud Kitchen төлөвийн түүх |
| `ubeats_merchant_order_search` | `POST …/v1/api/merchant-orders/list` | UBEats Merchant захиалга хайх |
| `ubeats_merchant_order_get` | `GET …/v1/api/merchant-orders/{id}` | Merchant захиалгын бүрэн дэлгэрэнгүй |
| `ubeats_merchant_order_state_histories` | `GET …/v1/api/merchant-orders/{id}/state-histories` | Merchant төлөвийн түүх |

> ⚠ `driver_get` / `trip_get` return PII (name, phone, register no, civil ID). `driver_set_state` is a write action.

## Local run (stdio)

```bash
npm install
npm test               # offline auth tests (compiles first; fetch is stubbed)
cp .env.example .env   # fill UBCAB_BO_CLIENT_ID + UBCAB_BO_CLIENT_SECRET (+ the express pair)
npm run test:login     # live: one read-only call per configured API, prints status/row counts only
```

Claude Desktop config:

```json
{
  "mcpServers": {
    "ubcab-bo": {
      "command": "node",
      "args": ["/abs/path/to/ubcab-bo-mcp/dist/api/index.js"],
      "env": {
        "UBCAB_BO_CLIENT_ID": "...",
        "UBCAB_BO_CLIENT_SECRET": "..."
      }
    }
  }
}
```

## Deploy (Vercel)

Deploy with the Vercel CLI from this folder: `vercel --prod` (`.vercel/project.json`
links it to `ubc-ab/bo-mcp`). Pushes to GitHub (`naranmunkh/bo-mcp`, a public repo)
stopped auto-deploying after the project moved to the UBCab team.
Zero-config: `api/index.ts` is auto-built as a serverless function, and
`vercel.json` `rewrites` send every path (`/mcp`, `/health`, `/.well-known/*`) to
it. There is intentionally **no `build` script** — a `build` script makes Vercel
expect a static `public/` output and the deploy fails. Local TypeScript build is
`npm run compile`.

Required env vars on the Vercel project: `UBCAB_BO_CLIENT_ID`, `UBCAB_BO_CLIENT_SECRET`
(Sensitive), and `UBCAB_BO_MCP_AUTH_TOKEN` (`openssl rand -hex 32`); for the express tools also
`UBCAB_EXPRESS_CLIENT_ID` + `_CLIENT_SECRET` (marketing and UBEats use the BO client unless given their own).
The retired `*_USERNAME`, `*_PASSWORD` and `*_TOTP_SECRET` vars are ignored — delete them.

Connect from Claude with `Authorization: Bearer <UBCAB_BO_MCP_AUTH_TOKEN>` at
`https://bo-mcp.vercel.app/mcp`. The endpoint **fails closed** if
`UBCAB_BO_MCP_AUTH_TOKEN` is unset.

### Is the latest build live?

Every Keycloak auth error ends with a non-secret context, for example
`[build 2026-11-02 client-credentials, client=bo-mcp-registration, origin=https://operator.ubcab.mn, grant=client_credentials, creds=UBCAB_BO_*]`.
No `[build …]`, or an older build (`2026-10-16 bo-login+totp`) → an old deploy is
still serving: the top Production deployment in Vercel must be the latest code
("Redeploy" on an old deployment rebuilds that old source). `client` / `origin` /
`creds` show what was actually sent and which env vars it came from, so a stale
override is visible there.

## Extending

Add a new endpoint by registering another tool inside `createMcpServer()` in
`api/index.ts` — copy one of the existing `reg(...)` blocks.
