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
