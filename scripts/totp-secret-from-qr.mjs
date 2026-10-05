#!/usr/bin/env node
/**
 * Google Authenticator «Export accounts» QR (эсвэл Keycloak-ийн тохиргооны QR)-ийн
 * зургаас TOTP түлхүүрийг гаргаж, ДЭЛГЭЦЭНД ХАРУУЛАХГҮЙГЭЭР Vercel-ийн bo-mcp
 * төслийн `UBCAB_BO_TOTP_SECRET` (Production, Sensitive)-д хадгална.
 *
 *   node scripts/totp-secret-from-qr.mjs <qr-зураг.png> [--pick N] [--dry-run]
 *
 * - Зургийг `zbarimg` (brew install zbar)-ээр уншина. Сүлжээнд юу ч илгээхгүй
 *   (зөвхөн эцэст нь `vercel env` команд).
 * - Олон аккаунттай экспорт бол нэр/issuer-ээр жагсааж, `--pick N`-ээр сонгуулна.
 * - Түлхүүрийг хэзээ ч хэвлэхгүй; зөвхөн ОДООГИЙН 6 оронтой кодыг харуулна —
 *   утсан дээрх кодтой таарч байгаа эсэхийг шалгахад.
 * - `--dry-run`: Vercel-д хадгалахгүй, зөвхөн код таарч буйг шалгана.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { createHmac } from "node:crypto";
import { existsSync } from "node:fs";

const args = process.argv.slice(2);
const image = args.find((a) => !a.startsWith("--"));
const pickIdx = args.indexOf("--pick");
const pick = pickIdx >= 0 ? Number(args[pickIdx + 1]) : null;
const dryRun = args.includes("--dry-run");
const ENV_NAME = "UBCAB_BO_TOTP_SECRET";

function fail(msg) {
  console.error("✗ " + msg);
  process.exit(1);
}

if (!image || !existsSync(image)) fail("QR зургийн замыг өгнө үү: node scripts/totp-secret-from-qr.mjs <зураг.png>");

let raw;
try {
  raw = execFileSync("zbarimg", ["--raw", "-q", image], { encoding: "utf8" }).trim();
} catch {
  fail("Зурган дээрээс QR уншиж чадсангүй (zbarimg). Илүү тод/томоор дахин зураг авна уу.");
}
const uri = raw.split(/\r?\n/).find((l) => l.startsWith("otpauth"));
if (!uri) fail("Энэ QR нь authenticator-ийн QR биш байна (otpauth:// эсвэл otpauth-migration:// хүлээсэн).");

/* ---------- base32 ---------- */
const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function toBase32(buf) {
  let bits = 0, value = 0, out = "";
  for (const b of buf) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  return out;
}
function fromBase32(s) {
  let bits = 0, value = 0; const out = [];
  for (const ch of s.toUpperCase().replace(/[\s=-]/g, "")) {
    const i = B32.indexOf(ch);
    if (i < 0) fail("Түлхүүр base32 биш байна.");
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 0xff); bits -= 8; }
  }
  return Buffer.from(out);
}

/* ---------- protobuf (Google Authenticator MigrationPayload) ---------- */
function readVarint(buf, pos) {
  let result = 0n, shift = 0n, b;
  do { b = buf[pos++]; result |= BigInt(b & 0x7f) << shift; shift += 7n; } while (b & 0x80);
  return [Number(result), pos];
}
function parseMessage(buf) {
  const fields = [];
  let pos = 0;
  while (pos < buf.length) {
    let key; [key, pos] = readVarint(buf, pos);
    const field = key >>> 3, wire = key & 7;
    if (wire === 0) { let v; [v, pos] = readVarint(buf, pos); fields.push([field, v]); }
    else if (wire === 2) { let len; [len, pos] = readVarint(buf, pos); fields.push([field, buf.subarray(pos, pos + len)]); pos += len; }
    else if (wire === 5) { pos += 4; } else if (wire === 1) { pos += 8; }
    else fail("Экспортын QR-ийн бүтэц танигдсангүй.");
  }
  return fields;
}

const ALG = { 0: "SHA1", 1: "SHA1", 2: "SHA256", 3: "SHA512" };
const DIGITS = { 0: 6, 1: 6, 2: 8 };
let accounts = [];

if (uri.startsWith("otpauth-migration://")) {
  const data = new URL(uri).searchParams.get("data");
  if (!data) fail("Экспортын QR-д өгөгдөл алга.");
  const payload = Buffer.from(data, "base64");
  for (const [f, v] of parseMessage(payload)) {
    if (f !== 1) continue;
    const acc = { secret: null, name: "", issuer: "", algorithm: "SHA1", digits: 6, type: 2 };
    for (const [g, w] of parseMessage(v)) {
      if (g === 1) acc.secret = Buffer.from(w);
      else if (g === 2) acc.name = w.toString("utf8");
      else if (g === 3) acc.issuer = w.toString("utf8");
      else if (g === 4) acc.algorithm = ALG[w] ?? "SHA1";
      else if (g === 5) acc.digits = DIGITS[w] ?? 6;
      else if (g === 6) acc.type = w; // 1 = HOTP, 2 = TOTP
    }
    if (acc.secret) accounts.push(acc);
  }
} else {
  const u = new URL(uri);
  const p = u.searchParams;
  const label = decodeURIComponent(u.pathname.replace(/^\/+totp\//, "").replace(/^\/+/, ""));
  accounts.push({
    secret: fromBase32(p.get("secret") ?? ""),
    name: label,
    issuer: p.get("issuer") ?? "",
    algorithm: (p.get("algorithm") ?? "SHA1").toUpperCase(),
    digits: Number(p.get("digits") ?? 6),
    type: u.host === "hotp" ? 1 : 2,
  });
}

if (accounts.length === 0) fail("QR дотроос аккаунт олдсонгүй.");

let chosen;
if (accounts.length === 1) chosen = accounts[0];
else {
  console.log("QR дотор хэд хэдэн аккаунт байна:");
  accounts.forEach((a, i) => console.log(`  ${i + 1}. ${a.issuer || "—"} · ${a.name || "—"}`));
  if (pick === null || !(pick >= 1 && pick <= accounts.length)) {
    fail("Аль нэгийг нь --pick N-ээр сонгоно уу (жиш: --pick 2).");
  }
  chosen = accounts[pick - 1];
}

if (chosen.type === 1) fail("Энэ нь HOTP (тоолууртай) аккаунт — TOTP хэрэгтэй.");
if (chosen.algorithm !== "SHA1" || chosen.digits !== 6) {
  console.log(`⚠ Энэ аккаунт ${chosen.algorithm}/${chosen.digits} оронтой — bo-mcp-д UBCAB_BO_TOTP_ALGORITHM, UBCAB_BO_TOTP_DIGITS env мөн тавих шаардлагатай.`);
}

function totpNow(key, alg, digits) {
  const counter = Math.floor(Date.now() / 30000);
  const msg = Buffer.alloc(8);
  msg.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  msg.writeUInt32BE(counter >>> 0, 4);
  const h = createHmac(alg.toLowerCase(), key).update(msg).digest();
  const o = h[h.length - 1] & 0x0f;
  const bin = ((h[o] & 0x7f) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3];
  return String(bin % 10 ** digits).padStart(digits, "0");
}

const secretB32 = toBase32(chosen.secret);
console.log(`Сонгосон аккаунт: ${chosen.issuer || "—"} · ${chosen.name || "—"}`);
console.log(`Одоогийн код: ${totpNow(chosen.secret, chosen.algorithm, chosen.digits)}  ← утсан дээрх кодтой таарч байгаа эсэхийг шалгаарай`);

if (dryRun) {
  console.log("--dry-run: Vercel-д хадгалсангүй.");
  process.exit(0);
}

// Хуучин (буруу) утгыг устгаад шинээр нэмнэ. Утгыг stdin-ээр дамжуулна — дэлгэц,
// түүх, процессын жагсаалтад харагдахгүй.
spawnSync("vercel", ["env", "rm", ENV_NAME, "production", "--yes"], { stdio: ["ignore", "ignore", "ignore"] });
const add = spawnSync("vercel", ["env", "add", ENV_NAME, "production", "--sensitive"], {
  input: secretB32 + "\n",
  stdio: ["pipe", "inherit", "inherit"],
});
if (add.status !== 0) fail("Vercel-д хадгалж чадсангүй (дээрх алдааг үзнэ үү).");
console.log(`✓ ${ENV_NAME} хадгалагдлаа. Одоо QR зургаа устгаарай, дараа нь bo-mcp-г дахин deploy хийнэ.`);
