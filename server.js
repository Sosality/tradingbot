// server.js
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import crypto from "crypto";
import cors from "cors";
import { Pool } from "pg";
import querystring from "querystring";

const app = express();

// ИЗМЕНЕНИЕ 1: Настраиваем CORS для передачи сессионных куки
app.use(cors({
  origin: true, // Разрешает любые домены (фронтенд)
  credentials: true // Разрешает передачу кук/сессий
}));

app.use(express.json());
app.use(express.static("public"));

// require env
if (!process.env.DATABASE_URL) {
if (!process.env.BOT_TOKEN) {
  console.warn("BOT_TOKEN not set! Telegram signature verification will fail.");
}

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper: create secretKey per Telegram docs
function telegramSecretKey() {
  return crypto.createHash("sha256").update(process.env.BOT_TOKEN || "").digest();
}

// Проверка подписанного initData string (Telegram WebApp)
function checkTelegramAuthInitData(initData) {
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash) return false;
    params.delete("hash");
    const dataCheckString = [...params.entries()].sort().map(([k,v]) => `${k}=${v}`).join("\n");
    const secretKey = telegramSecretKey();
    const computed = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
    return computed === hash;
  } catch (e) {
    console.error("checkTelegramAuthInitData err", e.message || e);
    return false;
  }
}

// Проверка подписанных query params от Telegram Login Widget (GET)
function checkTelegramAuthParams(paramsObj) {
  try {
    // paramsObj is object from req.query
    const copy = { ...paramsObj };
    const hash = copy.hash;
    if (!hash) return false;
    delete copy.hash;
    delete copy.redirect; // we may have redirect param, ignore it for check

    const dataCheckString = Object.keys(copy)
      .sort()
      .map(k => `${k}=${copy[k]}`)
      .join("\n");
    const secretKey = telegramSecretKey();
    const computed = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
    return computed === hash;
  } catch (e) {
    console.error("checkTelegramAuthParams err", e.message || e);
    return false;
  }
}

// Session cookie helpers
const COOKIE_NAME = "tg_session";
function makeSessionCookieValue(userId) {
  const secret = process.env.COOKIE_SECRET || process.env.BOT_TOKEN || "fallback_secret";
  const mac = crypto.createHmac("sha256", secret).update(String(userId)).digest("hex");
  return `${userId}:${mac}`;
}
function verifySessionCookieValue(val) {
  if (!val || typeof val !== "string") return false;
  const [userId, mac] = val.split(":");
  if (!userId || !mac) return false;
  const expected = crypto.createHmac("sha256", (process.env.COOKIE_SECRET || process.env.BOT_TOKEN || "fallback_secret")).update(String(userId)).digest("hex");
  return mac === expected ? userId : false;
}

// DB init
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      first_name TEXT,
      username TEXT,
      photo_url TEXT,
      balance NUMERIC NOT NULL DEFAULT 1000,
      created_at TIMESTAMP DEFAULT NOW(),
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS positions (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
      type TEXT NOT NULL,
      entry_price NUMERIC NOT NULL,
      margin NUMERIC NOT NULL,
      leverage INT NOT NULL,
      size NUMERIC NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
  console.log("DB initialized");
}
await initDB();

// Helper: create / update user record
async function upsertUserFromObj(userObj) {
  const userId = String(userObj.id);
  await db.query(
    `INSERT INTO users(user_id, first_name, username, photo_url)
     VALUES ($1,$2,$3,$4) ON CONFLICT(user_id) DO UPDATE
       SET first_name = EXCLUDED.first_name,
           username = EXCLUDED.username,
           photo_url = EXCLUDED.photo_url,
           updated_at = NOW()`,
    [userId, userObj.first_name || null, userObj.username || null, userObj.photo_url || null]
  );
  const res = await db.query("SELECT user_id, first_name, username, photo_url, balance FROM users WHERE user_id=$1", [userId]);
  return res.rows[0];
}

// ===== /auth/telegram  <-- endpoint для Telegram Login Widget (GET)
// Telegram widget делает GET на data-auth-url с параметрами user + hash
app.get("/auth/telegram", async (req, res) => {
  try {
    const params = req.query || {};
    const redirectTo = params.redirect || "/";
    const ok = checkTelegramAuthParams(params);
    if (!ok) {
      console.warn("Telegram login widget signature invalid");
      return res.status(403).send("Invalid Telegram signature");
    }
    // build user from params
    const user = {
      id: params.id,
      first_name: params.first_name,
      last_name: params.last_name,
      username: params.username,
      photo_url: params.photo_url
    };
    // upsert user
    const userRow = await upsertUserFromObj(user);

    // set cookie
    const cookieVal = makeSessionCookieValue(userRow.user_id);
    // set secure cookie (if deployed under https)
    const isSecure = req.headers["x-forwarded-proto"] === "https" || req.protocol === "https";
    const cookieParts = [
      `${COOKIE_NAME}=${cookieVal}`,
      `Path=/`,
      `HttpOnly`,
      `SameSite=Lax`,
      `Max-Age=${60 * 60 * 24 * 30}` // 30 days
    ];
    if (isSecure) cookieParts.push("Secure");
    res.setHeader("Set-Cookie", cookieParts.join("; "));
    // redirect back to app
    return res.redirect(redirectTo);
  } catch (err) {
    console.error("/auth/telegram error", err);
    return res.status(500).send("Server error");
  }
});

// ===== /api/init  <-- поддерживает оба пути: initData (Telegram WebApp) или cookie-сессию
app.post("/api/init", async (req, res) => {
  try {
    const { initData } = req.body;

    // 1) если пришёл initData (Telegram WebApp в iframe) — проверяем и используем
    if (initData) {
      const okSig = checkTelegramAuthInitData(initData);
      if (!okSig) {
        if (process.env.DEV_ALLOW_BYPASS === "1") {
          console.warn("DEV_ALLOW_BYPASS active — accepting invalid initData");
        } else {
          return res.status(403).json({ ok: false, error: "INVALID_SIGNATURE" });
        }
      }
      const params = new URLSearchParams(initData);
      const rawUser = params.get("user");
      if (!rawUser) return res.status(400).json({ ok: false, error: "NO_USER" });
      const userObj = JSON.parse(rawUser);
      const userRow = await upsertUserFromObj(userObj);
      const positionsRes = await db.query("SELECT * FROM positions WHERE user_id=$1 ORDER BY created_at ASC", [userRow.user_id]);
      // set session cookie so subsequent loads from browser work
      const cookieVal = makeSessionCookieValue(userRow.user_id);
      const isSecure = req.headers["x-forwarded-proto"] === "https" || req.protocol === "https";
      const cookieParts = [
        `${COOKIE_NAME}=${cookieVal}`,
        `Path=/`,
        `HttpOnly`,
        `SameSite=Lax`,
        `Max-Age=${60 * 60 * 24 * 30}` // 30 days
      ];
      if (isSecure) cookieParts.push("Secure");
      res.setHeader("Set-Cookie", cookieParts.join("; "));
      return res.json({ ok: true, user: userRow, positions: positionsRes.rows });
    }

    // 2) Если initData нет — пытаемся восстановить по cookie-сессии
    const cookies = (req.headers.cookie || "").split(";").map(s => s.trim()).filter(Boolean);
    const cookieObj = {};
    cookies.forEach(c => {
      const idx = c.indexOf("=");
      if (idx === -1) return;
      cookieObj[c.slice(0, idx)] = c.slice(idx + 1);
    });
    const sessionVal = cookieObj[COOKIE_NAME];
    const userId = verifySessionCookieValue(sessionVal);
    if (userId) {
      const ures = await db.query("SELECT user_id, first_name, username, photo_url, balance FROM users WHERE user_id=$1", [userId]);
      if (!ures.rows.length) return res.status(404).json({ ok:false, error: "NO_USER" });
      const positionsRes = await db.query("SELECT * FROM positions WHERE user_id=$1 ORDER BY created_at ASC", [userId]);
      return res.json({ ok:true, user: ures.rows[0], positions: positionsRes.rows });
    }

    // nothing found
    return res.status(400).json({ ok: false, error: "NO_INIT_DATA" });

  } catch (err) {
    console.error("/api/init error:", err);
    return res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

// keep your order endpoints (open/close) unchanged or copy existing ones
app.post("/api/order/open", async (req, res) => {
  // Implement or copy your previous logic here (use DB)
  return res.status(501).json({ ok:false, error: "NOT_IMPLEMENTED" });
});
app.post("/api/order/close", async (req, res) => {
  return res.status(501).json({ ok:false, error: "NOT_IMPLEMENTED" });
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server started on", PORT));
