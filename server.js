import dotenv from "dotenv";
dotenv.config();
import express from "express";
import crypto from "crypto";
import cors from "cors";
import { Pool } from "pg";

const app = express();

app.use(cors({
  origin: true,                  // или укажи свой домен, например "https://твой-домен.onrender.com"
  credentials: true
}));
app.use(express.json());
app.use(express.static("public"));

// Проверки env
if (!process.env.BOT_TOKEN) {
  console.warn("BOT_TOKEN not set! Telegram signature verification will fail.");
}
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL not set! Server will crash.");
  process.exit(1);
}

// Создаём пул БД ВНЕ условий
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Helper: secret key по документации Telegram
function telegramSecretKey() {
  return crypto.createHash("sha256").update(process.env.BOT_TOKEN || "").digest();
}

// Проверка initData (WebApp)
function checkTelegramAuthInitData(initData) {
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash) return false;
    params.delete("hash");

    // Правильная сортировка по ключу
    const dataCheckString = Array.from(params.entries())
      .sort(([a], [b]) => a.localeCompare(b))
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");

    const secretKey = telegramSecretKey();
    const computed = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
    return computed === hash;
  } catch (e) {
    console.error("checkTelegramAuthInitData err", e);
    return false;
  }
}

// Проверка query-параметров (Login Widget)
function checkTelegramAuthParams(paramsObj) {
  try {
    const copy = { ...paramsObj };
    const hash = copy.hash;
    if (!hash) return false;
    delete copy.hash;
    delete copy.redirect;

    const dataCheckString = Object.keys(copy)
      .sort()
      .map(k => `${k}=${copy[k]}`)
      .join("\n");

    const secretKey = telegramSecretKey();
    const computed = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");
    return computed === hash;
  } catch (e) {
    console.error("checkTelegramAuthParams err", e);
    return false;
  }
}

// Session cookie
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
  const secret = process.env.COOKIE_SECRET || process.env.BOT_TOKEN || "fallback_secret";
  const expected = crypto.createHmac("sha256", secret).update(String(userId)).digest("hex");
  return mac === expected ? Number(userId) || userId : false; // возвращаем как есть
}

// Инициализация БД
async function initDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      first_name TEXT,
      username TEXT,
      photo_url TEXT,
      balance NUMERIC NOT NULL DEFAULT 1000,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
      updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
  console.log("DB tables ensured");
}
await initDB();

// Upsert пользователя
async function upsertUserFromObj(userObj) {
  const userId = String(userObj.id);
  await db.query(`
    INSERT INTO users (user_id, first_name, username, photo_url)
    VALUES ($1, $2, $3, $4)
    ON CONFLICT (user_id) DO UPDATE SET
      first_name = EXCLUDED.first_name,
      username = EXCLUDED.username,
      photo_url = EXCLUDED.photo_url,
      updated_at = CURRENT_TIMESTAMP
  `, [userId, userObj.first_name || null, userObj.username || null, userObj.photo_url || null]);

  const res = await db.query(
    "SELECT user_id, first_name, username, photo_url, balance FROM users WHERE user_id = $1",
    [userId]
  );
  return res.rows[0];
}

// /auth/telegram — для Login Widget (не обязателен для Mini App, но оставляем)
app.get("/auth/telegram", async (req, res) => {
  try {
    const params = req.query;
    const redirectTo = params.redirect || "/";
    if (!checkTelegramAuthParams(params)) {
      return res.status(403).send("Invalid Telegram signature");
    }

    const user = {
      id: params.id,
      first_name: params.first_name,
      username: params.username,
      photo_url: params.photo_url
    };

    const userRow = await upsertUserFromObj(user);
    const cookieVal = makeSessionCookieValue(userRow.user_id);

    const isSecure = req.headers["x-forwarded-proto"] === "https" || req.protocol === "https";
    const cookieParts = [
      `${COOKIE_NAME}=${cookieVal}`,
      `Path=/`,
      `HttpOnly`,
      `SameSite=None`,
      `Max-Age=${60 * 60 * 24 * 30}`
    ];
    if (isSecure) cookieParts.push("Secure");

    res.setHeader("Set-Cookie", cookieParts.join("; "));
    res.redirect(redirectTo);
  } catch (err) {
    console.error("/auth/telegram error", err);
    res.status(500).send("Server error");
  }
});

// Основной эндпоинт для Mini App
app.post("/api/init", async (req, res) => {
  try {
    const { initData } = req.body;

    let userRow;

    if (initData) {
      // Проверка подписи
      if (!checkTelegramAuthInitData(initData) && process.env.DEV_ALLOW_BYPASS !== "1") {
        return res.status(403).json({ ok: false, error: "INVALID_SIGNATURE" });
      }

      const params = new URLSearchParams(initData);
      const rawUser = params.get("user");
      if (!rawUser) return res.status(400).json({ ok: false, error: "NO_USER" });

      const userObj = JSON.parse(rawUser);
      userRow = await upsertUserFromObj(userObj);
    } else {
      // Fallback на куки
      const cookieHeader = req.headers.cookie || "";
      const cookies = Object.fromEntries(
        cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2)
      );
      const sessionVal = cookies[COOKIE_NAME];
      const userId = verifySessionCookieValue(sessionVal);

      if (!userId) return res.status(401).json({ ok: false, error: "NO_SESSION" });

      const ures = await db.query(
        "SELECT user_id, first_name, username, photo_url, balance FROM users WHERE user_id = $1",
        [userId]
      );
      if (!ures.rows.length) return res.status(404).json({ ok: false, error: "NO_USER" });
      userRow = ures.rows[0];
    }

    // Загружаем позиции
    const positionsRes = await db.query(
      "SELECT * FROM positions WHERE user_id = $1 ORDER BY created_at ASC",
      [userRow.user_id]
    );

    // Устанавливаем куки (на всякий случай, даже если пришёл initData)
    const cookieVal = makeSessionCookieValue(userRow.user_id);
    const isSecure = req.headers["x-forwarded-proto"] === "https" || req.protocol === "https";
    const cookieParts = [
      `${COOKIE_NAME}=${cookieVal}`,
      `Path=/`,
      `HttpOnly`,
      `SameSite=Lax`,
      `Max-Age=${60 * 60 * 24 * 30}`
    ];
    if (isSecure) cookieParts.push("Secure");
    res.setHeader("Set-Cookie", cookieParts.join("; "));

    res.json({ ok: true, user: userRow, positions: positionsRes.rows });
  } catch (err) {
    console.error("/api/init error:", err);
    res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

// Заглушки для ордеров (реализуешь позже)
app.post("/api/order/open", async (req, res) => {
  res.status(501).json({ ok: false, error: "NOT_IMPLEMENTED" });
});

app.post("/api/order/close", async (req, res) => {
  res.status(501).json({ ok: false, error: "NOT_IMPLEMENTED" });
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
