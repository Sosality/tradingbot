import dotenv from "dotenv";
dotenv.config();
import express from "express";
import crypto from "crypto";
import cors from "cors";
import { Pool } from "pg";
// Используем библиотеку для проверки, как в оригинале
import { validate } from '@telegram-apps/init-data-node';

const app = express();

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.static("public"));

// ======================== КОНФИГУРАЦИЯ БД ========================
// Я вставил твою новую ссылку прямо сюда, чтобы заработало сразу.
// В идеале потом обнови переменную DATABASE_URL в настройках Render.
const CONNECTION_STRING = "postgresql://neondb_owner:npg_igxGcyUQmX52@ep-ancient-sky-a9db2z9z-pooler.gwc.azure.neon.tech/neondb?sslmode=require&channel_binding=require";

// ======================== ЛОГИРОВАНИЕ ENV ========================
console.log("=== ENV CHECK ===");
console.log("BOT_TOKEN set:", !!process.env.BOT_TOKEN); 
console.log("Using provided NeonDB connection string");
console.log("==================");

if (!process.env.BOT_TOKEN) {
  console.warn("⚠️  BOT_TOKEN not set! Signature verification will fail.");
}

// ======================== ПОДКЛЮЧЕНИЕ К БД ========================
const db = new Pool({
  connectionString: CONNECTION_STRING,
  ssl: true // Для NeonDB часто требуется явное указание, либо параметры в строке
});

// Тест подключения к БД при старте
db.connect()
  .then(client => {
    console.log("✅ Successfully connected to NeonDB (PostgreSQL)");
    client.release();
  })
  .catch(err => {
    console.error("❌ Failed to connect to database:", err.message);
    console.error("Full error:", err);
  });

// ======================== TELEGRAM AUTH HELPERS ========================
// Твоя оригинальная функция через библиотеку
function checkTelegramAuthInitData(initData) {
  try {
    console.log("🔍 Validating initData with official @telegram-apps/init-data-node library...");

    // Библиотека автоматически обрабатывает и hash, и signature
    validate(initData, process.env.BOT_TOKEN);

    console.log("✅ initData signature VALID (library confirmed)!");
    return true;
  } catch (err) {
    console.error("❌ initData validation FAILED:", err.message);
    if (err.message.includes("SIGN_INVALID")) {
      console.log("Possible causes: wrong BOT_TOKEN, outdated initData, or Telegram bug with signature");
    }
    return false;
  }
}

// ======================== COOKIE HELPERS ========================
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
  return mac === expected ? userId : false;
}

// ======================== INIT DB ========================
async function initDB() {
  try {
    console.log("🔄 Recreating/Checking DB tables...");

    // 1. Таблица Users
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

    // 2. Таблица Positions (с полем pair)
    await db.query(`
      CREATE TABLE IF NOT EXISTS positions (
        id BIGSERIAL PRIMARY KEY,
        user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
        pair TEXT NOT NULL DEFAULT 'BTC-USD',
        type TEXT NOT NULL,
        entry_price NUMERIC NOT NULL,
        margin NUMERIC NOT NULL,
        leverage INT NOT NULL,
        size NUMERIC NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Миграция: добавляем колонку pair, если её нет
    try {
        await db.query(`ALTER TABLE positions ADD COLUMN IF NOT EXISTS pair TEXT DEFAULT 'BTC-USD'`);
    } catch(e) { console.log("Migration check passed"); }

    // 3. Таблица trades_history (для истории сделок)
    await db.query(`
      CREATE TABLE IF NOT EXISTS trades_history (
        id BIGSERIAL PRIMARY KEY,
        user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
        pair TEXT NOT NULL,
        type TEXT NOT NULL,
        entry_price NUMERIC NOT NULL,
        exit_price NUMERIC NOT NULL,
        size NUMERIC NOT NULL,
        leverage INT NOT NULL,
        pnl NUMERIC NOT NULL,
        closed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    console.log("✅ DB tables ready!");
  } catch (err) {
    console.error("❌ Error recreating tables:", err.message);
    // Не выходим, пробуем работать дальше
  }
}
await initDB();

// ======================== UPSERT USER ========================
async function upsertUserFromObj(userObj) {
  const userId = String(userObj.id);
  console.log(`📝 Upserting user ${userId} (${userObj.first_name || "No name"} ${userObj.username ? `@${userObj.username}` : ""})`);

  try {
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
    console.log(`✅ User ${userId} saved. Balance: ${res.rows[0].balance}`);
    return res.rows[0];
  } catch (err) {
    console.error(`❌ Error saving user ${userId}:`, err.message);
    throw err;
  }
}

// ======================== ROUTES ========================

app.use((req, res, next) => {
  console.log(`\n📡 [${new Date().toISOString()}] ${req.method} ${req.path}`);
  if (req.body && Object.keys(req.body).length > 0) console.log("Body:", req.body);
  if (req.headers.cookie) console.log("Cookies present");
  next();
});

app.get("/auth/telegram", async (req, res) => {
  res.json({msg: "Endpoint exists"});
});

app.post("/api/init", async (req, res) => {
  console.log("\n🚀 /api/init called!");

  try {
    const { initData } = req.body;
    let userRow;

    if (initData) {
      console.log(`initData received (length: ${initData.length})`);
      
      // === ПРОВЕРКА ЧЕРЕЗ БИБЛИОТЕКУ ===
      const sigValid = checkTelegramAuthInitData(initData);
      
      if (!sigValid && process.env.DEV_ALLOW_BYPASS !== "1") {
        console.log("❌ Signature invalid and no bypass — rejecting");
        return res.status(403).json({ ok: false, error: "INVALID_SIGNATURE" });
      }

      const params = new URLSearchParams(initData);
      params.delete("signature");
      const rawUser = params.get("user");
      if (!rawUser) {
        return res.status(400).json({ ok: false, error: "NO_USER" });
      }

      let userObj;
      try {
        userObj = JSON.parse(rawUser);
      } catch (e) {
        return res.status(400).json({ ok: false, error: "INVALID_USER_JSON" });
      }

      userRow = await upsertUserFromObj(userObj);
    } else {
      // Cookie fallback
      const cookieHeader = req.headers.cookie || "";
      console.log("Trying cookie auth...");
      const cookies = Object.fromEntries(
        cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2)
      );
      const sessionVal = cookies[COOKIE_NAME];
      const userId = verifySessionCookieValue(sessionVal);
      
      if (!userId) {
        console.log("❌ Invalid/missing cookie");
        return res.status(401).json({ ok: false, error: "NO_SESSION" });
      }

      const ures = await db.query(
        "SELECT user_id, first_name, username, photo_url, balance FROM users WHERE user_id = $1",
        [userId]
      );
      if (!ures.rows.length) return res.status(404).json({ ok: false, error: "NO_USER" });
      
      userRow = ures.rows[0];
      console.log(`✅ Authenticated via cookie: user ${userId}`);
    }

    // Загружаем позиции
    const positionsRes = await db.query(
      "SELECT * FROM positions WHERE user_id = $1 ORDER BY created_at ASC",
      [userRow.user_id]
    );

    // Устанавливаем куки
    const cookieVal = makeSessionCookieValue(userRow.user_id);
    const isSecure = req.headers["x-forwarded-proto"] === "https" || req.protocol === "https";
    const cookieParts = [
      `${COOKIE_NAME}=${cookieVal}`,
      `Path=/`,
      `HttpOnly`,
      `SameSite=None`,
      `Secure`,
      `Max-Age=${60 * 60 * 24 * 30}`
    ];
    if (isSecure) cookieParts.push("Secure");
    res.setHeader("Set-Cookie", cookieParts.join("; "));

    res.json({ ok: true, user: userRow, positions: positionsRes.rows });

  } catch (err) {
    console.error("💥 UNHANDLED ERROR in /api/init:", err);
    res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

// === РОУТ ИСТОРИИ ===
app.get("/api/user/history", async (req, res) => {
  try {
    const cookieHeader = req.headers.cookie || "";
    const cookies = Object.fromEntries(cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2));
    let userId = verifySessionCookieValue(cookies[COOKIE_NAME]);
    
    // Fallback для тестов
    if (!userId && req.query.userId) userId = String(req.query.userId);

    if (!userId) return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });

    const historyRes = await db.query(
      "SELECT * FROM trades_history WHERE user_id = $1 ORDER BY closed_at DESC LIMIT 50",
      [userId]
    );

    res.json({ ok: true, history: historyRes.rows });
  } catch (err) {
    console.error("Error fetching history:", err);
    res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

// ======================== ORDER ENDPOINTS ========================

async function getAuthenticatedUser(req) {
  let userId;
  if (req.body && req.body.userId) {
    userId = String(req.body.userId);
  } else {
    const cookieHeader = req.headers.cookie || "";
    const cookies = Object.fromEntries(
      cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2)
    );
    const sessionVal = cookies[COOKIE_NAME];
    userId = verifySessionCookieValue(sessionVal);
  }

  if (!userId) throw new Error("NO_SESSION");

  const res = await db.query("SELECT user_id, balance FROM users WHERE user_id = $1", [userId]);
  if (!res.rows.length) throw new Error("NO_USER");

  return res.rows[0];
}

app.post("/api/order/open", async (req, res) => {
  console.log("/api/order/open called:", req.body);
  try {
    const user = await getAuthenticatedUser(req);
    const { pair, type, size, leverage, entryPrice } = req.body; 

    if (!pair || !type || !size || !leverage || !entryPrice) {
      return res.status(400).json({ ok: false, error: "MISSING_FIELDS" });
    }

    const margin = Number(size) / Number(leverage);
    if (margin > Number(user.balance)) {
      return res.status(400).json({ ok: false, error: "INSUFFICIENT_BALANCE" });
    }

    // Замораживаем маржу
    await db.query(
      "UPDATE users SET balance = balance - $1 WHERE user_id = $2",
      [margin, user.user_id]
    );

    // Сохраняем позицию (ВАЖНО: pair)
    const posRes = await db.query(`
      INSERT INTO positions (user_id, pair, type, entry_price, margin, leverage, size)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `, [user.user_id, pair, type, entryPrice, margin, leverage, size]);

    console.log(`✅ Position opened: ${type} ${pair}`);
    res.json({ ok: true, position: posRes.rows[0], newBalance: Number(user.balance) - margin });
  } catch (err) {
    console.error("Error opening position:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/order/close", async (req, res) => {
  console.log("📡 /api/order/close called:", req.body);
  try {
    const user = await getAuthenticatedUser(req);
    const { positionId, closePrice } = req.body;

    if (!positionId || !closePrice) return res.status(400).json({ ok: false, error: "MISSING_FIELDS" });

    // 1. Получаем позицию
    const posRes = await db.query(
      "SELECT * FROM positions WHERE id = $1 AND user_id = $2",
      [positionId, user.user_id]
    );

    if (!posRes.rows.length) return res.status(404).json({ ok: false, error: "POSITION_NOT_FOUND" });
    const pos = posRes.rows[0];

    // 2. Расчёт
    const cPrice = Number(closePrice);
    const ePrice = Number(pos.entry_price);
    const pSize = Number(pos.size);
    const pMargin = Number(pos.margin);

    const priceChangePct = (cPrice - ePrice) / ePrice;
    let pnl = priceChangePct * pSize;
    if (pos.type === "SHORT") pnl = -pnl;
    
    if (pnl < -pMargin) pnl = -pMargin;
    const totalReturn = pMargin + pnl;

    // 3. Транзакция
    await db.query("BEGIN"); 
    
    await db.query("UPDATE users SET balance = balance + $1 WHERE user_id = $2", [totalReturn, user.user_id]);

    // ЗАПИСЬ В ИСТОРИЮ
    await db.query(`
      INSERT INTO trades_history (user_id, pair, type, entry_price, exit_price, size, leverage, pnl)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [user.user_id, pos.pair || 'BTC-USD', pos.type, ePrice, cPrice, pSize, pos.leverage, pnl]);

    await db.query("DELETE FROM positions WHERE id = $1", [positionId]);

    await db.query("COMMIT"); 

    const newBalRes = await db.query("SELECT balance FROM users WHERE user_id = $1", [user.user_id]);
    
    res.json({
      ok: true,
      pnl: Number(pnl.toFixed(2)),
      newBalance: Number(newBalRes.rows[0].balance)
    });

  } catch (err) {
    await db.query("ROLLBACK");
    console.error("❌ Ошибка закрытия позиции:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
