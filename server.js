import dotenv from "dotenv";
dotenv.config();
import express from "express";
import crypto from "crypto";
import cors from "cors";
import { Pool } from "pg";
import { validate } from '@telegram-apps/init-data-node';
import rateLimit from 'express-rate-limit';
import cron from "node-cron";

const app = express();

// Важно для корректного определения IP на Render/Heroku
app.set('trust proxy', 1);

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.static("public"));

// ======================== RATE LIMITING (ЗАЩИТА ОТ БОТОВ) ========================
// Ограничение: 100 запросов за 15 минут с одного IP
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, 
  max: 100, 
  standardHeaders: true, 
  legacyHeaders: false,
  message: { ok: false, error: "TOO_MANY_REQUESTS" }
});

// Применяем лимит ко всем API запросам
app.use('/api/', limiter);

// === 🛡️ СИСТЕМА ANTI-SLEEP (ВСТАВИТЬ ГДЕ УГОДНО ПОСЛЕ СОЗДАНИЯ app) 🛡️ ===
// Сюда вставь ссылку на твой ПЕРВЫЙ сервер (Price/Liquidation)
const PRICE_SERVER_URL = "https://tradingbot-backend-2yws.onrender.com"; // <-- ЗАМЕНИ НА СВОЙ URL

// Запускаем задачу каждые 10 минут
cron.schedule("*/10 * * * *", async () => {
    console.log("⏰ Anti-Sleep: Pinging Price Server...");
    try {
        // Пингуем endpoint /health первого сервера
        const response = await fetch(`${PRICE_SERVER_URL}/health`);
        if (response.ok) console.log("✅ Price Server is awake");
        else console.log("⚠️ Price Server responded with " + response.status);
    } catch (e) {
        console.error("❌ Anti-Sleep Error:", e.message);
    }
});

// ======================== КОНФИГУРАЦИЯ БД ========================
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
  ssl: true 
});

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
function checkTelegramAuthInitData(initData) {
  try {
    console.log("🔍 Validating initData with official @telegram-apps/init-data-node library...");
    validate(initData, process.env.BOT_TOKEN);
    console.log("✅ initData signature VALID (library confirmed)!");
    return true;
  } catch (err) {
    console.error("❌ initData validation FAILED:", err.message);
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

// ======================== HELPER: GET IP ========================
function getClientIp(req) {
  const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
  return ip ? ip.split(',')[0].trim() : ip;
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
        last_ip TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Миграция IP
    try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip TEXT`); } catch(e) {}

    // 2. Таблица Positions
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
        warning_sent BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Миграции для positions
    try { await db.query(`ALTER TABLE positions ADD COLUMN IF NOT EXISTS pair TEXT DEFAULT 'BTC-USD'`); } catch(e) {}
    try { await db.query(`ALTER TABLE positions ADD COLUMN IF NOT EXISTS warning_sent BOOLEAN DEFAULT FALSE`); } catch(e) {}

    // 3. Таблица trades_history
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
        commission NUMERIC DEFAULT 0,
        closed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Миграция для комиссии
    try { await db.query(`ALTER TABLE trades_history ADD COLUMN IF NOT EXISTS commission NUMERIC DEFAULT 0`); } catch(e) {}

    console.log("✅ DB tables ready!");
  } catch (err) {
    console.error("❌ Error recreating tables:", err.message);
  }
}
await initDB();

// ======================== UPSERT USER ========================
async function upsertUserFromObj(userObj, ipAddress) {
  const userId = String(userObj.id);
  console.log(`📝 Upserting user ${userId} (${userObj.first_name || "No name"}). IP: ${ipAddress}`);

  try {
    await db.query(`
      INSERT INTO users (user_id, first_name, username, photo_url, last_ip)
      VALUES ($1, $2, $3, $4, $5)
      ON CONFLICT (user_id) DO UPDATE SET
        first_name = EXCLUDED.first_name,
        username = EXCLUDED.username,
        photo_url = EXCLUDED.photo_url,
        last_ip = EXCLUDED.last_ip,
        updated_at = CURRENT_TIMESTAMP
    `, [userId, userObj.first_name || null, userObj.username || null, userObj.photo_url || null, ipAddress]);

    const res = await db.query(
      "SELECT user_id, first_name, username, photo_url, balance FROM users WHERE user_id = $1",
      [userId]
    );
    return res.rows[0];
  } catch (err) {
    console.error(`❌ Error saving user ${userId}:`, err.message);
    throw err;
  }
}

// ======================== ROUTES ========================

// Логирование запросов с IP
app.use((req, res, next) => {
  const ip = getClientIp(req);
  console.log(`\n📡 [${new Date().toISOString()}] ${req.method} ${req.path} [IP: ${ip}]`);
  if (req.body && Object.keys(req.body).length > 0) console.log("Body:", req.body);
  next();
});

app.get("/auth/telegram", async (req, res) => {
  res.json({msg: "Endpoint exists"});
});

app.post("/api/init", async (req, res) => {
  console.log("\n🚀 /api/init called!");
  const ip = getClientIp(req);

  try {
    const { initData } = req.body;
    let userRow;

    if (initData) {
      const sigValid = checkTelegramAuthInitData(initData);
      
      if (!sigValid && process.env.DEV_ALLOW_BYPASS !== "1") {
        console.log("❌ Signature invalid and no bypass — rejecting");
        return res.status(403).json({ ok: false, error: "INVALID_SIGNATURE" });
      }

      const params = new URLSearchParams(initData);
      params.delete("signature");
      const rawUser = params.get("user");
      if (!rawUser) return res.status(400).json({ ok: false, error: "NO_USER" });

      let userObj;
      try {
        userObj = JSON.parse(rawUser);
      } catch (e) {
        return res.status(400).json({ ok: false, error: "INVALID_USER_JSON" });
      }

      // Сохраняем юзера вместе с IP
      userRow = await upsertUserFromObj(userObj, ip);
    } else {
      // Cookie fallback
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

    const positionsRes = await db.query(
      "SELECT * FROM positions WHERE user_id = $1 ORDER BY created_at ASC",
      [userRow.user_id]
    );

    const cookieVal = makeSessionCookieValue(userRow.user_id);
    const isSecure = req.headers["x-forwarded-proto"] === "https" || req.protocol === "https";
    const cookieParts = [`${COOKIE_NAME}=${cookieVal}`, `Path=/`, `HttpOnly`, `SameSite=None`, `Secure`, `Max-Age=${60 * 60 * 24 * 30}`];
    if (isSecure) cookieParts.push("Secure");
    res.setHeader("Set-Cookie", cookieParts.join("; "));

    res.json({ ok: true, user: userRow, positions: positionsRes.rows });

  } catch (err) {
    console.error("💥 UNHANDLED ERROR in /api/init:", err);
    res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

app.get("/api/user/history", async (req, res) => {
  try {
    const cookieHeader = req.headers.cookie || "";
    const cookies = Object.fromEntries(cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2));
    let userId = verifySessionCookieValue(cookies[COOKIE_NAME]);
    
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

    await db.query(
      "UPDATE users SET balance = balance - $1 WHERE user_id = $2",
      [margin, user.user_id]
    );

    const posRes = await db.query(`
      INSERT INTO positions (user_id, pair, type, entry_price, margin, leverage, size)
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING *
    `, [user.user_id, pair, type, entryPrice, margin, leverage, size]);

    res.json({ ok: true, position: posRes.rows[0], newBalance: Number(user.balance) - margin });
  } catch (err) {
    console.error("Error opening position:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.post("/api/order/close", async (req, res) => {
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

    // 2. Расчёты
    const cPrice = Number(closePrice);
    const ePrice = Number(pos.entry_price);
    const pSize = Number(pos.size);
    const pMargin = Number(pos.margin);

    // 3. PnL
    const priceChangePct = (cPrice - ePrice) / ePrice;
    let pnl = priceChangePct * pSize;
    if (pos.type === "SHORT") pnl = -pnl;
    
    // 4. Комиссия (0.03%)
    const commission = pSize * 0.0003; 

    // 5. Итоговый возврат
    let totalReturn = pMargin + pnl - commission;

    // 6. Проверка на Ликвидацию
    let isLiquidated = false;
    if (totalReturn <= 0) {
        isLiquidated = true;
        totalReturn = 0; 
        pnl = -pMargin; // Фиксируем убыток равный марже
    }

    // 7. Транзакция
    await db.query("BEGIN"); 
    
    if (totalReturn > 0) {
        await db.query("UPDATE users SET balance = balance + $1 WHERE user_id = $2", [totalReturn, user.user_id]);
    }

    const finalCommission = isLiquidated ? 0 : commission;

    await db.query(`
      INSERT INTO trades_history (user_id, pair, type, entry_price, exit_price, size, leverage, pnl, commission)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
    `, [user.user_id, pos.pair || 'BTC-USD', pos.type, ePrice, cPrice, pSize, pos.leverage, pnl, finalCommission]);

    await db.query("DELETE FROM positions WHERE id = $1", [positionId]);

    await db.query("COMMIT"); 

    const newBalRes = await db.query("SELECT balance FROM users WHERE user_id = $1", [user.user_id]);
    
    console.log(`✅ ${isLiquidated ? 'LIQUIDATED' : 'CLOSED'} | PnL: ${pnl.toFixed(2)}`);

    res.json({
      ok: true,
      pnl: Number(pnl.toFixed(2)),
      commission: Number(finalCommission.toFixed(2)),
      liquidated: isLiquidated,
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
