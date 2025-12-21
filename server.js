import dotenv from "dotenv";
dotenv.config();
import express from "express";
import crypto from "crypto";
import cors from "cors";
import { Pool } from "pg";
import { validate } from '@telegram-apps/init-data-node';

const app = express();

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.static("public"));

// ======================== ЛОГИРОВАНИЕ ENV ========================
console.log("=== ENV CHECK ===");
console.log("BOT_TOKEN set:", !!process.env.BOT_TOKEN); // не показываем сам токен
console.log("DATABASE_URL set:", !!process.env.DATABASE_URL);
console.log("DEV_ALLOW_BYPASS:", process.env.DEV_ALLOW_BYPASS || "not set");
console.log("==================");

if (!process.env.BOT_TOKEN) {
  console.warn("⚠️  BOT_TOKEN not set! Signature verification will fail.");
}
if (!process.env.DATABASE_URL) {
  console.error("❌ DATABASE_URL not set! Server will crash.");
  process.exit(1);
}

// ======================== ПОДКЛЮЧЕНИЕ К БД ========================
const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// Тест подключения к БД при старте
db.connect()
  .then(client => {
    console.log("✅ Successfully connected to PostgreSQL database");
    client.release();
  })
  .catch(err => {
    console.error("❌ Failed to connect to database:", err.message);
    console.error("Full error:", err);
  });

// ======================== TELEGRAM AUTH HELPERS ========================
// ПРАВИЛЬНЫЙ secret key для Mini Apps (bot-token method)
function telegramSecretKey(botToken) {
  if (!botToken) return Buffer.from("");
  return crypto.createHmac("sha256", "WebAppData")
               .update(botToken)
               .digest(); // binary digest
}

function checkTelegramAuthInitData(initData) {
  try {
    console.log("🔍 Validating initData with official @telegram-apps/init-data-node library...");

    // Библиотека автоматически обрабатывает и hash, и signature (с padding!), и выбирает правильный метод
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
    console.log("🔄 Recreating DB tables...");

    // Создаём заново
    await db.query(`
      CREATE TABLE users (
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
      CREATE TABLE positions (
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

    console.log("✅ DB tables recreated successfully!");
  } catch (err) {
    console.error("❌ Error recreating tables:", err.message);
    console.error(err.stack);
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
    console.log(`✅ User ${userId} successfully saved/updated. Balance: ${res.rows[0].balance}`);
    return res.rows[0];
  } catch (err) {
    console.error(`❌ Error saving user ${userId} to DB:`, err.message);
    throw err;
  }
}

// ======================== ROUTES ========================

// Простой лог всех входящих запросов
app.use((req, res, next) => {
  console.log(`\n📡 [${new Date().toISOString()}] ${req.method} ${req.path}`);
  if (req.body && Object.keys(req.body).length > 0) {
    console.log("Body:", req.body);
  }
  if (req.headers.cookie) {
    console.log("Cookies:", req.headers.cookie);
  }
  next();
});

app.get("/auth/telegram", async (req, res) => {
  console.log("/auth/telegram called with query:", req.query);
  // ... (оставляем как есть, но добавь логи если нужно)
  // твой код без изменений
});

app.post("/api/init", async (req, res) => {
  console.log("\n🚀 /api/init called!");

  try {
    const { initData } = req.body;

    if (!initData) {
      console.log("⚠️ No initData in body — trying cookie fallback");
    } else {
      console.log(`initData received (length: ${initData.length})`);
      console.log("First 200 chars:", initData.substring(0, 200));
    }

    let userRow;

    if (initData) {
      const sigValid = checkTelegramAuthInitData(initData);
      if (!sigValid && process.env.DEV_ALLOW_BYPASS !== "1") {
        console.log("❌ Signature invalid and no bypass — rejecting");
        return res.status(403).json({ ok: false, error: "INVALID_SIGNATURE" });
      }
      if (!sigValid) console.log("⚠️ Signature invalid but DEV_ALLOW_BYPASS enabled");

      const params = new URLSearchParams(initData);
      params.delete("signature");
      const rawUser = params.get("user");
      if (!rawUser) {
        console.log("❌ No 'user' field in initData");
        return res.status(400).json({ ok: false, error: "NO_USER" });
      }

      let userObj;
      try {
        userObj = JSON.parse(rawUser);
        console.log(`👤 Parsed user: ID=${userObj.id}, name=${userObj.first_name}, username=${userObj.username || "none"}`);
      } catch (e) {
        console.log("❌ Failed to parse user JSON");
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
      console.log("Session cookie found:", !!sessionVal);

      const userId = verifySessionCookieValue(sessionVal);
      if (!userId) {
        console.log("❌ Invalid or missing session cookie");
        return res.status(401).json({ ok: false, error: "NO_SESSION" });
      }

      const ures = await db.query(
        "SELECT user_id, first_name, username, photo_url, balance FROM users WHERE user_id = $1",
        [userId]
      );
      if (!ures.rows.length) {
        console.log("❌ User not found by cookie ID");
        return res.status(404).json({ ok: false, error: "NO_USER" });
      }
      userRow = ures.rows[0];
      console.log(`✅ Authenticated via cookie: user ${userId}`);
    }

    // Загружаем позиции
    const positionsRes = await db.query(
      "SELECT * FROM positions WHERE user_id = $1 ORDER BY created_at ASC",
      [userRow.user_id]
    );
    console.log(`📊 Loaded ${positionsRes.rows.length} positions`);

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

    console.log(`✅ /api/init success for user ${userRow.user_id}`);
    res.json({ ok: true, user: userRow, positions: positionsRes.rows });

  } catch (err) {
    console.error("💥 UNHANDLED ERROR in /api/init:", err);
    console.error(err.stack);
    res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

// ======================== ORDER ENDPOINTS ========================

// Получаем user_id из сессии (куки) — общая функция
async function getAuthenticatedUser(req) {
  let userId;

  // Приоритет 1: userId из тела запроса (надёжно из Mini App)
  if (req.body && req.body.userId) {
    userId = String(req.body.userId);
    console.log(`Authenticated via userId from body: ${userId}`);
  } else {
    // Приоритет 2: fallback на куки (для браузера вне Telegram)
    const cookieHeader = req.headers.cookie || "";
    const cookies = Object.fromEntries(
      cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2)
    );
    const sessionVal = cookies[COOKIE_NAME];
    userId = verifySessionCookieValue(sessionVal);
    if (userId) {
      console.log(`Authenticated via cookie: ${userId}`);
    }
  }

  if (!userId) throw new Error("NO_SESSION");

  const res = await db.query(
    "SELECT user_id, balance FROM users WHERE user_id = $1",
    [userId]
  );
  if (!res.rows.length) throw new Error("NO_USER");

  return res.rows[0];
}

app.post("/api/order/open", async (req, res) => {
  console.log("/api/order/open called:", req.body);
  try {
    const user = await getAuthenticatedUser(req);
    const { pair, type, size, leverage, entryPrice } = req.body; // type: "LONG" или "SHORT"

    if (!pair || !type || !size || !leverage || !entryPrice) {
      return res.status(400).json({ ok: false, error: "MISSING_FIELDS" });
    }

    const margin = Number(size) / Number(leverage);
    if (margin > Number(user.balance)) {
      return res.status(400).json({ ok: false, error: "INSUFFICIENT_BALANCE", required: margin, available: user.balance });
    }

    // Замораживаем маржу
    await db.query(
      "UPDATE users SET balance = balance - $1 WHERE user_id = $2",
      [margin, user.user_id]
    );

    // Сохраняем позицию
    const posRes = await db.query(`
      INSERT INTO positions (user_id, type, entry_price, margin, leverage, size)
      VALUES ($1, $2, $3, $4, $5, $6)
      RETURNING *
    `, [user.user_id, type, entryPrice, margin, leverage, size]);

    console.log(`✅ Position opened: ${type} ${pair} size=${size} leverage=${leverage} margin=${margin}`);

    res.json({ ok: true, position: posRes.rows[0], newBalance: Number(user.balance) - margin });
  } catch (err) {
    console.error("Error opening position:", err.message);
    res.status(500).json({ ok: false, error: err.message || "SERVER_ERROR" });
  }
});

app.post("/api/order/close", async (req, res) => {
  console.log("📡 /api/order/close called:", req.body);
  try {
    const user = await getAuthenticatedUser(req);
    const { positionId, closePrice } = req.body;

    if (!positionId || !closePrice) {
      return res.status(400).json({ ok: false, error: "MISSING_FIELDS" });
    }

    // 1. Получаем позицию из базы
    const posRes = await db.query(
      "SELECT * FROM positions WHERE id = $1 AND user_id = $2",
      [positionId, user.user_id]
    );

    if (!posRes.rows.length) {
      return res.status(404).json({ ok: false, error: "POSITION_NOT_FOUND" });
    }

    const pos = posRes.rows[0];

    // 2. Приводим все данные к числам (PostgreSQL возвращает Numeric как String)
    const cPrice = Number(closePrice);
    const ePrice = Number(pos.entry_price);
    const pSize = Number(pos.size);
    const pMargin = Number(pos.margin);

    // 3. Расчёт процентного изменения цены (ROE)
    // Формула: (Текущая - Вход) / Вход
    const priceChangePct = (cPrice - ePrice) / ePrice;

    // 4. Расчёт PnL (процент изменения * объем всей позиции)
    let pnl = priceChangePct * pSize;

    // Если это SHORT, инвертируем PnL (прибыль при падении)
    if (pos.type === "SHORT") {
      pnl = -pnl;
    }

    // 5. Защита от "ухода в долг" (Ликвидация)
    // Максимальный убыток не может превышать вложенную маржу
    if (pnl < -pMargin) {
      pnl = -pMargin;
    }

    // 6. Считаем итоговый возврат средств на баланс (Маржа + Прибыль/Убыток)
    const totalReturn = pMargin + pnl;

    // 7. Обновляем баланс пользователя и удаляем позицию в одной транзакции
    await db.query("BEGIN"); // Начинаем транзакцию для надежности
    
    await db.query(
      "UPDATE users SET balance = balance + $1 WHERE user_id = $2",
      [totalReturn, user.user_id]
    );

    await db.query("DELETE FROM positions WHERE id = $1", [positionId]);

    await db.query("COMMIT"); // Сохраняем изменения

    // 8. Получаем актуальный баланс для ответа
    const newBalRes = await db.query("SELECT balance FROM users WHERE user_id = $1", [user.user_id]);
    const finalBalance = Number(newBalRes.rows[0].balance);

    console.log(`✅ Позиция закрыта! 
      Тип: ${pos.type}, 
      PnL: ${pnl.toFixed(2)} VP, 
      Вернулось на баланс: ${totalReturn.toFixed(2)} VP`);

    res.json({
      ok: true,
      pnl: Number(pnl.toFixed(2)),
      newBalance: finalBalance
    });

  } catch (err) {
    await db.query("ROLLBACK"); // Откатываем изменения при ошибке
    console.error("❌ Ошибка закрытия позиции:", err.message);
    res.status(500).json({ ok: false, error: err.message || "SERVER_ERROR" });
  }
});
app.get("/api/health", (req, res) => {
  console.log("/api/health check");
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`Health check: https://your-service.onrender.com/api/health`);
});
