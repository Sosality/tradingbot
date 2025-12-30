import dotenv from "dotenv";
dotenv.config();
import express from "express";
import crypto from "crypto";
import cors from "cors";
import { Pool } from "pg";
// Убрали импорт @telegram-apps/init-data-node, так как он мог вызывать ошибки

const app = express();

app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(express.static("public"));

// ======================== ЛОГИРОВАНИЕ ENV ========================
console.log("=== ENV CHECK ===");
console.log("BOT_TOKEN set:", !!process.env.BOT_TOKEN);
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

db.connect()
  .then(client => {
    console.log("✅ Successfully connected to PostgreSQL database");
    client.release();
  })
  .catch(err => {
    console.error("❌ Failed to connect to database:", err.message);
  });

// ======================== TELEGRAM AUTH (MANUAL FIX) ========================
// Мы вернули ручную проверку, так как она надежнее работает без внешних зависимостей
function checkTelegramAuthInitData(initData) {
  if (!process.env.BOT_TOKEN) return false;

  const urlParams = new URLSearchParams(initData);
  const hash = urlParams.get("hash");
  if (!hash) return false;

  urlParams.delete("hash");
  
  const dataToCheck = [...urlParams.entries()]
    .map(([key, value]) => key + "=" + value)
    .sort()
    .join("\n");

  const secretKey = crypto.createHmac("sha256", "WebAppData").update(process.env.BOT_TOKEN).digest();
  const calculatedHash = crypto.createHmac("sha256", secretKey).update(dataToCheck).digest("hex");

  const valid = calculatedHash === hash;
  if(valid) {
    console.log("✅ Signature verified successfully (manual crypto)");
  } else {
    console.log("❌ Signature verification failed. Calculated:", calculatedHash, "Received:", hash);
  }
  return valid;
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
    console.log("🔄 Checking/Creating DB tables...");

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
        pair TEXT NOT NULL DEFAULT 'BTC-USD',
        type TEXT NOT NULL,
        entry_price NUMERIC NOT NULL,
        margin NUMERIC NOT NULL,
        leverage INT NOT NULL,
        size NUMERIC NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);
    
    // Миграция
    try {
        await db.query(`ALTER TABLE positions ADD COLUMN IF NOT EXISTS pair TEXT DEFAULT 'BTC-USD'`);
    } catch(e) { console.log("Migration check passed"); }

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
  }
}
await initDB();

// ======================== UPSERT USER ========================
async function upsertUserFromObj(userObj) {
  const userId = String(userObj.id);
  console.log(`📝 Upserting user ${userId} (${userObj.first_name || "No name"})`);

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
    return res.rows[0];
  } catch (err) {
    console.error(`❌ Error saving user ${userId}:`, err.message);
    throw err;
  }
}

// ======================== AUTH HELPERS ========================
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

// ======================== ROUTES ========================

app.use((req, res, next) => {
  console.log(`\n📡 [${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

app.post("/api/init", async (req, res) => {
  try {
    const { initData } = req.body;
    let userRow;

    if (initData) {
      // Manual Check
      const sigValid = checkTelegramAuthInitData(initData);
      if (!sigValid && process.env.DEV_ALLOW_BYPASS !== "1") {
        return res.status(403).json({ ok: false, error: "INVALID_SIGNATURE" });
      }
      
      // Parse User
      const params = new URLSearchParams(initData);
      const userObj = JSON.parse(params.get("user"));
      userRow = await upsertUserFromObj(userObj);
      
    } else {
      // Cookie Fallback
      const cookieHeader = req.headers.cookie || "";
      const cookies = Object.fromEntries(
        cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2)
      );
      const userId = verifySessionCookieValue(cookies[COOKIE_NAME]);
      if (!userId) return res.status(401).json({ ok: false, error: "NO_SESSION" });
      
      const ures = await db.query("SELECT * FROM users WHERE user_id = $1", [userId]);
      if (!ures.rows.length) return res.status(404).json({ ok: false, error: "NO_USER" });
      userRow = ures.rows[0];
    }

    const positionsRes = await db.query(
      "SELECT * FROM positions WHERE user_id = $1 ORDER BY created_at ASC",
      [userRow.user_id]
    );

    const cookieVal = makeSessionCookieValue(userRow.user_id);
    res.setHeader("Set-Cookie", `${COOKIE_NAME}=${cookieVal}; Path=/; HttpOnly; SameSite=None; Secure; Max-Age=${60 * 60 * 24 * 30}`);

    res.json({ ok: true, user: userRow, positions: positionsRes.rows });
  } catch (err) {
    console.error("Error in /api/init:", err);
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

    await db.query("UPDATE users SET balance = balance - $1 WHERE user_id = $2", [margin, user.user_id]);

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

    const posRes = await db.query("SELECT * FROM positions WHERE id = $1 AND user_id = $2", [positionId, user.user_id]);
    if (!posRes.rows.length) return res.status(404).json({ ok: false, error: "POSITION_NOT_FOUND" });
    const pos = posRes.rows[0];

    const cPrice = Number(closePrice);
    const ePrice = Number(pos.entry_price);
    const pSize = Number(pos.size);
    const pMargin = Number(pos.margin);

    const priceChangePct = (cPrice - ePrice) / ePrice;
    let pnl = priceChangePct * pSize;
    if (pos.type === "SHORT") pnl = -pnl;
    
    if (pnl < -pMargin) pnl = -pMargin;

    const totalReturn = pMargin + pnl;

    await db.query("BEGIN");
    
    await db.query("UPDATE users SET balance = balance + $1 WHERE user_id = $2", [totalReturn, user.user_id]);

    await db.query(`
      INSERT INTO trades_history (user_id, pair, type, entry_price, exit_price, size, leverage, pnl)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
    `, [user.user_id, pos.pair || 'BTC-USD', pos.type, ePrice, cPrice, pSize, pos.leverage, pnl]);

    await db.query("DELETE FROM positions WHERE id = $1", [positionId]);
    await db.query("COMMIT");

    const newBalRes = await db.query("SELECT balance FROM users WHERE user_id = $1", [user.user_id]);
    
    res.json({ ok: true, pnl: Number(pnl.toFixed(2)), newBalance: Number(newBalRes.rows[0].balance) });

  } catch (err) {
    await db.query("ROLLBACK");
    console.error("❌ Error closing position:", err.message);
    res.status(500).json({ ok: false, error: err.message });
  }
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
