// server.js
import dotenv from "dotenv";
dotenv.config();

import express from "express";
import crypto from "crypto";
import cors from "cors";
import { Pool } from "pg";

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static("public"));

if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL not set!");
  process.exit(1);
}

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// ---- Правильная проверка Telegram WebApp initData
function checkTelegramAuth(initData) {
  try {
    const url = new URLSearchParams(initData);
    const hash = url.get("hash");
    if (!hash) return false;
    url.delete("hash");

    // data_check_string: sorted entries -> "k=v\nk2=v2..."
    const dataCheckString = [...url.entries()]
      .sort()
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");

    // Секретный ключ — SHA256 от BOT_TOKEN (raw bytes)
    const secretKey = crypto.createHash("sha256").update(process.env.BOT_TOKEN || "").digest();

    // HMAC-SHA256 of dataCheckString using secretKey, hex
    const computed = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    return computed === hash;
  } catch (err) {
    console.error("checkTelegramAuth error:", err?.message || err);
    return false;
  }
}

// Инициализация таблиц
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

// --- /api/init
app.post("/api/init", async (req, res) => {
  try {
    const { initData } = req.body;
    console.log("POST /api/init called; initData present:", !!initData);

    if (!initData) {
      return res.status(400).json({ ok: false, error: "NO_INIT_DATA" });
    }

    const okSig = checkTelegramAuth(initData);
    console.log("Telegram signature valid:", okSig);

    if (!okSig) {
      // Для отладки можно включить DEV_ALLOW_BYPASS=1 (см. ниже), чтобы пропускать подпись
      if (process.env.DEV_ALLOW_BYPASS === "1") {
        console.warn("DEV_ALLOW_BYPASS active — accepting initData without valid signature");
      } else {
        return res.status(403).json({ ok: false, error: "INVALID_SIGNATURE" });
      }
    }

    const params = new URLSearchParams(initData);
    const rawUser = params.get("user");
    if (!rawUser) return res.status(400).json({ ok: false, error: "NO_USER" });

    const user = JSON.parse(rawUser);
    const userId = user.id.toString();

    console.log(`Creating/updating user ${userId} (${user.username || "no-username"})`);

    await db.query(
      `INSERT INTO users(user_id, first_name, username, photo_url)
       VALUES ($1,$2,$3,$4)
       ON CONFLICT (user_id) DO UPDATE
         SET first_name = EXCLUDED.first_name,
             username = EXCLUDED.username,
             photo_url = EXCLUDED.photo_url,
             updated_at = NOW()`,
      [userId, user.first_name || null, user.username || null, user.photo_url || null]
    );

    const u = await db.query("SELECT user_id, first_name, username, photo_url, balance FROM users WHERE user_id=$1", [userId]);
    const userRow = u.rows[0];

    const positionsRes = await db.query("SELECT * FROM positions WHERE user_id=$1 ORDER BY created_at ASC", [userId]);

    return res.json({
      ok: true,
      user: userRow,
      positions: positionsRes.rows
    });
  } catch (err) {
    console.error("/api/init error:", err);
    return res.status(500).json({ ok: false, error: "SERVER_ERROR" });
  }
});

// (остальные endpoints open/close можно оставить как у тебя)
app.post("/api/order/open", async (req, res) => { /* copy your implementation or keep earlier one */ });
app.post("/api/order/close", async (req, res) => { /* copy your implementation or keep earlier one */ });

app.get("/api/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server started on", PORT));
