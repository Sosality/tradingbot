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

// Проверка Telegram WebApp подписи (initData string)
function checkTelegramAuth(initData) {
  try {
    const url = new URLSearchParams(initData);
    const hash = url.get("hash");
    url.delete("hash");

    const dataCheckString = [...url.entries()]
      .sort()
      .map(([k, v]) => `${k}=${v}`)
      .join("\n");

    const secretKey = crypto
      .createHmac("sha256", "WebAppData")
      .update(process.env.BOT_TOKEN)
      .digest();

    const computed = crypto
      .createHmac("sha256", secretKey)
      .update(dataCheckString)
      .digest("hex");

    return computed === hash;
  } catch (err) {
    return false;
  }
}

// Инициализация таблиц (users, positions)
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

// API: init (при первом заходе сохраняем пользователя)
app.post("/api/init", async (req, res) => {
  try {
    const { initData } = req.body;
    if (!initData) return res.status(400).json({ error: "NO_INIT_DATA" });

    if (!checkTelegramAuth(initData)) return res.status(403).json({ error: "INVALID_SIGNATURE" });

    const params = new URLSearchParams(initData);
    const rawUser = params.get("user");
    if (!rawUser) return res.status(400).json({ error: "NO_USER" });

    const user = JSON.parse(rawUser);
    const userId = user.id.toString();

    // Insert user if not exists, update profile fields
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

    // Fetch user (with balance)
    const u = await db.query("SELECT user_id, first_name, username, photo_url, balance FROM users WHERE user_id=$1", [userId]);
    const userRow = u.rows[0];

    // Fetch open positions for user
    const positionsRes = await db.query("SELECT * FROM positions WHERE user_id=$1 ORDER BY created_at ASC", [userId]);

    return res.json({
      ok: true,
      user: userRow,
      positions: positionsRes.rows
    });
  } catch (err) {
    console.error("/api/init error:", err);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// Optional: endpoints to open/close positions (simple implementation)
app.post("/api/order/open", async (req, res) => {
  try {
    const { userId, type, margin, leverage, entryPrice } = req.body;
    if (!userId) return res.status(400).json({ error: "NO_USER" });

    // Basic checks
    const u = await db.query("SELECT balance FROM users WHERE user_id=$1", [userId]);
    if (!u.rows.length) return res.status(404).json({ error: "NO_USER" });

    const balance = Number(u.rows[0].balance);
    if (balance < Number(margin)) return res.status(400).json({ error: "LOW_BALANCE" });

    const fee = Number(margin) * Number(leverage) * 0.001;
    const newBalance = balance - Number(margin) - fee;

    await db.query("UPDATE users SET balance=$1, updated_at=NOW() WHERE user_id=$2", [newBalance, userId]);

    const size = Number(margin) * Number(leverage);
    const ins = await db.query(
      `INSERT INTO positions(user_id, type, entry_price, margin, leverage, size)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [userId, type, entryPrice, margin, leverage, size]
    );

    return res.json({ ok: true, position: ins.rows[0], balance: newBalance });
  } catch (err) {
    console.error("/api/order/open error:", err);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

app.post("/api/order/close", async (req, res) => {
  try {
    const { userId, positionId, exitPrice } = req.body;
    if (!userId || !positionId) return res.status(400).json({ error: "MISSING" });

    const posRes = await db.query("SELECT * FROM positions WHERE id=$1 AND user_id=$2", [positionId, userId]);
    if (!posRes.rows.length) return res.status(404).json({ error: "NOT_FOUND" });

    const pos = posRes.rows[0];

    let pnl = 0;
    if (pos.type === "LONG") {
      pnl = ((Number(exitPrice) - Number(pos.entry_price)) / Number(pos.entry_price)) * Number(pos.size);
    } else {
      pnl = ((Number(pos.entry_price) - Number(exitPrice)) / Number(pos.entry_price)) * Number(pos.size);
    }

    const userRes = await db.query("SELECT balance FROM users WHERE user_id=$1", [userId]);
    const newBalance = Number(userRes.rows[0].balance) + Number(pos.margin) + Number(pnl);

    await db.query("UPDATE users SET balance=$1, updated_at=NOW() WHERE user_id=$2", [newBalance, userId]);
    await db.query("DELETE FROM positions WHERE id=$1", [positionId]);

    return res.json({ ok: true, pnl, balance: newBalance });
  } catch (err) {
    console.error("/api/order/close error:", err);
    return res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// Health
app.get("/api/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server started on", PORT));
