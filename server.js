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

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

// === Telegram подпись ===
function checkTelegramAuth(initData) {
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
}

// === Инициализация DB ===
await db.query(`
  CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    balance NUMERIC DEFAULT 0,
    updated_at TIMESTAMP DEFAULT NOW()
  );
`);

// === API: INIT SESSION ===
app.post("/api/init", async (req, res) => {
  console.log("🔵 /api/init вызван, тело запроса:", req.body);

  const { initData } = req.body;

  if (!initData) return res.json({ error: "NO_INIT_DATA" });

  if (!checkTelegramAuth(initData))
    return res.json({ error: "INVALID_SIGNATURE" });

  const parsed = new URLSearchParams(initData);
  const rawUser = parsed.get("user");
  const user = JSON.parse(rawUser);
  const userId = user.id.toString();

  // Создаём пользователя, если нет
  await db.query(
    "INSERT INTO users(user_id) VALUES($1) ON CONFLICT (user_id) DO NOTHING",
    [userId]
  );

  const userRow = await db.query(
    "SELECT * FROM users WHERE user_id=$1",
    [userId]
  );

  res.json({
    ok: true,
    user: userRow.rows[0]
  });
});

// === RUN ===
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("Server started on", PORT));
