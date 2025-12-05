import express from "express";
import pg from "pg";
import dotenv from "dotenv";
import crypto from "crypto";

dotenv.config();

const app = express();
app.use(express.json());
app.use(express.static("public"));

// =========================
// 🔥 PostgreSQL
// =========================
const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// =========================
// 🔥 Проверка подписи Telegram
// =========================
function validateTelegramData(initData, botToken) {
    const params = new URLSearchParams(initData);

    const hash = params.get("hash");
    params.delete("hash");

    const dataCheckString = [...params.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(e => `${e[0]}=${e[1]}`)
        .join("\n");

    const secretKey = crypto
        .createHmac("sha256", "WebAppData")
        .update(botToken)
        .digest();

    const calculatedHash = crypto
        .createHmac("sha256", secretKey)
        .update(dataCheckString)
        .digest("hex");

    if (calculatedHash !== hash) {
        throw new Error("Invalid Telegram hash");
    }

    const userObj = params.get("user");
    return JSON.parse(userObj);
}

// =========================
// 🔥 API INIT
// =========================
app.post("/api/init", async (req, res) => {
    console.log("🔵 /api/init вызван, тело запроса:", req.body);

    const { initData } = req.body;

    if (!initData) {
        return res.status(400).json({ error: "NO_INIT_DATA" });
    }

    let tgUser;
    try {
        tgUser = validateTelegramData(initData, process.env.BOT_TOKEN);
        console.log("🟢 Telegram авторизация валидна:", tgUser);
    } catch (err) {
        console.log("🔴 Ошибка подписи:", err.message);
        return res.status(401).json({ error: "INVALID_SIGNATURE", details: err.message });
    }

    const userId = tgUser.id.toString();
    console.log("🟣 userId:", userId);

    try {
        const result = await pool.query(`
            INSERT INTO users (user_id, balance)
            VALUES ($1, 0)
            ON CONFLICT (user_id) DO UPDATE SET updated_at = NOW()
            RETURNING *
        `, [userId]);

        console.log("🟢 Пользователь:", result.rows[0]);

        res.json({
            ok: true,
            user: result.rows[0]
        });
    } catch (err) {
        console.log("🔴 DB ERROR:", err.message);
        res.status(500).json({ error: "DB_ERROR", details: err.message });
    }
});

// =========================
// 🔥 Запуск сервера
// =========================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 SERVER STARTED ON ${PORT}`));
