require("dotenv").config();
const express = require("express");
const http = require("http");
const WebSocketClient = require("ws");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);

// ------------------------------------------
// 🔥 PostgreSQL CONNECTION
// ------------------------------------------
const db = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// === Создаём таблицы при запуске ===
async function initDB() {
    await db.query(`
        CREATE TABLE IF NOT EXISTS users (
            id BIGINT PRIMARY KEY,
            balance NUMERIC NOT NULL DEFAULT 1000
        );
    `);

    await db.query(`
        CREATE TABLE IF NOT EXISTS positions (
            id BIGSERIAL PRIMARY KEY,
            user_id BIGINT REFERENCES users(id),
            type TEXT,
            entry_price NUMERIC,
            margin NUMERIC,
            leverage INT,
            size NUMERIC,
            created_at TIMESTAMP DEFAULT NOW()
        );
    `);

    console.log("Database ready ✔");
}
initDB();

// ------------------------------------------
// 🔥 TELEGRAM AUTH VALIDATION
// ------------------------------------------
function checkTelegramAuth(initData) {
    const urlParams = new URLSearchParams(initData);
    const hash = urlParams.get("hash");

    urlParams.delete("hash");

    const dataCheckString = [...urlParams.entries()]
        .sort()
        .map(([k, v]) => `${k}=${v}`)
        .join("\n");

    const secretKey = crypto
        .createHmac("sha256", "WebAppData")
        .update(process.env.BOT_TOKEN)
        .digest();

    const computedHash = crypto
        .createHmac("sha256", secretKey)
        .update(dataCheckString)
        .digest("hex");

    return computedHash === hash;
}

// ------------------------------------------
// 🔥 REAL-TIME BTC PRICE (Coinbase WebSocket)
// ------------------------------------------
let currentPrice = 0;

function connectCoinbase() {
    const ws = new WebSocketClient("wss://ws-feed.exchange.coinbase.com");

    ws.on("open", () => {
        console.log("Connected to Coinbase");
        ws.send(JSON.stringify({
            type: "subscribe",
            product_ids: ["BTC-USD"],
            channels: ["ticker"]
        }));
    });

    ws.on("message", (msg) => {
        const data = JSON.parse(msg);
        if (data.type === "ticker" && data.price) {
            currentPrice = parseFloat(data.price);
        }
    });

    ws.on("close", () => {
        console.log("Coinbase closed, reconnecting…");
        setTimeout(connectCoinbase, 5000);
    });

    ws.on("error", err => console.error("Coinbase error:", err));
}

connectCoinbase();

// ------------------------------------------
// 🔥 API: Get price
// ------------------------------------------
app.get("/api/price", (req, res) => {
    if (!currentPrice) return res.json({ error: "NO_PRICE_YET" });
    res.json({ price: currentPrice });
});

// ------------------------------------------
// 🔥 API: Init user session
// ------------------------------------------
app.post("/api/init", async (req, res) => {
    const { initData } = req.body;

    if (!checkTelegramAuth(initData)) {
        return res.status(403).json({ error: "INVALID_TG_AUTH" });
    }

    const data = new URLSearchParams(initData);
    const userId = data.get("user.id");

    // Проверяем существование
    const existing = await db.query("SELECT * FROM users WHERE id=$1", [userId]);

    if (existing.rows.length === 0) {
        await db.query(
            "INSERT INTO users(id, balance) VALUES($1, $2)",
            [userId, 1000]
        );
    }

    // Загружаем позиции
    const positions = await db.query(
        "SELECT * FROM positions WHERE user_id=$1",
        [userId]
    );

    const user = await db.query(
        "SELECT * FROM users WHERE id=$1",
        [userId]
    );

    res.json({
        balance: user.rows[0].balance,
        positions: positions.rows
    });
});

// ------------------------------------------
// 🔥 API: Open order
// ------------------------------------------
app.post("/api/order/open", async (req, res) => {
    const { userId, type, margin, leverage } = req.body;

    if (!currentPrice) return res.status(503).json({ error: "NO_PRICE_YET" });

    const user = await db.query("SELECT * FROM users WHERE id=$1", [userId]);
    if (user.rows.length === 0) return res.status(404).json({ error: "NO_USER" });

    if (user.rows[0].balance < margin)
        return res.status(400).json({ error: "LOW_BALANCE" });

    const fee = margin * leverage * 0.001;
    const newBalance = user.rows[0].balance - (margin + fee);

    await db.query("UPDATE users SET balance=$1 WHERE id=$2", [newBalance, userId]);

    const size = margin * leverage;

    const pos = await db.query(
        `INSERT INTO positions(user_id, type, entry_price, margin, leverage, size)
         VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
        [userId, type, currentPrice, margin, leverage, size]
    );

    res.json({ position: pos.rows[0], balance: newBalance });
});

// ------------------------------------------
// 🔥 API: Close order
// ------------------------------------------
app.post("/api/order/close", async (req, res) => {
    const { userId, positionId } = req.body;

    const pos = await db.query(
        "SELECT * FROM positions WHERE id=$1 AND user_id=$2",
        [positionId, userId]
    );

    if (pos.rows.length === 0) return res.status(404).json({ error: "NOT_FOUND" });

    const p = pos.rows[0];

    let pnl = 0;
    if (p.type === "LONG")
        pnl = ((currentPrice - p.entry_price) / p.entry_price) * p.size;
    else
        pnl = ((p.entry_price - currentPrice) / p.entry_price) * p.size;

    // Обновляем баланс
    const user = await db.query("SELECT balance FROM users WHERE id=$1", [userId]);
    const newBalance = parseFloat(user.rows[0].balance) + parseFloat(p.margin) + pnl;

    await db.query("UPDATE users SET balance=$1 WHERE id=$2", [newBalance, userId]);

    // Удаляем позицию
    await db.query("DELETE FROM positions WHERE id=$1", [positionId]);

    res.json({ pnl, balance: newBalance });
});

// ------------------------------------------
// 🔥 RUN SERVER
// ------------------------------------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`SERVER STARTED ON ${PORT}`));
