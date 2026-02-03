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
const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { ok: false, error: "TOO_MANY_REQUESTS" }
});

// Применяем лимит ко всем API запросам
app.use('/api/', limiter);

// Строгий лимитер для Adsgram callback (защита от DDoS на награды)
const adsgramLimiter = rateLimit({
    windowMs: 60 * 1000, // 1 минута
    max: 10, // максимум 10 запросов в минуту с одного IP
    standardHeaders: true,
    legacyHeaders: false,
    message: "TOO_MANY_REQUESTS"
});

// === 🛡️ СИСТЕМА ANTI-SLEEP ===
const PRICE_SERVER_URL = "https://tradingbot-backend-2yws.onrender.com";

cron.schedule("*/10 * * * *", async () => {
    console.log("⏰ Anti-Sleep: Pinging Price Server...");
    try {
        const response = await fetch(`${PRICE_SERVER_URL}/health`);
        if (response.ok) console.log("✅ Price Server is awake");
        else console.log("⚠️ Price Server responded with " + response.status);
    } catch (e) {
        console.error("❌ Anti-Sleep Error:", e.message);
    }
});

// ======================== КОНФИГУРАЦИЯ БД ========================
const CONNECTION_STRING = "postgresql://neondb_owner:npg_igxGcyUQmX52@ep-ancient-sky-a9db2z9z-pooler.gwc.azure.neon.tech/neondb?sslmode=require&channel_binding=require";

// Adsgram секрет для защиты от накрутки.
// ВАЖНО: Задайте эту переменную в Render (ADSGRAM_SECRET)
// и используйте ТО ЖЕ значение в ссылке настроек Adsgram.
const ADSGRAM_SECRET = process.env.ADSGRAM_SECRET || "";
const AD_REWARD_AMOUNT = 1; // VP за просмотр рекламы

console.log("=== ENV CHECK ===");
console.log("BOT_TOKEN set:", !!process.env.BOT_TOKEN);
console.log("ADSGRAM_SECRET set:", !!ADSGRAM_SECRET);
console.log("Using provided NeonDB connection string");
console.log("==================");

if (!process.env.BOT_TOKEN) {
    console.warn("⚠️  BOT_TOKEN not set! Signature verification will fail.");
}
if (!ADSGRAM_SECRET) {
    console.warn("⚠️  ADSGRAM_SECRET not set! Ad reward endpoint will be vulnerable.");
}

// ======================== ПОДКЛЮЧЕНИЕ К БД ========================
const db = new Pool({
    connectionString: CONNECTION_STRING,
    ssl: true
});

// ======================== REFERRALS CONFIG ========================
const BOT_USERNAME = process.env.BOT_USERNAME || "";
const WEBAPP_SHORT_NAME = process.env.WEBAPP_SHORT_NAME || "";

// ======================== REFERRAL HELPERS ========================
const REFERRAL_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // без 0/O/1/I

function makeReferralCode(len = 8) {
    const bytes = crypto.randomBytes(len);
    let out = "";
    for (let i = 0; i < len; i++) {
        out += REFERRAL_ALPHABET[bytes[i] % REFERRAL_ALPHABET.length];
    }
    return out;
}

async function generateUniqueReferralCode() {
    for (let attempt = 0; attempt < 20; attempt++) {
        const code = makeReferralCode(8);
        const check = await db.query("SELECT 1 FROM users WHERE referral_code = $1 LIMIT 1", [code]);
        if (!check.rows.length) return code;
    }
    for (let attempt = 0; attempt < 20; attempt++) {
        const code = makeReferralCode(12);
        const check = await db.query("SELECT 1 FROM users WHERE referral_code = $1 LIMIT 1", [code]);
        if (!check.rows.length) return code;
    }
    throw new Error("REFERRAL_CODE_GENERATION_FAILED");
}

function buildReferralLink(code) {
    if (BOT_USERNAME && WEBAPP_SHORT_NAME) {
        return `https://t.me/${BOT_USERNAME}/${WEBAPP_SHORT_NAME}?startapp=${encodeURIComponent(code)}`;
    }
    if (BOT_USERNAME) {
        return `https://t.me/${BOT_USERNAME}?start=${encodeURIComponent(code)}`;
    }
    return code;
}

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
                referral_code TEXT,
                invited_by TEXT,
                invited_at TIMESTAMP,
                ad_views_count INT NOT NULL DEFAULT 0,
                last_ad_reward_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        // Миграции
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip TEXT`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code TEXT`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_by TEXT`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_at TIMESTAMP`); } catch(e) {}
        
        // Adsgram миграции
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ad_views_count INT NOT NULL DEFAULT 0`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ad_reward_at TIMESTAMP`); } catch(e) {}

        // Индексы
        await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_referral_code_uidx ON users(referral_code) WHERE referral_code IS NOT NULL;`);
        await db.query(`CREATE INDEX IF NOT EXISTS users_invited_by_idx ON users(invited_by);`);

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

        try { await db.query(`ALTER TABLE trades_history ADD COLUMN IF NOT EXISTS commission NUMERIC DEFAULT 0`); } catch(e) {}

        console.log("✅ DB tables ready!");

        // Backfill referral_code
        try {
            const missing = await db.query("SELECT user_id FROM users WHERE referral_code IS NULL");
            if (missing.rows.length) {
                console.log(`🔁 Backfill referral_code: ${missing.rows.length} users`);
                for (const row of missing.rows) {
                    const code = await generateUniqueReferralCode();
                    await db.query("UPDATE users SET referral_code = $1 WHERE user_id = $2 AND referral_code IS NULL", [code, row.user_id]);
                }
                console.log("✅ Backfill referral_code done");
            }
        } catch (e) {
            console.error("⚠️ Backfill referral_code failed:", e.message);
        }
    } catch (err) {
        console.error("❌ Error recreating tables:", err.message);
    }
}
await initDB();

// ======================== UPSERT USER ========================
async function upsertUserFromObj(userObj, ipAddress, startParamRaw) {
    const userId = String(userObj.id);
    console.log(`📝 Upserting user ${userId} (${userObj.first_name || "No name"}). IP: ${ipAddress}`);

    const startParam = startParamRaw ? String(startParamRaw).trim() : "";

    try {
        await db.query("BEGIN");

        const existingRes = await db.query(
            "SELECT user_id, referral_code, invited_by, ad_views_count FROM users WHERE user_id = $1 FOR UPDATE",
            [userId]
        );

        let referralCode = existingRes.rows[0]?.referral_code || null;
        let invitedBy = existingRes.rows[0]?.invited_by || null;
        let invitedAt = null;

        if (!referralCode) {
            referralCode = await generateUniqueReferralCode();
        }

        if (!invitedBy && startParam) {
            const inviterRes = await db.query(
                "SELECT user_id FROM users WHERE referral_code = $1 LIMIT 1",
                [startParam]
            );
            const inviterId = inviterRes.rows[0]?.user_id || null;
            if (inviterId && inviterId !== userId) {
                invitedBy = inviterId;
                invitedAt = new Date();
            }
        }

        if (!existingRes.rows.length) {
            await db.query(`
                INSERT INTO users (user_id, first_name, username, photo_url, last_ip, referral_code, invited_by, invited_at)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
            `, [
                userId,
                userObj.first_name || null,
                userObj.username || null,
                userObj.photo_url || null,
                ipAddress,
                referralCode,
                invitedBy,
                invitedAt
            ]);
        } else {
            await db.query(`
                UPDATE users SET
                    first_name = $2,
                    username = $3,
                    photo_url = $4,
                    last_ip = $5,
                    referral_code = $6,
                    invited_by = COALESCE(users.invited_by, $7),
                    invited_at = COALESCE(users.invited_at, $8),
                    updated_at = CURRENT_TIMESTAMP
                WHERE user_id = $1
            `, [
                userId,
                userObj.first_name || null,
                userObj.username || null,
                userObj.photo_url || null,
                ipAddress,
                referralCode,
                invitedBy,
                invitedAt
            ]);
        }

        await db.query("COMMIT");

        const res = await db.query(
            "SELECT user_id, first_name, username, photo_url, balance, referral_code, invited_by, invited_at, ad_views_count FROM users WHERE user_id = $1",
            [userId]
        );
        return res.rows[0];
    } catch (err) {
        try { await db.query("ROLLBACK"); } catch (e) {}
        console.error(`❌ Error saving user ${userId}:`, err.message);
        throw err;
    }
}

// ======================== ROUTES ========================

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
        const { initData, referralCode: referralCodeFromBody } = req.body;
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

            const startParam = params.get("start_param") || referralCodeFromBody || "";

            let userObj;
            try {
                userObj = JSON.parse(rawUser);
            } catch (e) {
                return res.status(400).json({ ok: false, error: "INVALID_USER_JSON" });
            }

            userRow = await upsertUserFromObj(userObj, ip, startParam);
        } else {
            const cookieHeader = req.headers.cookie || "";
            const cookies = Object.fromEntries(
                cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2)
            );
            const sessionVal = cookies[COOKIE_NAME];
            const userId = verifySessionCookieValue(sessionVal);

            if (!userId) return res.status(401).json({ ok: false, error: "NO_SESSION" });

            const ures = await db.query(
                "SELECT user_id, first_name, username, photo_url, balance, ad_views_count FROM users WHERE user_id = $1",
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
        const sameSite = isSecure ? "SameSite=None" : "SameSite=Lax";
        const cookieParts = [`${COOKIE_NAME}=${cookieVal}`, `Path=/`, `HttpOnly`, sameSite, `Max-Age=${60 * 60 * 24 * 30}`];
        if (isSecure) cookieParts.push("Secure");
        res.setHeader("Set-Cookie", cookieParts.join("; "));

        res.json({ ok: true, user: userRow, positions: positionsRes.rows });

    } catch (err) {
        console.error("💥 UNHANDLED ERROR in /api/init:", err);
        res.status(500).json({ ok: false, error: "SERVER_ERROR" });
    }
});

// ======================== ADSGRAM REWARD CALLBACK ========================
app.get("/api/adsgram/reward", adsgramLimiter, async (req, res) => {
    const ip = getClientIp(req);
    console.log(`\n🎬 Adsgram Reward Callback [IP: ${ip}]`);
    console.log("Query params:", req.query);

    try {
        const { userId, secret } = req.query;

        // 1. Проверка секретного ключа (Защита от накрутки)
        if (!ADSGRAM_SECRET) {
            console.error("❌ ADSGRAM_SECRET not configured on server");
            return res.status(500).send("SERVER_CONFIG_ERROR");
        }

        if (!secret || secret !== ADSGRAM_SECRET) {
            console.warn(`⚠️ Invalid secret from IP: ${ip}`);
            return res.status(403).send("INVALID_SECRET");
        }

        // 2. Проверка userId
        if (!userId) {
            console.warn("⚠️ Missing userId in callback");
            return res.status(400).send("MISSING_USER_ID");
        }

        const userIdStr = String(userId).trim();

        // 3. Проверка существования пользователя
        const userRes = await db.query(
            "SELECT user_id, balance, ad_views_count, last_ad_reward_at FROM users WHERE user_id = $1",
            [userIdStr]
        );

        if (!userRes.rows.length) {
            console.warn(`⚠️ User not found: ${userIdStr}`);
            return res.status(404).send("USER_NOT_FOUND");
        }

        const user = userRes.rows[0];

        // 4. Защита от слишком частых наград (Rate Limit на стороне БД)
        // Разрешаем награду только раз в 5 секунд
        if (user.last_ad_reward_at) {
            const lastRewardTime = new Date(user.last_ad_reward_at).getTime();
            const now = Date.now();
            const diffSeconds = (now - lastRewardTime) / 1000;

            if (diffSeconds < 5) {
                console.warn(`⚠️ Too fast reward request for user ${userIdStr}: ${diffSeconds.toFixed(1)}s ago`);
                return res.status(429).send("TOO_FAST");
            }
        }

        // 5. Начисление награды
        await db.query("BEGIN");

        await db.query(`
            UPDATE users 
            SET balance = balance + $1,
                ad_views_count = ad_views_count + 1,
                last_ad_reward_at = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $2
        `, [AD_REWARD_AMOUNT, userIdStr]);

        await db.query("COMMIT");

        const newAdViews = (user.ad_views_count || 0) + 1;
        console.log(`✅ Reward granted to user ${userIdStr}: +${AD_REWARD_AMOUNT} VP (total ads: ${newAdViews})`);

        // Adsgram ожидает HTTP 200 для подтверждения успешной обработки
        res.status(200).send("OK");

    } catch (err) {
        try { await db.query("ROLLBACK"); } catch (e) {}
        console.error("❌ Error processing ad reward:", err.message);
        res.status(500).send("SERVER_ERROR");
    }
});

// ======================== USER REWARDS STATS ========================
app.get("/api/user/rewards", async (req, res) => {
    try {
        const userId = await getAuthenticatedUserId(req);
        if (!userId) return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });

        const userRes = await db.query(
            "SELECT balance, ad_views_count FROM users WHERE user_id = $1",
            [userId]
        );

        if (!userRes.rows.length) {
            return res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });
        }

        const user = userRes.rows[0];

        res.json({
            ok: true,
            balance: Number(user.balance),
            adViewsCount: Number(user.ad_views_count || 0)
        });
    } catch (err) {
        console.error("Error fetching rewards:", err);
        res.status(500).json({ ok: false, error: "SERVER_ERROR" });
    }
});

// ======================== HELPERS FOR AUTH ========================
async function getAuthenticatedUserId(req) {
    if (req.body && req.body.userId) return String(req.body.userId);
    if (req.query && req.query.userId) return String(req.query.userId);

    const cookieHeader = req.headers.cookie || "";
    const cookies = Object.fromEntries(
        cookieHeader.split(";").map(c => c.trim().split("=")).filter(p => p.length === 2)
    );
    const sessionVal = cookies[COOKIE_NAME];
    const userId = verifySessionCookieValue(sessionVal);
    return userId ? String(userId) : null;
}

// ======================== REFERRALS API ========================
app.get("/api/user/referrals", async (req, res) => {
    try {
        const userId = await getAuthenticatedUserId(req);
        if (!userId) return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });

        const userRes = await db.query(
            "SELECT user_id, referral_code FROM users WHERE user_id = $1",
            [userId]
        );
        if (!userRes.rows.length) return res.status(404).json({ ok: false, error: "NO_USER" });

        let referralCode = userRes.rows[0].referral_code;
        if (!referralCode) {
            referralCode = await generateUniqueReferralCode();
            await db.query("UPDATE users SET referral_code = $1 WHERE user_id = $2 AND referral_code IS NULL", [referralCode, userId]);
        }

        const invitedRes = await db.query(
            `SELECT user_id, first_name, username, photo_url, invited_at, created_at
             FROM users
             WHERE invited_by = $1
             ORDER BY invited_at DESC NULLS LAST, created_at DESC
             LIMIT 50`,
            [userId]
        );

        const countRes = await db.query(
            "SELECT COUNT(*)::int AS cnt FROM users WHERE invited_by = $1",
            [userId]
        );

        res.json({
            ok: true,
            referralCode,
            referralLink: buildReferralLink(referralCode),
            invitedCount: countRes.rows[0]?.cnt || 0,
            invited: invitedRes.rows
        });
    } catch (err) {
        console.error("Error fetching referrals:", err);
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

        const posRes = await db.query(
            "SELECT * FROM positions WHERE id = $1 AND user_id = $2",
            [positionId, user.user_id]
        );

        if (!posRes.rows.length) return res.status(404).json({ ok: false, error: "POSITION_NOT_FOUND" });
        const pos = posRes.rows[0];

        const cPrice = Number(closePrice);
        const ePrice = Number(pos.entry_price);
        const pSize = Number(pos.size);
        const pMargin = Number(pos.margin);

        const priceChangePct = (cPrice - ePrice) / ePrice;
        let pnl = priceChangePct * pSize;
        if (pos.type === "SHORT") pnl = -pnl;

        const commission = pSize * 0.0003;
        let totalReturn = pMargin + pnl - commission;

        let isLiquidated = false;
        if (totalReturn <= 0) {
            isLiquidated = true;
            totalReturn = 0;
            pnl = commission - pMargin;
        }

        await db.query("BEGIN");

        if (totalReturn > 0) {
            await db.query("UPDATE users SET balance = balance + $1 WHERE user_id = $2", [totalReturn, user.user_id]);
        }

        const finalCommission = commission;

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
