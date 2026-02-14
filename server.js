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

app.set('trust proxy', 1);

app.use(cors({
    origin: true,
    credentials: true
}));
app.use(express.json());
app.use(express.static("public"));

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100,
    standardHeaders: true,
    legacyHeaders: false,
    message: { ok: false, error: "TOO_MANY_REQUESTS" }
});

app.use('/api/', limiter);

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

const CONNECTION_STRING = "postgresql://neondb_owner:npg_igxGcyUQmX52@ep-ancient-sky-a9db2z9z-pooler.gwc.azure.neon.tech/neondb?sslmode=require&channel_binding=require";

console.log("=== ENV CHECK ===");
console.log("BOT_TOKEN set:", !!process.env.BOT_TOKEN);
console.log("ADSGRAM_SECRET set:", !!process.env.ADSGRAM_SECRET);
console.log("Using provided NeonDB connection string");
console.log("==================");

if (!process.env.BOT_TOKEN) {
    console.warn("⚠️  BOT_TOKEN not set! Signature verification will fail.");
}

if (!process.env.ADSGRAM_SECRET) {
    console.warn("⚠️  ADSGRAM_SECRET not set! Ad reward endpoint will reject all requests.");
}

const db = new Pool({
    connectionString: CONNECTION_STRING,
    ssl: true
});

const BOT_USERNAME = process.env.BOT_USERNAME || "";
const WEBAPP_SHORT_NAME = process.env.WEBAPP_SHORT_NAME || "";

const REFERRAL_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

const AD_REWARD_AMOUNT = 1;
const DAILY_AD_LIMIT = 5;
const VP_TO_USD_RATE = 0.005;
const MAX_TP_PER_POSITION = 3;
const MAX_SL_PER_POSITION = 3;
const MIN_PARTIAL_PERCENT = 10;
const MAX_PARTIAL_PERCENT = 100;

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

function getTodayDateUTC() {
    const now = new Date();
    return now.toISOString().split('T')[0];
}

function checkAndResetDailyAds(user) {
    const today = getTodayDateUTC();
    const lastResetDate = user.ad_views_reset_date ? user.ad_views_reset_date.toISOString().split('T')[0] : null;

    if (lastResetDate !== today) {
        return {
            needsReset: true,
            dailyAdViews: 0,
            newResetDate: today
        };
    }

    return {
        needsReset: false,
        dailyAdViews: Number(user.daily_ad_views) || 0,
        newResetDate: lastResetDate
    };
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

function getClientIp(req) {
    const ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress;
    return ip ? ip.split(',')[0].trim() : ip;
}

async function initDB() {
    try {
        console.log("🔄 Recreating/Checking DB tables...");

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
        ad_views_count INTEGER NOT NULL DEFAULT 0,
        daily_ad_views INTEGER NOT NULL DEFAULT 0,
        ad_views_reset_date DATE,
        last_ad_view TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
      );
    `);

        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ip TEXT`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS referral_code TEXT`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_by TEXT`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS invited_at TIMESTAMP`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ad_views_count INTEGER NOT NULL DEFAULT 0`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS last_ad_view TIMESTAMP`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS daily_ad_views INTEGER NOT NULL DEFAULT 0`); } catch(e) {}
        try { await db.query(`ALTER TABLE users ADD COLUMN IF NOT EXISTS ad_views_reset_date DATE`); } catch(e) {}

        await db.query(`CREATE UNIQUE INDEX IF NOT EXISTS users_referral_code_uidx ON users(referral_code) WHERE referral_code IS NOT NULL;`);
        await db.query(`CREATE INDEX IF NOT EXISTS users_invited_by_idx ON users(invited_by);`);

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

        await db.query(`
      CREATE TABLE IF NOT EXISTS tp_sl_orders (
        id BIGSERIAL PRIMARY KEY,
        position_id BIGINT NOT NULL REFERENCES positions(id) ON DELETE CASCADE,
        user_id TEXT NOT NULL REFERENCES users(user_id) ON DELETE CASCADE,
        pair TEXT NOT NULL,
        order_type TEXT NOT NULL CHECK (order_type IN ('TP', 'SL')),
        trigger_price NUMERIC NOT NULL,
        size_percent NUMERIC NOT NULL DEFAULT 100 CHECK (size_percent >= 10 AND size_percent <= 100),
        status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE', 'TRIGGERED', 'CANCELLED')),
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        triggered_at TIMESTAMP
      );
    `);

        await db.query(`CREATE INDEX IF NOT EXISTS tp_sl_orders_position_idx ON tp_sl_orders(position_id) WHERE status = 'ACTIVE';`);
        await db.query(`CREATE INDEX IF NOT EXISTS tp_sl_orders_status_idx ON tp_sl_orders(status) WHERE status = 'ACTIVE';`);
        await db.query(`CREATE INDEX IF NOT EXISTS tp_sl_orders_user_idx ON tp_sl_orders(user_id);`);

        console.log("✅ DB tables ready (including tp_sl_orders)!");

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

async function upsertUserFromObj(userObj, ipAddress, startParamRaw) {
    const userId = String(userObj.id);
    console.log(`📝 Upserting user ${userId} (${userObj.first_name || "No name"}). IP: ${ipAddress}`);

    const startParam = startParamRaw ? String(startParamRaw).trim() : "";

    try {
        await db.query("BEGIN");

        const existingRes = await db.query(
            "SELECT user_id, referral_code, invited_by FROM users WHERE user_id = $1 FOR UPDATE",
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
            "SELECT user_id, first_name, username, photo_url, balance, referral_code, invited_by, invited_at, ad_views_count, daily_ad_views, ad_views_reset_date FROM users WHERE user_id = $1",
            [userId]
        );
        return res.rows[0];
    } catch (err) {
        try { await db.query("ROLLBACK"); } catch (e) {}
        console.error(`❌ Error saving user ${userId}:`, err.message);
        throw err;
    }
}

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
                "SELECT user_id, first_name, username, photo_url, balance, ad_views_count, daily_ad_views, ad_views_reset_date FROM users WHERE user_id = $1",
                [userId]
            );
            if (!ures.rows.length) return res.status(404).json({ ok: false, error: "NO_USER" });
            userRow = ures.rows[0];
        }

        const dailyStatus = checkAndResetDailyAds(userRow);
        if (dailyStatus.needsReset) {
            await db.query(
                "UPDATE users SET daily_ad_views = 0, ad_views_reset_date = $1 WHERE user_id = $2",
                [dailyStatus.newResetDate, userRow.user_id]
            );
            userRow.daily_ad_views = 0;
            userRow.ad_views_reset_date = dailyStatus.newResetDate;
        }

        const positionsRes = await db.query(
            "SELECT * FROM positions WHERE user_id = $1 ORDER BY created_at ASC",
            [userRow.user_id]
        );

        const tpSlRes = await db.query(
            "SELECT * FROM tp_sl_orders WHERE user_id = $1 AND status = 'ACTIVE' ORDER BY created_at ASC",
            [userRow.user_id]
        );

        const cookieVal = makeSessionCookieValue(userRow.user_id);
        const isSecure = req.headers["x-forwarded-proto"] === "https" || req.protocol === "https";

        const sameSite = isSecure ? "SameSite=None" : "SameSite=Lax";
        const cookieParts = [`${COOKIE_NAME}=${cookieVal}`, `Path=/`, `HttpOnly`, sameSite, `Max-Age=${60 * 60 * 24 * 30}`];
        if (isSecure) cookieParts.push("Secure");
        res.setHeader("Set-Cookie", cookieParts.join("; "));

        res.json({
            ok: true,
            user: {
                ...userRow,
                daily_ad_views: dailyStatus.dailyAdViews,
                daily_ad_limit: DAILY_AD_LIMIT,
                vp_to_usd_rate: VP_TO_USD_RATE
            },
            positions: positionsRes.rows,
            tpSlOrders: tpSlRes.rows
        });

    } catch (err) {
        console.error("💥 UNHANDLED ERROR in /api/init:", err);
        res.status(500).json({ ok: false, error: "SERVER_ERROR" });
    }
});

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

app.get("/api/adsgram/reward", async (req, res) => {
    console.log("\n🎬 /api/adsgram/reward called!");
    console.log("Query params:", req.query);

    try {
        const { userid, secret } = req.query;

        if (!userid) {
            console.log("❌ Missing userid parameter");
            return res.status(400).json({ ok: false, error: "MISSING_USERID" });
        }

        if (!secret) {
            console.log("❌ Missing secret parameter");
            return res.status(400).json({ ok: false, error: "MISSING_SECRET" });
        }

        const expectedSecret = process.env.ADSGRAM_SECRET;
        if (!expectedSecret) {
            console.error("❌ ADSGRAM_SECRET not configured on server");
            return res.status(500).json({ ok: false, error: "SERVER_CONFIG_ERROR" });
        }

        if (secret !== expectedSecret) {
            console.log("❌ Invalid secret provided");
            return res.status(403).json({ ok: false, error: "INVALID_SECRET" });
        }

        const userId = String(userid).trim();

        const userCheck = await db.query(
            "SELECT user_id, balance, ad_views_count, daily_ad_views, ad_views_reset_date FROM users WHERE user_id = $1",
            [userId]
        );

        if (!userCheck.rows.length) {
            console.log(`❌ User ${userId} not found in database`);
            return res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });
        }

        const user = userCheck.rows[0];
        const dailyStatus = checkAndResetDailyAds(user);

        if (dailyStatus.needsReset) {
            await db.query(
                "UPDATE users SET daily_ad_views = 0, ad_views_reset_date = $1 WHERE user_id = $2",
                [dailyStatus.newResetDate, userId]
            );
            user.daily_ad_views = 0;
        }

        const currentDailyViews = dailyStatus.dailyAdViews;

        if (currentDailyViews >= DAILY_AD_LIMIT) {
            console.log(`⚠️ User ${userId} reached daily ad limit (${currentDailyViews}/${DAILY_AD_LIMIT})`);
            return res.status(429).json({
                ok: false,
                error: "DAILY_LIMIT_REACHED",
                dailyAdViews: currentDailyViews,
                dailyAdLimit: DAILY_AD_LIMIT,
                message: `Daily limit of ${DAILY_AD_LIMIT} ads reached. Try again tomorrow!`
            });
        }

        await db.query(`
            UPDATE users
            SET balance = balance + $1,
                ad_views_count = ad_views_count + 1,
                daily_ad_views = daily_ad_views + 1,
                ad_views_reset_date = COALESCE(ad_views_reset_date, CURRENT_DATE),
                last_ad_view = CURRENT_TIMESTAMP,
                updated_at = CURRENT_TIMESTAMP
            WHERE user_id = $2
        `, [AD_REWARD_AMOUNT, userId]);

        const updatedUser = await db.query(
            "SELECT balance, ad_views_count, daily_ad_views FROM users WHERE user_id = $1",
            [userId]
        );

        const newDailyViews = Number(updatedUser.rows[0].daily_ad_views);
        const remainingToday = DAILY_AD_LIMIT - newDailyViews;

        console.log(`✅ Ad reward granted to user ${userId}: +${AD_REWARD_AMOUNT} VP`);
        console.log(`   New balance: ${updatedUser.rows[0].balance}, Daily views: ${newDailyViews}/${DAILY_AD_LIMIT}, Remaining: ${remainingToday}`);

        res.json({
            ok: true,
            reward: AD_REWARD_AMOUNT,
            newBalance: Number(updatedUser.rows[0].balance),
            totalViews: Number(updatedUser.rows[0].ad_views_count),
            dailyAdViews: newDailyViews,
            dailyAdLimit: DAILY_AD_LIMIT,
            remainingToday: remainingToday
        });

    } catch (err) {
        console.error("💥 Error in /api/adsgram/reward:", err);
        res.status(500).json({ ok: false, error: "SERVER_ERROR" });
    }
});

app.get("/api/user/ad-stats", async (req, res) => {
    try {
        const userId = await getAuthenticatedUserId(req);
        if (!userId) return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });

        const userRes = await db.query(
            "SELECT ad_views_count, daily_ad_views, ad_views_reset_date, last_ad_view, balance FROM users WHERE user_id = $1",
            [userId]
        );

        if (!userRes.rows.length) {
            return res.status(404).json({ ok: false, error: "USER_NOT_FOUND" });
        }

        const user = userRes.rows[0];
        const dailyStatus = checkAndResetDailyAds(user);

        if (dailyStatus.needsReset) {
            await db.query(
                "UPDATE users SET daily_ad_views = 0, ad_views_reset_date = $1 WHERE user_id = $2",
                [dailyStatus.newResetDate, userId]
            );
        }

        const currentDailyViews = dailyStatus.dailyAdViews;
        const remainingToday = DAILY_AD_LIMIT - currentDailyViews;

        res.json({
            ok: true,
            adViewsCount: Number(user.ad_views_count) || 0,
            dailyAdViews: currentDailyViews,
            dailyAdLimit: DAILY_AD_LIMIT,
            remainingToday: Math.max(0, remainingToday),
            lastAdView: user.last_ad_view,
            balance: Number(user.balance),
            vpToUsdRate: VP_TO_USD_RATE
        });
    } catch (err) {
        console.error("Error fetching ad stats:", err);
        res.status(500).json({ ok: false, error: "SERVER_ERROR" });
    }
});

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

// ======================== TP/SL ENDPOINTS ========================

app.post("/api/tp-sl/create", async (req, res) => {
    try {
        const user = await getAuthenticatedUser(req);
        const { positionId, orderType, triggerPrice, sizePercent } = req.body;

        if (!positionId || !orderType || !triggerPrice) {
            return res.status(400).json({ ok: false, error: "MISSING_FIELDS" });
        }

        const normalizedType = String(orderType).toUpperCase();
        if (normalizedType !== 'TP' && normalizedType !== 'SL') {
            return res.status(400).json({ ok: false, error: "INVALID_ORDER_TYPE" });
        }

        const trigPrice = Number(triggerPrice);
        if (isNaN(trigPrice) || trigPrice <= 0) {
            return res.status(400).json({ ok: false, error: "INVALID_TRIGGER_PRICE" });
        }

        const percent = Number(sizePercent) || 100;
        if (percent < MIN_PARTIAL_PERCENT || percent > MAX_PARTIAL_PERCENT) {
            return res.status(400).json({ ok: false, error: `SIZE_PERCENT_MUST_BE_${MIN_PARTIAL_PERCENT}_TO_${MAX_PARTIAL_PERCENT}` });
        }

        const client = await db.pool ? db.connect() : db.connect();
        try {
            await client.query("BEGIN");

            const posRes = await client.query(
                "SELECT * FROM positions WHERE id = $1 AND user_id = $2 FOR UPDATE",
                [positionId, user.user_id]
            );

            if (!posRes.rows.length) {
                await client.query("ROLLBACK");
                return res.status(404).json({ ok: false, error: "POSITION_NOT_FOUND" });
            }

            const pos = posRes.rows[0];
            const entryPrice = Number(pos.entry_price);
            const posType = pos.type.toUpperCase();

            if (normalizedType === 'TP') {
                if (posType === 'LONG' && trigPrice <= entryPrice) {
                    await client.query("ROLLBACK");
                    return res.status(400).json({ ok: false, error: "TP_MUST_BE_ABOVE_ENTRY_FOR_LONG" });
                }
                if (posType === 'SHORT' && trigPrice >= entryPrice) {
                    await client.query("ROLLBACK");
                    return res.status(400).json({ ok: false, error: "TP_MUST_BE_BELOW_ENTRY_FOR_SHORT" });
                }
            }

            if (normalizedType === 'SL') {
                if (posType === 'LONG' && trigPrice >= entryPrice) {
                    await client.query("ROLLBACK");
                    return res.status(400).json({ ok: false, error: "SL_MUST_BE_BELOW_ENTRY_FOR_LONG" });
                }
                if (posType === 'SHORT' && trigPrice <= entryPrice) {
                    await client.query("ROLLBACK");
                    return res.status(400).json({ ok: false, error: "SL_MUST_BE_ABOVE_ENTRY_FOR_SHORT" });
                }
            }

            const existingOrders = await client.query(
                "SELECT * FROM tp_sl_orders WHERE position_id = $1 AND status = 'ACTIVE'",
                [positionId]
            );

            const tpCount = existingOrders.rows.filter(o => o.order_type === 'TP').length;
            const slCount = existingOrders.rows.filter(o => o.order_type === 'SL').length;

            if (normalizedType === 'TP' && tpCount >= MAX_TP_PER_POSITION) {
                await client.query("ROLLBACK");
                return res.status(400).json({ ok: false, error: `MAX_${MAX_TP_PER_POSITION}_TP_ORDERS_REACHED` });
            }

            if (normalizedType === 'SL' && slCount >= MAX_SL_PER_POSITION) {
                await client.query("ROLLBACK");
                return res.status(400).json({ ok: false, error: `MAX_${MAX_SL_PER_POSITION}_SL_ORDERS_REACHED` });
            }

            const sameTypeOrders = existingOrders.rows.filter(o => o.order_type === normalizedType);
            const usedPercent = sameTypeOrders.reduce((sum, o) => sum + Number(o.size_percent), 0);
            const availablePercent = 100 - usedPercent;

            if (percent > availablePercent) {
                await client.query("ROLLBACK");
                return res.status(400).json({
                    ok: false,
                    error: "EXCEEDS_AVAILABLE_VOLUME",
                    availablePercent: Math.floor(availablePercent),
                    usedPercent: Math.ceil(usedPercent)
                });
            }

            const duplicatePrice = sameTypeOrders.find(o => Math.abs(Number(o.trigger_price) - trigPrice) < 0.0001);
            if (duplicatePrice) {
                await client.query("ROLLBACK");
                return res.status(400).json({ ok: false, error: "DUPLICATE_TRIGGER_PRICE" });
            }

            const orderRes = await client.query(`
                INSERT INTO tp_sl_orders (position_id, user_id, pair, order_type, trigger_price, size_percent, status)
                VALUES ($1, $2, $3, $4, $5, $6, 'ACTIVE')
                RETURNING *
            `, [positionId, user.user_id, pos.pair, normalizedType, trigPrice, percent]);

            await client.query("COMMIT");

            const allOrders = await db.query(
                "SELECT * FROM tp_sl_orders WHERE position_id = $1 AND status = 'ACTIVE' ORDER BY created_at ASC",
                [positionId]
            );

            console.log(`✅ ${normalizedType} order created for position ${positionId}: price=${trigPrice}, size=${percent}%`);

            res.json({
                ok: true,
                order: orderRes.rows[0],
                allOrders: allOrders.rows,
                tpCount: allOrders.rows.filter(o => o.order_type === 'TP').length,
                slCount: allOrders.rows.filter(o => o.order_type === 'SL').length
            });

        } catch (innerErr) {
            await client.query("ROLLBACK");
            throw innerErr;
        } finally {
            client.release();
        }

    } catch (err) {
        console.error("❌ Error creating TP/SL:", err.message);
        res.status(500).json({ ok: false, error: err.message });
    }
});

app.post("/api/tp-sl/delete", async (req, res) => {
    try {
        const user = await getAuthenticatedUser(req);
        const { orderId } = req.body;

        if (!orderId) {
            return res.status(400).json({ ok: false, error: "MISSING_ORDER_ID" });
        }

        const orderRes = await db.query(
            "SELECT * FROM tp_sl_orders WHERE id = $1 AND user_id = $2 AND status = 'ACTIVE'",
            [orderId, user.user_id]
        );

        if (!orderRes.rows.length) {
            return res.status(404).json({ ok: false, error: "ORDER_NOT_FOUND" });
        }

        const order = orderRes.rows[0];

        await db.query(
            "UPDATE tp_sl_orders SET status = 'CANCELLED' WHERE id = $1",
            [orderId]
        );

        const allOrders = await db.query(
            "SELECT * FROM tp_sl_orders WHERE position_id = $1 AND status = 'ACTIVE' ORDER BY created_at ASC",
            [order.position_id]
        );

        console.log(`✅ ${order.order_type} order ${orderId} cancelled for position ${order.position_id}`);

        res.json({
            ok: true,
            deletedOrderId: orderId,
            allOrders: allOrders.rows,
            tpCount: allOrders.rows.filter(o => o.order_type === 'TP').length,
            slCount: allOrders.rows.filter(o => o.order_type === 'SL').length
        });

    } catch (err) {
        console.error("❌ Error deleting TP/SL:", err.message);
        res.status(500).json({ ok: false, error: err.message });
    }
});

app.get("/api/tp-sl/list", async (req, res) => {
    try {
        const userId = await getAuthenticatedUserId(req);
        if (!userId) return res.status(401).json({ ok: false, error: "UNAUTHORIZED" });

        const positionId = req.query.positionId;

        let ordersRes;
        if (positionId) {
            ordersRes = await db.query(
                "SELECT * FROM tp_sl_orders WHERE position_id = $1 AND user_id = $2 AND status = 'ACTIVE' ORDER BY created_at ASC",
                [positionId, userId]
            );
        } else {
            ordersRes = await db.query(
                "SELECT * FROM tp_sl_orders WHERE user_id = $1 AND status = 'ACTIVE' ORDER BY created_at ASC",
                [userId]
            );
        }

        const orders = ordersRes.rows;
        const tpOrders = orders.filter(o => o.order_type === 'TP');
        const slOrders = orders.filter(o => o.order_type === 'SL');

        res.json({
            ok: true,
            orders,
            tpCount: tpOrders.length,
            slCount: slOrders.length,
            tpUsedPercent: tpOrders.reduce((s, o) => s + Number(o.size_percent), 0),
            slUsedPercent: slOrders.reduce((s, o) => s + Number(o.size_percent), 0)
        });

    } catch (err) {
        console.error("Error fetching TP/SL orders:", err);
        res.status(500).json({ ok: false, error: "SERVER_ERROR" });
    }
});

app.get("/api/health", (req, res) => res.json({ ok: true }));

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));
