// server.js
require("dotenv").config();
const express = require("express");
const http = require("http");
const WebSocketClient = require("ws");
const cors = require("cors");
const path = require("path");
const crypto = require("crypto");
const { Pool } = require("pg");
const cookieParser = require("cookie-parser");
const { v4: uuidv4 } = require("uuid");

const app = express();
app.use(cors({
  origin: true,
  credentials: true
}));
app.use(express.json());
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

const server = http.createServer(app);

// ------------------------------------------
// PostgreSQL pool
// ------------------------------------------
if (!process.env.DATABASE_URL) {
  console.error("DATABASE_URL is not set in env!");
  process.exit(1);
}

const db = new Pool({
  connectionString: process.env.DATABASE_URL,
  // Render / many managed DB require SSL; if running locally w/out ssl, set NODE_ENV=development
  ssl: process.env.NODE_ENV === "production" ? { rejectUnauthorized: false } : false
});

// ------------------------------------------
// DB init: users, positions, sessions
// ------------------------------------------
async function initDB() {
  // users table - user_id TEXT primary key
  await db.query(`
    CREATE TABLE IF NOT EXISTS users (
      user_id TEXT PRIMARY KEY,
      balance NUMERIC NOT NULL DEFAULT 0,
      updated_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // ensure default is 0 (in case existing table had different default)
  try {
    await db.query(`ALTER TABLE users ALTER COLUMN balance SET DEFAULT 0`);
  } catch (e) {
    // ignore if can't alter (older PG versions) — not critical
  }

  // positions
  await db.query(`
    CREATE TABLE IF NOT EXISTS positions (
      id BIGSERIAL PRIMARY KEY,
      user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
      type TEXT,
      entry_price NUMERIC,
      margin NUMERIC,
      leverage INT,
      size NUMERIC,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // sessions: token stored server-side, long expiration
  await db.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      token TEXT PRIMARY KEY,
      user_id TEXT REFERENCES users(user_id) ON DELETE CASCADE,
      created_at TIMESTAMP DEFAULT NOW(),
      expires_at TIMESTAMP
    );
  `);

  console.log("DB ready");
}

initDB().catch(err => {
  console.error("DB init error:", err);
  process.exit(1);
});

// ------------------------------------------
// Telegram initData verification helper
// ------------------------------------------
function checkTelegramAuth(initData) {
  // initData must be a string like: "query_id=...&user=...&auth_date=...&hash=..."
  if (!initData || typeof initData !== "string") return false;

  try {
    // Telegram may supply &-separated params (sometimes with URL encoding). Use URLSearchParams on a query string.
    const params = new URLSearchParams(initData);
    const hash = params.get("hash");
    if (!hash) return false;

    // Build data-check-string: entries except hash sorted by key, joined with '\n' as "k=value"
    params.delete("hash");
    const entries = [...params.entries()].sort((a, b) => a[0].localeCompare(b[0]));
    const dataCheckString = entries.map(([k, v]) => `${k}=${v}`).join("\n");

    const botToken = process.env.BOT_TOKEN || "";
    const secretKey = crypto.createHmac("sha256", "WebAppData").update(botToken).digest();
    const computedHash = crypto.createHmac("sha256", secretKey).update(dataCheckString).digest("hex");

    return computedHash === hash;
  } catch (err) {
    console.error("checkTelegramAuth error:", err);
    return false;
  }
}

// ------------------------------------------
// Session management helpers
// ------------------------------------------
const SESSION_COOKIE = "sid";
const SESSION_DAYS = 30; // keep session for 30 days

async function createSession(userId) {
  const token = uuidv4();
  const now = new Date();
  const expires = new Date(now.getTime() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await db.query(
    "INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES($1,$2,NOW(),$3)",
    [token, userId, expires]
  );
  return { token, expires };
}

async function getSession(token) {
  if (!token) return null;
  const r = await db.query("SELECT token, user_id, created_at, expires_at FROM sessions WHERE token=$1", [token]);
  if (r.rows.length === 0) return null;
  const session = r.rows[0];
  if (new Date(session.expires_at) < new Date()) {
    // expired — remove
    await db.query("DELETE FROM sessions WHERE token=$1", [token]);
    return null;
  }
  return session;
}

async function extendSession(token) {
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);
  await db.query("UPDATE sessions SET expires_at=$1 WHERE token=$2", [expires, token]);
  return expires;
}

function setSessionCookie(res, token, expires) {
  const secure = process.env.NODE_ENV === "production";
  res.cookie(SESSION_COOKIE, token, {
    httpOnly: true,
    secure,
    sameSite: "lax",
    expires
  });
}

function clearSessionCookie(res) {
  res.clearCookie(SESSION_COOKIE);
}

// ------------------------------------------
// Middleware: load session if cookie present
// attaches req.userId if valid
// ------------------------------------------
async function sessionMiddleware(req, res, next) {
  try {
    const token = req.cookies && req.cookies[SESSION_COOKIE];
    if (!token) return next();
    const session = await getSession(token);
    if (!session) {
      clearSessionCookie(res);
      return next();
    }
    // extend session on activity
    const newExp = await extendSession(token);
    setSessionCookie(res, token, newExp);
    req.userId = session.user_id;
    next();
  } catch (err) {
    console.error("sessionMiddleware error:", err);
    next();
  }
}

app.use(sessionMiddleware);

// ------------------------------------------
// Coinbase Websocket (price feed)
// ------------------------------------------
let currentPrice = 0;

function connectCoinbase() {
  const ws = new WebSocketClient("wss://ws-feed.exchange.coinbase.com");

  ws.on("open", () => {
    console.log("Coinbase ws open - subscribing to BTC-USD ticker");
    ws.send(JSON.stringify({ type: "subscribe", product_ids: ["BTC-USD"], channels: ["ticker"] }));
  });

  ws.on("message", (msg) => {
    try {
      const data = JSON.parse(msg);
      if (data.type === "ticker" && data.price) {
        currentPrice = parseFloat(data.price);
      }
    } catch (e) {}
  });

  ws.on("close", () => {
    console.log("Coinbase ws closed, reconnecting in 5s");
    setTimeout(connectCoinbase, 5000);
  });

  ws.on("error", (err) => {
    console.error("Coinbase ws error:", err);
  });
}
connectCoinbase();

// ------------------------------------------
// API: auth status - returns current user status based on session cookie
// ------------------------------------------
app.get("/auth/status", async (req, res) => {
  try {
    if (!req.userId) return res.json({ loggedIn: false });
    // fetch user and positions
    const u = await db.query("SELECT user_id, balance, updated_at FROM users WHERE user_id=$1", [req.userId]);
    const positions = await db.query("SELECT * FROM positions WHERE user_id=$1", [req.userId]);
    if (u.rows.length === 0) {
      // shouldn't happen but handle
      return res.json({ loggedIn: false });
    }
    return res.json({
      loggedIn: true,
      userId: u.rows[0].user_id,
      balance: Number(u.rows[0].balance),
      updated_at: u.rows[0].updated_at,
      positions: positions.rows
    });
  } catch (err) {
    console.error("auth/status error:", err);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ------------------------------------------
// API: auth/init - the client sends Telegram initData (string). We validate and create session.
// Body: { initData: "<signed string from tg WebApp>" }
// ------------------------------------------
app.post("/auth/init", async (req, res) => {
  try {
    const { initData } = req.body;
    if (!initData || typeof initData !== "string") {
      return res.status(400).json({ error: "NO_INIT_DATA" });
    }

    if (!checkTelegramAuth(initData)) {
      return res.status(403).json({ error: "INVALID_TG_AUTH" });
    }

    const params = new URLSearchParams(initData);
    const userJson = params.get("user") || params.get("user.id");
    // Telegram encodes user as JSON in 'user' param — parse safely
    let userId = null;
    try {
      if (params.has("user")) {
        // user is URL-encoded JSON
        const userStr = decodeURIComponent(params.get("user"));
        const userObj = JSON.parse(userStr);
        userId = String(userObj.id);
      } else if (params.has("user.id")) {
        userId = params.get("user.id");
      }
    } catch (e) {
      console.warn("Failed to parse user from initData", e);
    }

    if (!userId) return res.status(400).json({ error: "NO_USER_ID_IN_INIT" });

    // ensure user exists
    const existing = await db.query("SELECT user_id FROM users WHERE user_id=$1", [userId]);
    if (existing.rows.length === 0) {
      await db.query("INSERT INTO users(user_id, balance, updated_at) VALUES($1,$2,NOW())", [userId, 0]);
    }

    // create session token
    const { token, expires } = await createSession(userId);
    setSessionCookie(res, token, expires);

    // return user info
    const user = await db.query("SELECT user_id, balance FROM users WHERE user_id=$1", [userId]);
    const positions = await db.query("SELECT * FROM positions WHERE user_id=$1", [userId]);

    res.json({
      success: true,
      userId: user.rows[0].user_id,
      balance: Number(user.rows[0].balance),
      positions: positions.rows
    });
  } catch (err) {
    console.error("auth/init error:", err);
    res.status(500).json({ error: "SERVER_ERROR", details: err.message });
  }
});

// ------------------------------------------
// API: logout
// ------------------------------------------
app.post("/auth/logout", async (req, res) => {
  try {
    const token = req.cookies && req.cookies[SESSION_COOKIE];
    if (token) {
      await db.query("DELETE FROM sessions WHERE token=$1", [token]);
      clearSessionCookie(res);
    }
    res.json({ success: true });
  } catch (err) {
    console.error("auth/logout error:", err);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// ------------------------------------------
// API: price (public)
// ------------------------------------------
app.get("/api/price", (req, res) => {
  if (!currentPrice) return res.json({ error: "NO_PRICE_YET" });
  res.json({ price: currentPrice });
});

// ------------------------------------------
// Protected API: requires session (req.userId set by middleware)
// ------------------------------------------
function requireAuth(req, res, next) {
  if (!req.userId) return res.status(401).json({ error: "NOT_AUTHENTICATED" });
  next();
}

// init for client usage (returns balance+positions) - uses session
app.get("/api/init", requireAuth, async (req, res) => {
  try {
    const u = await db.query("SELECT user_id, balance FROM users WHERE user_id=$1", [req.userId]);
    const positions = await db.query("SELECT * FROM positions WHERE user_id=$1", [req.userId]);
    if (u.rows.length === 0) return res.status(404).json({ error: "NO_USER" });
    res.json({ balance: Number(u.rows[0].balance), positions: positions.rows });
  } catch (err) {
    console.error("api/init error:", err);
    res.status(500).json({ error: "SERVER_ERROR" });
  }
});

// Open order (session-based)
app.post("/api/order/open", requireAuth, async (req, res) => {
  try {
    const userId = req.userId;
    const { type, margin, leverage } = req.body;

    if (!currentPrice) return res.status(503).json({ error: "NO_PRICE_YET" });

    const userRes = await db.query("SELECT balance FROM users WHERE user_id=$1", [userId]);
    if (userRes.rows.length === 0) return res.status(404).json({ error: "NO_USER" });

    const balance = parseFloat(userRes.rows[0].balance);
    if (balance < margin) return res.status(400).json({ error: "LOW_BALANCE" });

    const fee = margin * leverage * 0.001;
    const newBalance = balance - (margin + fee);

    await db.query("UPDATE users SET balance=$1, updated_at=NOW() WHERE user_id=$2", [newBalance, userId]);

    const size = margin * leverage;
    const posRes = await db.query(
      `INSERT INTO positions(user_id, type, entry_price, margin, leverage, size)
       VALUES($1,$2,$3,$4,$5,$6) RETURNING *`,
      [userId, type, currentPrice, margin, leverage, size]
    );

    res.json({ position: posRes.rows[0], balance: newBalance });
  } catch (err) {
    console.error("api/order/open error:", err);
    res.status(500).json({ error: "SERVER_ERROR", details: err.message });
  }
});

// Close order (session-based)
app.post("/api/order/close", requireAuth, async (req, res) => {
  try {
    const userId = req.userId;
    const { positionId } = req.body;

    const posRes = await db.query("SELECT * FROM positions WHERE id=$1 AND user_id=$2", [positionId, userId]);
    if (posRes.rows.length === 0) return res.status(404).json({ error: "NOT_FOUND" });

    const p = posRes.rows[0];
    let pnl = 0;
    if (p.type === "LONG")
      pnl = ((currentPrice - p.entry_price) / p.entry_price) * p.size;
    else
      pnl = ((p.entry_price - currentPrice) / p.entry_price) * p.size;

    const userRes = await db.query("SELECT balance FROM users WHERE user_id=$1", [userId]);
    const newBalance = parseFloat(userRes.rows[0].balance) + parseFloat(p.margin) + pnl;

    await db.query("UPDATE users SET balance=$1, updated_at=NOW() WHERE user_id=$2", [newBalance, userId]);
    await db.query("DELETE FROM positions WHERE id=$1", [positionId]);

    res.json({ pnl, balance: newBalance });
  } catch (err) {
    console.error("api/order/close err:", err);
    res.status(500).json({ error: "SERVER_ERROR", details: err.message });
  }
});

// ------------------------------------------
// Serve single-page app fallback (optional)
// ------------------------------------------
app.get("*", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

// ------------------------------------------
// Start server
// ------------------------------------------
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
