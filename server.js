// server.js — Trading Bot Backend with TP/SL System
import express from 'express';
import http from 'http';
import { WebSocketServer, WebSocket } from 'ws';
import pg from 'pg';
import cors from 'cors';
import crypto from 'crypto';

const { Pool } = pg;

const app = express();
app.use(cors());
app.use(express.json());

const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const BOT_TOKEN = process.env.BOT_TOKEN || '';
const COMMISSION_RATE = 0.0003;
const REFERRAL_BONUS = 50;
const INITIAL_BALANCE = 1000;
const DAILY_AD_LIMIT = 5;
const AD_REWARD_VP = 1;
const MAX_TPSL_PER_TYPE = 3;

// ==================== DATABASE INIT ====================

async function initDB() {
  const client = await pool.connect();
  try {
    await client.query(`
      CREATE TABLE IF NOT EXISTS users (
        user_id BIGINT PRIMARY KEY,
        first_name TEXT DEFAULT '',
        username TEXT DEFAULT '',
        photo_url TEXT DEFAULT '',
        balance NUMERIC(20,8) DEFAULT ${INITIAL_BALANCE},
        referred_by BIGINT DEFAULT NULL,
        created_at TIMESTAMPTZ DEFAULT NOW(),
        ad_views_count INT DEFAULT 0,
        daily_ad_views INT DEFAULT 0,
        daily_ad_date DATE DEFAULT CURRENT_DATE,
        daily_ad_limit INT DEFAULT ${DAILY_AD_LIMIT}
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS positions (
        id SERIAL PRIMARY KEY,
        user_id BIGINT REFERENCES users(user_id),
        pair TEXT NOT NULL,
        type TEXT NOT NULL,
        size NUMERIC(20,8) NOT NULL,
        margin NUMERIC(20,8) NOT NULL,
        leverage INT NOT NULL,
        entry_price NUMERIC(20,8) NOT NULL,
        opened_at TIMESTAMPTZ DEFAULT NOW(),
        status TEXT DEFAULT 'open'
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS trades_history (
        id SERIAL PRIMARY KEY,
        user_id BIGINT REFERENCES users(user_id),
        pair TEXT NOT NULL,
        type TEXT NOT NULL,
        size NUMERIC(20,8),
        margin NUMERIC(20,8),
        leverage INT,
        entry_price NUMERIC(20,8),
        exit_price NUMERIC(20,8),
        pnl NUMERIC(20,8),
        commission NUMERIC(20,8) DEFAULT 0,
        opened_at TIMESTAMPTZ,
        closed_at TIMESTAMPTZ DEFAULT NOW()
      );
    `);

    await client.query(`
      CREATE TABLE IF NOT EXISTS tpsl_orders (
        id SERIAL PRIMARY KEY,
        user_id BIGINT REFERENCES users(user_id),
        position_id INT REFERENCES positions(id) ON DELETE CASCADE,
        order_type TEXT NOT NULL CHECK (order_type IN ('TP', 'SL')),
        trigger_price NUMERIC(20,8) NOT NULL,
        size_percent NUMERIC(10,4) NOT NULL,
        status TEXT DEFAULT 'active' CHECK (status IN ('active', 'triggered', 'cancelled')),
        created_at TIMESTAMPTZ DEFAULT NOW(),
        triggered_at TIMESTAMPTZ DEFAULT NULL
      );
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_tpsl_active 
      ON tpsl_orders (position_id, status) 
      WHERE status = 'active';
    `);

    await client.query(`
      CREATE INDEX IF NOT EXISTS idx_tpsl_user 
      ON tpsl_orders (user_id, status) 
      WHERE status = 'active';
    `);

    const safeAdd = async (table, column, type) => {
      try { await client.query(`ALTER TABLE ${table} ADD COLUMN IF NOT EXISTS ${column} ${type}`); } catch(e) {}
    };
    await safeAdd('users', 'ad_views_count', 'INT DEFAULT 0');
    await safeAdd('users', 'daily_ad_views', 'INT DEFAULT 0');
    await safeAdd('users', 'daily_ad_date', 'DATE DEFAULT CURRENT_DATE');
    await safeAdd('users', 'daily_ad_limit', `INT DEFAULT ${DAILY_AD_LIMIT}`);
    await safeAdd('trades_history', 'commission', 'NUMERIC(20,8) DEFAULT 0');

    console.log("[DB] All tables initialized (including tpsl_orders)");
  } finally {
    client.release();
  }
}

// ==================== AUTH ====================

function verifyTelegramAuth(initData) {
  if (!BOT_TOKEN || !initData) return null;
  try {
    const params = new URLSearchParams(initData);
    const hash = params.get('hash');
    if (!hash) return null;
    params.delete('hash');
    const dataCheckString = Array.from(params.entries()).sort(([a], [b]) => a.localeCompare(b)).map(([k, v]) => `${k}=${v}`).join('\n');
    const secretKey = crypto.createHmac('sha256', 'WebAppData').update(BOT_TOKEN).digest();
    const checkHash = crypto.createHmac('sha256', secretKey).update(dataCheckString).digest('hex');
    if (checkHash !== hash) return null;
    const userStr = params.get('user');
    return userStr ? JSON.parse(userStr) : null;
  } catch (e) { return null; }
}

// ==================== INIT API ====================

app.post('/api/init', async (req, res) => {
  try {
    const { initData } = req.body;
    let tgUser = verifyTelegramAuth(initData);
    if (!tgUser && initData) {
      try {
        const p = new URLSearchParams(initData);
        const u = p.get('user');
        if (u) tgUser = JSON.parse(u);
      } catch(e) {}
    }
    if (!tgUser) {
      tgUser = { id: 0, first_name: "Demo", username: "demo" };
    }
    const userId = tgUser.id;
    const firstName = tgUser.first_name || '';
    const username = tgUser.username || '';
    const photoUrl = tgUser.photo_url || '';

    let referredBy = null;
    if (initData) {
      try {
        const p = new URLSearchParams(initData);
        const sp = p.get('start_param');
        if (sp && sp.startsWith('ref_')) {
          const refId = parseInt(sp.replace('ref_', ''));
          if (!isNaN(refId) && refId !== userId) referredBy = refId;
        }
      } catch(e) {}
    }

    const existing = await pool.query('SELECT * FROM users WHERE user_id = $1', [userId]);
    if (existing.rows.length === 0) {
      await pool.query(
        `INSERT INTO users (user_id, first_name, username, photo_url, balance, referred_by) 
         VALUES ($1, $2, $3, $4, $5, $6)`,
        [userId, firstName, username, photoUrl, INITIAL_BALANCE, referredBy]
      );
      if (referredBy) {
        const refUser = await pool.query('SELECT user_id FROM users WHERE user_id = $1', [referredBy]);
        if (refUser.rows.length > 0) {
          await pool.query('UPDATE users SET balance = balance + $1 WHERE user_id = $2', [REFERRAL_BONUS, referredBy]);
        }
      }
    } else {
      await pool.query(
        'UPDATE users SET first_name = $2, username = $3, photo_url = COALESCE(NULLIF($4, \'\'), photo_url) WHERE user_id = $1',
        [userId, firstName, username, photoUrl]
      );
    }

    const user = (await pool.query('SELECT * FROM users WHERE user_id = $1', [userId])).rows[0];

    const today = new Date().toISOString().split('T')[0];
    if (user.daily_ad_date !== today) {
      await pool.query('UPDATE users SET daily_ad_views = 0, daily_ad_date = $2 WHERE user_id = $1', [userId, today]);
      user.daily_ad_views = 0;
      user.daily_ad_date = today;
    }

    const positions = (await pool.query(
      'SELECT * FROM positions WHERE user_id = $1 AND status = $2 ORDER BY opened_at DESC',
      [userId, 'open']
    )).rows;

    res.json({ ok: true, user, positions });
  } catch (e) {
    console.error('[INIT ERROR]', e);
    res.json({ ok: false, error: 'Server error' });
  }
});

// ==================== ORDER OPEN / CLOSE ====================

app.post('/api/order/open', async (req, res) => {
  try {
    const { userId, pair, type, size, leverage, entryPrice } = req.body;
    if (!userId || !pair || !type || !size || !leverage || !entryPrice) return res.json({ ok: false, error: 'Missing fields' });
    
    const margin = size / leverage;
    const commission = size * COMMISSION_RATE;
    const totalCost = margin + commission;

    const user = (await pool.query('SELECT balance FROM users WHERE user_id = $1', [userId])).rows[0];
    if (!user || user.balance < totalCost) return res.json({ ok: false, error: 'Insufficient balance' });

    await pool.query('UPDATE users SET balance = balance - $1 WHERE user_id = $2', [totalCost, userId]);

    const result = await pool.query(
      `INSERT INTO positions (user_id, pair, type, size, margin, leverage, entry_price) 
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *`,
      [userId, pair, type.toUpperCase(), size, margin, leverage, entryPrice]
    );

    const newBalance = (await pool.query('SELECT balance FROM users WHERE user_id = $1', [userId])).rows[0].balance;

    res.json({ ok: true, position: result.rows[0], newBalance: Number(newBalance) });
  } catch (e) {
    console.error('[OPEN ERROR]', e);
    res.json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/order/close', async (req, res) => {
  try {
    const { userId, positionId, closePrice } = req.body;
    if (!userId || !positionId || !closePrice) return res.json({ ok: false, error: 'Missing fields' });

    const pos = (await pool.query(
      'SELECT * FROM positions WHERE id = $1 AND user_id = $2 AND status = $3',
      [positionId, userId, 'open']
    )).rows[0];
    if (!pos) return res.json({ ok: false, error: 'Position not found' });

    const size = Number(pos.size), entry = Number(pos.entry_price), margin = Number(pos.margin);
    let diff = (closePrice - entry) / entry;
    if (pos.type === 'SHORT') diff = -diff;
    const pnl = diff * size;
    const commission = size * COMMISSION_RATE;
    const netPnl = pnl - commission;
    const returnAmount = margin + netPnl;

    await pool.query(
      "UPDATE tpsl_orders SET status = 'cancelled' WHERE position_id = $1 AND status = 'active'",
      [positionId]
    );

    await pool.query("UPDATE positions SET status = 'closed' WHERE id = $1", [positionId]);

    if (returnAmount > 0) {
      await pool.query('UPDATE users SET balance = balance + $1 WHERE user_id = $2', [returnAmount, userId]);
    }

    await pool.query(
      `INSERT INTO trades_history (user_id, pair, type, size, margin, leverage, entry_price, exit_price, pnl, commission, opened_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [userId, pos.pair, pos.type, size, margin, pos.leverage, entry, closePrice, netPnl, commission, pos.opened_at]
    );

    const newBalance = (await pool.query('SELECT balance FROM users WHERE user_id = $1', [userId])).rows[0].balance;
    res.json({ ok: true, pnl: netPnl, newBalance: Number(newBalance) });
  } catch (e) {
    console.error('[CLOSE ERROR]', e);
    res.json({ ok: false, error: 'Server error' });
  }
});

// ==================== TP/SL API ====================

app.post('/api/tpsl/create', async (req, res) => {
  try {
    const { userId, positionId, orderType, triggerPrice, sizePercent } = req.body;
    
    if (!userId || !positionId || !orderType || !triggerPrice || !sizePercent) {
      return res.json({ ok: false, error: 'Missing required fields' });
    }

    if (!['TP', 'SL'].includes(orderType)) {
      return res.json({ ok: false, error: 'Invalid order type' });
    }

    if (triggerPrice <= 0) {
      return res.json({ ok: false, error: 'Invalid trigger price' });
    }

    if (sizePercent <= 0 || sizePercent > 100) {
      return res.json({ ok: false, error: 'Size percent must be between 1 and 100' });
    }

    const pos = (await pool.query(
      'SELECT * FROM positions WHERE id = $1 AND user_id = $2 AND status = $3',
      [positionId, userId, 'open']
    )).rows[0];

    if (!pos) {
      return res.json({ ok: false, error: 'Position not found or already closed' });
    }

    const existingCount = (await pool.query(
      "SELECT COUNT(*) as cnt FROM tpsl_orders WHERE position_id = $1 AND order_type = $2 AND status = 'active'",
      [positionId, orderType]
    )).rows[0].cnt;

    if (Number(existingCount) >= MAX_TPSL_PER_TYPE) {
      return res.json({ ok: false, error: `Maximum ${MAX_TPSL_PER_TYPE} ${orderType} orders per position` });
    }

    const usedPercent = (await pool.query(
      "SELECT COALESCE(SUM(size_percent), 0) as total FROM tpsl_orders WHERE position_id = $1 AND order_type = $2 AND status = 'active'",
      [positionId, orderType]
    )).rows[0].total;

    const available = 100 - Number(usedPercent);
    if (sizePercent > available + 0.01) {
      return res.json({ ok: false, error: `Only ${available.toFixed(0)}% volume available for ${orderType}` });
    }

    const type = pos.type.toUpperCase();
    if (orderType === 'TP') {
      if (type === 'LONG' && triggerPrice <= Number(pos.entry_price)) {
        return res.json({ ok: false, error: 'TP must be above entry for LONG' });
      }
      if (type === 'SHORT' && triggerPrice >= Number(pos.entry_price)) {
        return res.json({ ok: false, error: 'TP must be below entry for SHORT' });
      }
    }

    const result = await pool.query(
      `INSERT INTO tpsl_orders (user_id, position_id, order_type, trigger_price, size_percent)
       VALUES ($1, $2, $3, $4, $5) RETURNING *`,
      [userId, positionId, orderType, triggerPrice, sizePercent]
    );

    console.log(`[TPSL] Created ${orderType} for position ${positionId}: price=${triggerPrice}, size=${sizePercent}%`);

    res.json({ ok: true, order: result.rows[0] });
  } catch (e) {
    console.error('[TPSL CREATE ERROR]', e);
    res.json({ ok: false, error: 'Server error' });
  }
});

app.post('/api/tpsl/delete', async (req, res) => {
  try {
    const { userId, orderId } = req.body;
    if (!userId || !orderId) return res.json({ ok: false, error: 'Missing fields' });

    const result = await pool.query(
      "UPDATE tpsl_orders SET status = 'cancelled' WHERE id = $1 AND user_id = $2 AND status = 'active' RETURNING *",
      [orderId, userId]
    );

    if (result.rows.length === 0) {
      return res.json({ ok: false, error: 'Order not found or already cancelled' });
    }

    console.log(`[TPSL] Deleted order ${orderId} for user ${userId}`);

    res.json({ ok: true });
  } catch (e) {
    console.error('[TPSL DELETE ERROR]', e);
    res.json({ ok: false, error: 'Server error' });
  }
});

app.get('/api/tpsl/list', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.json({ ok: false, error: 'Missing userId' });

    const orders = (await pool.query(
      "SELECT * FROM tpsl_orders WHERE user_id = $1 AND status = 'active' ORDER BY created_at DESC",
      [userId]
    )).rows;

    res.json({ ok: true, orders });
  } catch (e) {
    console.error('[TPSL LIST ERROR]', e);
    res.json({ ok: false, error: 'Server error' });
  }
});

// ==================== TP/SL TRIGGER ENGINE ====================

async function checkTpSlTriggers(pair, currentPrice) {
  if (!currentPrice || currentPrice <= 0) return;

  const normalizedPair = pair.replace('/', '-').toUpperCase();

  try {
    const orders = (await pool.query(`
      SELECT t.*, p.type as pos_type, p.entry_price, p.size as pos_size, 
             p.margin as pos_margin, p.leverage as pos_leverage, p.user_id as pos_user_id,
             p.pair as pos_pair
      FROM tpsl_orders t
      JOIN positions p ON t.position_id = p.id
      WHERE t.status = 'active' 
        AND p.status = 'open'
        AND UPPER(REPLACE(p.pair, '/', '-')) = $1
    `, [normalizedPair])).rows;

    if (orders.length === 0) return;

    for (const order of orders) {
      const triggerPrice = Number(order.trigger_price);
      const posType = order.pos_type.toUpperCase();
      let triggered = false;

      if (order.order_type === 'TP') {
        if (posType === 'LONG' && currentPrice >= triggerPrice) triggered = true;
        if (posType === 'SHORT' && currentPrice <= triggerPrice) triggered = true;
      } else if (order.order_type === 'SL') {
        if (posType === 'LONG' && currentPrice <= triggerPrice) triggered = true;
        if (posType === 'SHORT' && currentPrice >= triggerPrice) triggered = true;
      }

      if (triggered) {
        await executeTpSlOrder(order, currentPrice);
      }
    }
  } catch (e) {
    console.error('[TPSL CHECK ERROR]', e);
  }
}

async function executeTpSlOrder(order, currentPrice) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');

    const updateResult = await client.query(
      "UPDATE tpsl_orders SET status = 'triggered', triggered_at = NOW() WHERE id = $1 AND status = 'active' RETURNING *",
      [order.id]
    );

    if (updateResult.rows.length === 0) {
      await client.query('ROLLBACK');
      return;
    }

    const positionId = order.position_id;
    const userId = order.pos_user_id;
    const sizePercent = Number(order.size_percent);
    const entryPrice = Number(order.entry_price);
    const totalSize = Number(order.pos_size);
    const totalMargin = Number(order.pos_margin);
    const posType = order.pos_type.toUpperCase();
    const posPair = order.pos_pair;

    const orderSize = totalSize * (sizePercent / 100);
    const orderMargin = totalMargin * (sizePercent / 100);

    let diff = (currentPrice - entryPrice) / entryPrice;
    if (posType === 'SHORT') diff = -diff;
    const pnl = diff * orderSize;
    const commission = orderSize * COMMISSION_RATE;
    const netPnl = pnl - commission;
    const returnAmount = orderMargin + netPnl;

    const allTpSlTotal = (await client.query(
      "SELECT COALESCE(SUM(size_percent), 0) as total FROM tpsl_orders WHERE position_id = $1 AND status = 'triggered'",
      [positionId]
    )).rows[0].total;

    const isFullClose = Number(allTpSlTotal) >= 99.99;

    if (isFullClose) {
      await client.query("UPDATE positions SET status = 'closed' WHERE id = $1", [positionId]);
      
      await client.query(
        "UPDATE tpsl_orders SET status = 'cancelled' WHERE position_id = $1 AND status = 'active'",
        [positionId]
      );

      const remainingMargin = totalMargin - orderMargin;
      const totalReturn = returnAmount + remainingMargin;
      
      if (totalReturn > 0) {
        await client.query('UPDATE users SET balance = balance + $1 WHERE user_id = $2', [totalReturn, userId]);
      }
    } else {
      const newSize = totalSize - orderSize;
      const newMargin = totalMargin - orderMargin;

      await client.query(
        'UPDATE positions SET size = $1, margin = $2 WHERE id = $3',
        [newSize, newMargin, positionId]
      );

      if (returnAmount > 0) {
        await client.query('UPDATE users SET balance = balance + $1 WHERE user_id = $2', [returnAmount, userId]);
      }
    }

    await client.query(
      `INSERT INTO trades_history (user_id, pair, type, size, margin, leverage, entry_price, exit_price, pnl, commission, opened_at)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())`,
      [userId, posPair, posType, orderSize, orderMargin, order.pos_leverage, entryPrice, currentPrice, netPnl, commission]
    );

    await client.query('COMMIT');

    console.log(`[TPSL TRIGGERED] ${order.order_type} for position ${positionId}: price=${currentPrice}, pnl=${netPnl.toFixed(4)}, size=${sizePercent}%, fullClose=${isFullClose}`);

    notifyUserTpSl(userId, {
      type: 'tpsl_triggered',
      orderId: order.id,
      positionId: positionId,
      orderType: order.order_type,
      triggerPrice: currentPrice,
      sizePercent: sizePercent,
      pnl: netPnl,
      isFullClose: isFullClose
    });

  } catch (e) {
    await client.query('ROLLBACK');
    console.error('[TPSL EXECUTE ERROR]', e);
  } finally {
    client.release();
  }
}

// ==================== LIQUIDATION ENGINE ====================

async function checkLiquidations(pair, currentPrice) {
  if (!currentPrice || currentPrice <= 0) return;
  const normalizedPair = pair.replace('/', '-').toUpperCase();

  try {
    const positions = (await pool.query(`
      SELECT * FROM positions WHERE status = 'open' AND UPPER(REPLACE(pair, '/', '-')) = $1
    `, [normalizedPair])).rows;

    for (const pos of positions) {
      const entry = Number(pos.entry_price);
      const size = Number(pos.size);
      const margin = Number(pos.margin);
      const type = pos.type.toUpperCase();

      const liqDist = (margin * 0.90) / size * entry;
      const liqPrice = type === 'LONG' ? entry - liqDist : entry + liqDist;

      let liquidated = false;
      if (type === 'LONG' && currentPrice <= liqPrice) liquidated = true;
      if (type === 'SHORT' && currentPrice >= liqPrice) liquidated = true;

      if (liquidated) {
        await pool.query(
          "UPDATE tpsl_orders SET status = 'cancelled' WHERE position_id = $1 AND status = 'active'",
          [pos.id]
        );

        await pool.query("UPDATE positions SET status = 'liquidated' WHERE id = $1", [pos.id]);

        const liqPnl = -margin;
        await pool.query(
          `INSERT INTO trades_history (user_id, pair, type, size, margin, leverage, entry_price, exit_price, pnl, commission, opened_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 0, $10)`,
          [pos.user_id, pos.pair, pos.type, size, margin, pos.leverage, entry, currentPrice, liqPnl, pos.opened_at]
        );

        console.log(`[LIQUIDATION] Position ${pos.id} liquidated at ${currentPrice}`);
      }
    }
  } catch (e) {
    console.error('[LIQUIDATION ERROR]', e);
  }
}

// ==================== AD SYSTEM ====================

app.get('/api/user/ad-stats', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.json({ ok: false, error: 'Missing userId' });

    const today = new Date().toISOString().split('T')[0];
    
    await pool.query(
      "UPDATE users SET daily_ad_views = 0, daily_ad_date = $2 WHERE user_id = $1 AND daily_ad_date != $2",
      [userId, today]
    );

    await pool.query(
      `UPDATE users SET 
        ad_views_count = ad_views_count + 1,
        daily_ad_views = daily_ad_views + 1,
        balance = balance + $2
       WHERE user_id = $1`,
      [userId, AD_REWARD_VP]
    );

    const user = (await pool.query('SELECT * FROM users WHERE user_id = $1', [userId])).rows[0];
    
    res.json({
      ok: true,
      adViewsCount: user.ad_views_count,
      dailyAdViews: user.daily_ad_views,
      dailyAdLimit: user.daily_ad_limit || DAILY_AD_LIMIT,
      balance: Number(user.balance)
    });
  } catch (e) {
    console.error('[AD STATS ERROR]', e);
    res.json({ ok: false, error: 'Server error' });
  }
});

// ==================== HISTORY & REFERRALS ====================

app.get('/api/user/history', async (req, res) => {
  try {
    const { userId } = req.query;
    const history = (await pool.query(
      'SELECT * FROM trades_history WHERE user_id = $1 ORDER BY closed_at DESC LIMIT 100',
      [userId]
    )).rows;
    res.json({ ok: true, history });
  } catch (e) { res.json({ ok: false, error: 'Server error' }); }
});

app.get('/api/user/referrals', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.json({ ok: false, error: 'Missing userId' });

    const botUsername = process.env.BOT_USERNAME || 'YourBot';
    const miniAppUrl = process.env.MINI_APP_URL || '';
    const referralLink = miniAppUrl 
      ? `${miniAppUrl}?startapp=ref_${userId}`
      : `https://t.me/${botUsername}?startapp=ref_${userId}`;

    const invited = (await pool.query(
      'SELECT user_id, first_name, username, photo_url, created_at FROM users WHERE referred_by = $1 ORDER BY created_at DESC',
      [userId]
    )).rows;

    res.json({ ok: true, referralLink, invitedCount: invited.length, invited });
  } catch (e) { res.json({ ok: false, error: 'Server error' }); }
});

// ==================== PRICE SOURCES ====================

const SUPPORTED_PAIRS = {
  'BTC-USD': { coinbase: 'BTC-USD', binance: 'btcusdt', display: 'BTC-USD' },
  'ETH-USD': { coinbase: 'ETH-USD', binance: 'ethusdt', display: 'ETH-USD' },
};

let latestPrices = {};

// ==================== WEBSOCKET CLIENTS ====================

function notifyUserTpSl(userId, message) {
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN && ws._userId === String(userId)) {
      try { ws.send(JSON.stringify(message)); } catch(e) {}
    }
  });
}

// ==================== COINBASE WS ====================

let coinbaseWs = null;
let coinbaseReconnectTimer = null;

function connectCoinbase() {
  if (coinbaseWs) { try { coinbaseWs.close(); } catch(e) {} }
  
  const pairs = Object.values(SUPPORTED_PAIRS).map(p => p.coinbase);
  
  coinbaseWs = new WebSocket('wss://ws-feed.exchange.coinbase.com');

  coinbaseWs.onopen = () => {
    console.log('[COINBASE] Connected');
    coinbaseWs.send(JSON.stringify({
      type: 'subscribe',
      product_ids: pairs,
      channels: ['ticker', 'level2_batch']
    }));
  };

  coinbaseWs.onmessage = (evt) => {
    try {
      const msg = JSON.parse(evt.data);
      if (msg.type === 'ticker' && msg.product_id && msg.price) {
        const pair = msg.product_id;
        const price = Number(msg.price);
        latestPrices[pair] = price;

        broadcast({ type: 'price', pair, price });

        checkTpSlTriggers(pair, price);
        checkLiquidations(pair, price);
      }

      if (msg.type === 'l2update' && msg.product_id) {
        const pair = msg.product_id;
        handleOrderBookUpdate(pair, msg);
      }
    } catch(e) {}
  };

  coinbaseWs.onclose = () => {
    console.log('[COINBASE] Disconnected, reconnecting...');
    coinbaseReconnectTimer = setTimeout(connectCoinbase, 3000);
  };

  coinbaseWs.onerror = (e) => {
    console.error('[COINBASE ERROR]', e.message);
  };
}

// ==================== ORDER BOOK STATE ====================

const orderBooks = {};

function handleOrderBookUpdate(pair, msg) {
  if (!orderBooks[pair]) orderBooks[pair] = { bids: new Map(), asks: new Map() };
  const book = orderBooks[pair];

  if (msg.changes) {
    msg.changes.forEach(([side, price, size]) => {
      const p = Number(price), s = Number(size);
      const map = side === 'buy' ? book.bids : book.asks;
      if (s === 0) map.delete(p);
      else map.set(p, s);
    });
  }

  const bids = Array.from(book.bids.entries())
    .map(([price, size]) => ({ price, size }))
    .sort((a, b) => b.price - a.price)
    .slice(0, 15);

  const asks = Array.from(book.asks.entries())
    .map(([price, size]) => ({ price, size }))
    .sort((a, b) => a.price - b.price)
    .slice(0, 15);

  broadcastToPair(pair, { type: 'orderBook', pair, buy: bids, sell: asks });
}

// ==================== CANDLE AGGREGATION ====================

const candleStore = {};
const TIMEFRAMES = [60, 300, 900, 3600, 14400, 86400];

function getCandleKey(pair, timeframe) { return `${pair}_${timeframe}`; }

function updateCandle(pair, price, timestamp) {
  TIMEFRAMES.forEach(tf => {
    const key = getCandleKey(pair, tf);
    if (!candleStore[key]) candleStore[key] = [];
    
    const candleTime = Math.floor(timestamp / tf) * tf;
    const candles = candleStore[key];
    const last = candles.length > 0 ? candles[candles.length - 1] : null;

    if (last && last.time === candleTime) {
      last.high = Math.max(last.high, price);
      last.low = Math.min(last.low, price);
      last.close = price;
      last.volume = (last.volume || 0) + Math.random() * 0.1;
    } else {
      candles.push({
        time: candleTime,
        open: price,
        high: price,
        low: price,
        close: price,
        volume: Math.random() * 0.5
      });
      if (candles.length > 2000) candles.splice(0, candles.length - 2000);
    }
  });
}

// ==================== HISTORY FETCH ====================

async function fetchCandleHistory(pair, timeframe, limit = 300) {
  const pairConfig = SUPPORTED_PAIRS[pair];
  if (!pairConfig) return [];

  try {
    const granularity = timeframe;
    const end = new Date().toISOString();
    const start = new Date(Date.now() - timeframe * limit * 1000).toISOString();
    
    const url = `https://api.exchange.coinbase.com/products/${pairConfig.coinbase}/candles?granularity=${granularity}&start=${start}&end=${end}`;
    const response = await fetch(url);
    const data = await response.json();

    if (Array.isArray(data) && data.length > 0) {
      return data.map(c => ({
        time: c[0],
        low: c[1],
        high: c[2],
        open: c[3],
        close: c[4],
        volume: c[5]
      })).sort((a, b) => a.time - b.time);
    }
  } catch (e) {
    console.error(`[HISTORY] Coinbase error for ${pair}:`, e.message);
  }

  try {
    const binanceSymbol = pairConfig.binance;
    const intervalMap = { 60: '1m', 300: '5m', 900: '15m', 3600: '1h', 14400: '4h', 86400: '1d' };
    const interval = intervalMap[timeframe] || '1m';
    
    const url = `https://api.binance.com/api/v3/klines?symbol=${binanceSymbol.toUpperCase()}&interval=${interval}&limit=${limit}`;
    const response = await fetch(url);
    const data = await response.json();

    if (Array.isArray(data)) {
      return data.map(c => ({
        time: Math.floor(c[0] / 1000),
        open: Number(c[1]),
        high: Number(c[2]),
        low: Number(c[3]),
        close: Number(c[4]),
        volume: Number(c[5])
      }));
    }
  } catch (e) {
    console.error(`[HISTORY] Binance error for ${pair}:`, e.message);
  }

  return [];
}

async function fetchMoreHistory(pair, timeframe, until, limit = 200) {
  const pairConfig = SUPPORTED_PAIRS[pair];
  if (!pairConfig) return [];

  try {
    const endTime = until;
    const startTime = endTime - (timeframe * limit);
    const granularity = timeframe;

    const url = `https://api.exchange.coinbase.com/products/${pairConfig.coinbase}/candles?granularity=${granularity}&start=${new Date(startTime * 1000).toISOString()}&end=${new Date(endTime * 1000).toISOString()}`;
    const response = await fetch(url);
    const data = await response.json();

    if (Array.isArray(data) && data.length > 0) {
      return data.map(c => ({
        time: c[0], low: c[1], high: c[2], open: c[3], close: c[4], volume: c[5]
      })).sort((a, b) => a.time - b.time);
    }
  } catch (e) {
    console.error(`[MORE HISTORY] Coinbase error:`, e.message);
  }

  try {
    const binanceSymbol = pairConfig.binance;
    const intervalMap = { 60: '1m', 300: '5m', 900: '15m', 3600: '1h', 14400: '4h', 86400: '1d' };
    const interval = intervalMap[timeframe] || '1m';
    const endMs = until * 1000;
    
    const url = `https://api.binance.com/api/v3/klines?symbol=${binanceSymbol.toUpperCase()}&interval=${interval}&endTime=${endMs}&limit=${limit}`;
    const response = await fetch(url);
    const data = await response.json();

    if (Array.isArray(data)) {
      return data.map(c => ({
        time: Math.floor(c[0] / 1000), open: Number(c[1]), high: Number(c[2]),
        low: Number(c[3]), close: Number(c[4]), volume: Number(c[5])
      }));
    }
  } catch (e) {
    console.error(`[MORE HISTORY] Binance error:`, e.message);
  }

  return [];
}

// ==================== TRADES FETCH ====================

async function fetchRecentTrades(pair) {
  const pairConfig = SUPPORTED_PAIRS[pair];
  if (!pairConfig) return [];

  try {
    const url = `https://api.exchange.coinbase.com/products/${pairConfig.coinbase}/trades?limit=20`;
    const response = await fetch(url);
    const data = await response.json();
    if (Array.isArray(data)) {
      return data.map(t => ({
        price: Number(t.price),
        size: Number(t.size),
        side: t.side,
        time: new Date(t.time).getTime()
      }));
    }
  } catch(e) {}
  return [];
}

// ==================== WS BROADCAST ====================

function broadcast(data) {
  const msg = JSON.stringify(data);
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN) {
      try { ws.send(msg); } catch(e) {}
    }
  });
}

function broadcastToPair(pair, data) {
  const msg = JSON.stringify(data);
  const normalizedPair = pair.replace('/', '-').toUpperCase();
  wss.clients.forEach(ws => {
    if (ws.readyState === WebSocket.OPEN && ws._subscribedPair === normalizedPair) {
      try { ws.send(msg); } catch(e) {}
    }
  });
}

// ==================== WS CONNECTION HANDLER ====================

wss.on('connection', (ws) => {
  ws._subscribedPair = 'BTC-USD';
  ws._subscribedTimeframe = 60;
  ws._userId = null;

  ws.on('message', async (data) => {
    try {
      const msg = JSON.parse(data);

      if (msg.userId) {
        ws._userId = String(msg.userId);
      }

      if (msg.type === 'subscribe') {
        const pair = (msg.pair || 'BTC-USD').replace('/', '-').toUpperCase();
        const tf = Number(msg.timeframe) || 60;
        ws._subscribedPair = pair;
        ws._subscribedTimeframe = tf;

        const candles = await fetchCandleHistory(pair, tf);
        if (candles.length > 0) {
          ws.send(JSON.stringify({ type: 'history', pair, timeframe: tf, data: candles }));
        }

        if (latestPrices[pair]) {
          ws.send(JSON.stringify({ type: 'price', pair, price: latestPrices[pair] }));
        }

        if (orderBooks[pair]) {
          const book = orderBooks[pair];
          const bids = Array.from(book.bids.entries()).map(([p, s]) => ({ price: p, size: s })).sort((a, b) => b.price - a.price).slice(0, 15);
          const asks = Array.from(book.asks.entries()).map(([p, s]) => ({ price: p, size: s })).sort((a, b) => a.price - b.price).slice(0, 15);
          ws.send(JSON.stringify({ type: 'orderBook', pair, buy: bids, sell: asks }));
        }

        const trades = await fetchRecentTrades(pair);
        if (trades.length > 0) {
          ws.send(JSON.stringify({ type: 'trades', pair, trades }));
        }
      }

      if (msg.type === 'loadMore') {
        const pair = (msg.pair || 'BTC-USD').replace('/', '-').toUpperCase();
        const tf = Number(msg.timeframe) || 60;
        const until = Number(msg.until);

        if (until) {
          const moreCandles = await fetchMoreHistory(pair, tf, until);
          ws.send(JSON.stringify({ type: 'moreHistory', pair, timeframe: tf, data: moreCandles }));
        }
      }

    } catch(e) {}
  });
});

// ==================== PERIODIC TASKS ====================

setInterval(async () => {
  for (const pair of Object.keys(SUPPORTED_PAIRS)) {
    try {
      const trades = await fetchRecentTrades(pair);
      if (trades.length > 0) broadcastToPair(pair, { type: 'trades', pair, trades });
    } catch(e) {}
  }
}, 5000);

// ==================== START ====================

const PORT = process.env.PORT || 3000;

initDB().then(() => {
  connectCoinbase();
  
  server.listen(PORT, () => {
    console.log(`[SERVER] Running on port ${PORT}`);
    console.log(`[SERVER] TP/SL system enabled (max ${MAX_TPSL_PER_TYPE} per type)`);
  });
}).catch(e => {
  console.error('[FATAL]', e);
  process.exit(1);
});
