const express = require('express');
const http = require('http');
// Используем 'ws' как клиент для Coinbase, но не как сервер для WebApp
const WebSocketClient = require('ws'); 
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors()); 
app.use(express.json());

// === Раздача статики ===
// Сервер будет раздавать index.html и другие файлы из папки 'public'
app.use(express.static(path.join(__dirname, 'public'))); 
// =========================

const server = http.createServer(app);
// WebSocket Server (WSS) удален, чтобы избежать конфликтов и проблем с проксированием.

// === ХРАНИЛИЩЕ (В ПАМЯТИ) ===
const users = {}; 
let currentPrice = 0; 

// =======================================================
// 🔥 COINBASE CONNECTION (Получение цены для Polling) 🔥
// =======================================================
function connectCoinbase() {
    const coinbaseWs = new WebSocketClient('wss://ws-feed.exchange.coinbase.com');
    
    coinbaseWs.on('open', () => {
        console.log('Connected to Coinbase. Subscribing to BTC-USD...');
        
        // Сообщение для подписки на канал 'ticker'
        const subscribeMessage = JSON.stringify({
            "type": "subscribe",
            "product_ids": ["BTC-USD"],
            "channels": ["ticker"]
        });
        coinbaseWs.send(subscribeMessage);
    });
    
    coinbaseWs.on('message', (data) => {
        const trade = JSON.parse(data);

        // Обновляем текущую глобальную цену
        if (trade.type === 'ticker' && trade.product_id === 'BTC-USD' && trade.price) {
            currentPrice = parseFloat(trade.price);
        }
    });

    coinbaseWs.on('close', () => {
        console.log('Coinbase connection closed, reconnecting in 5 seconds...');
        setTimeout(connectCoinbase, 5000);
    });

    coinbaseWs.on('error', (err) => console.error('Coinbase Error:', err));
}

connectCoinbase(); 

// =======================================================
// 🔥 API ЭНДПОИНТ ДЛЯ ПОЛЛИНГА ЦЕНЫ 🔥
// =======================================================
app.get('/api/price', (req, res) => {
    // Отдаем текущую цену, которую мы получаем через WebSocket Coinbase
    if (currentPrice === 0) {
        return res.status(503).json({ error: 'Цена еще не получена' });
    }
    res.json({ price: currentPrice, time: Date.now() });
});

// === API ROUTES ===
app.post('/api/init', (req, res) => {
    const { userId } = req.body;
    // ВНИМАНИЕ: Здесь будут изменения для БД
    if (!users[userId]) users[userId] = { balance: 1000.00, positions: [] };
    res.json(users[userId]);
});

app.post('/api/order/open', (req, res) => {
    const { userId, type, margin, leverage } = req.body;
    const user = users[userId];
    
    if (currentPrice === 0) return res.status(503).json({ error: 'Цены еще не получены. Попробуйте через секунду.' });
    if (!user || user.balance < margin) return res.status(400).json({ error: 'Low balance' });

    const fee = margin * leverage * 0.001; 
    user.balance -= (margin + fee);

    const position = {
        id: Date.now(),
        type,
        entryPrice: currentPrice,
        margin: parseFloat(margin),
        leverage: parseInt(leverage),
        size: parseFloat(margin) * parseInt(leverage)
    };
    user.positions.push(position);
    res.json({ success: true, balance: user.balance, position });
});

app.post('/api/order/close', (req, res) => {
    const { userId, positionId } = req.body;
    const user = users[userId];
    const idx = user.positions.findIndex(p => p.id === positionId);
    if (idx === -1) return res.status(404).json({ error: 'Position not found' });

    const pos = user.positions[idx];
    let pnl = 0;
    if (pos.type === 'LONG') pnl = ((currentPrice - pos.entryPrice) / pos.entryPrice) * pos.size;
    else pnl = ((pos.entryPrice - currentPrice) / pos.entryPrice) * pos.size;

    user.balance += (pos.margin + pnl);
    user.positions.splice(idx, 1);
    res.json({ success: true, balance: user.balance, pnl });
});

// === ЗАПУСК ===
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
