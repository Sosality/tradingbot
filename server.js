const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors()); // Разрешаем запросы с любых доменов
app.use(express.json());

// Раздаем статику (наш фронтенд), если заходим через браузер
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// === ХРАНИЛИЩЕ (В ПАМЯТИ) ===
// Внимание: На Render Free Tier сервер перезагружается при простое,
// поэтому данные в памяти будут сбрасываться.
const users = {}; 
let currentPrice = 0;

// === BINANCE CONNECTION ===
// Используем reconnect логику, чтобы сервер не падал при разрыве связи с Binance
function connectBinance() {
    const binanceWs = new WebSocket('wss://stream.binance.com:9443/ws/btcusdt@trade');
    
    binanceWs.on('open', () => console.log('Connected to Binance'));
    
    binanceWs.on('message', (data) => {
        const trade = JSON.parse(data);
        currentPrice = parseFloat(trade.p);
        
        // Рассылка всем клиентам
        const updateMsg = JSON.stringify({ type: 'PRICE_UPDATE', price: currentPrice, time: trade.T });
        wss.clients.forEach(client => {
            if (client.readyState === WebSocket.OPEN) client.send(updateMsg);
        });
    });

    binanceWs.on('close', () => {
        console.log('Binance connection closed, reconnecting...');
        setTimeout(connectBinance, 5000);
    });

    binanceWs.on('error', (err) => console.error('Binance Error:', err));
}

connectBinance();

// === API ROUTES ===
app.post('/api/init', (req, res) => {
    const { userId } = req.body;
    if (!users[userId]) users[userId] = { balance: 1000.00, positions: [] };
    res.json(users[userId]);
});

app.post('/api/order/open', (req, res) => {
    const { userId, type, margin, leverage } = req.body;
    const user = users[userId];
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

// === WEBSOCKET CLIENT HANDLING ===
wss.on('connection', (ws) => {
    ws.send(JSON.stringify({ type: 'PRICE_UPDATE', price: currentPrice, time: Date.now() }));
    // Пинг-понг для поддержания связи (Render может рвать idle соединения)
    const interval = setInterval(() => {
        if (ws.readyState === WebSocket.OPEN) ws.ping();
    }, 30000);
    ws.on('close', () => clearInterval(interval));
});

// === ЗАПУСК ===
// Важно: Render сам выдает порт через process.env.PORT
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
