const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const cors = require('cors');
const path = require('path');

const app = express();
app.use(cors()); // Разрешаем запросы с любых доменов
app.use(express.json());

// Раздаем статику (наш фронтенд), если заходим через браузер
// (Оставляем, даже если фронтенд отдельно, для удобства тестов)
app.use(express.static(path.join(__dirname, 'public')));

const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

// === ХРАНИЛИЩЕ (В ПАМЯТИ) ===
// Внимание: Данные будут сбрасываться при перезапуске Render.
const users = {}; 
let currentPrice = 0;

// =======================================================
// 🔥 COINBASE CONNECTION (Новый источник данных) 🔥
// =======================================================
function connectCoinbase() {
    // Подключение к WebSocket Coinbase
    const coinbaseWs = new WebSocket('wss://ws-feed.exchange.coinbase.com');
    
    coinbaseWs.on('open', () => {
        console.log('Connected to Coinbase. Subscribing to BTC-USD...');
        
        // Сообщение для подписки на канал 'ticker' (для получения цены)
        const subscribeMessage = JSON.stringify({
            "type": "subscribe",
            "product_ids": ["BTC-USD"],
            "channels": ["ticker"]
        });
        coinbaseWs.send(subscribeMessage);
    });
    
    coinbaseWs.on('message', (data) => {
        const trade = JSON.parse(data);

        // Проверяем, что это тикер (цена) для нужной пары
        if (trade.type === 'ticker' && trade.product_id === 'BTC-USD' && trade.price) {
            currentPrice = parseFloat(trade.price); // Обновляем глобальную цену
            
            // Рассылаем цену всем подключенным клиентам
            const updateMsg = JSON.stringify({ 
                type: 'PRICE_UPDATE', 
                price: currentPrice, 
                time: Date.now() 
            }); 
            
            wss.clients.forEach(client => {
                if (client.readyState === WebSocket.OPEN) {
                    client.send(updateMsg);
                }
            });
        }
    });

    coinbaseWs.on('close', () => {
        console.log('Coinbase connection closed, reconnecting in 5 seconds...');
        setTimeout(connectCoinbase, 5000);
    });

    coinbaseWs.on('error', (err) => console.error('Coinbase Error:', err));
}

connectCoinbase(); // Запуск нового подключения

// === API ROUTES ===
app.post('/api/init', (req, res) => {
    const { userId } = req.body;
    if (!users[userId]) users[userId] = { balance: 1000.00, positions: [] };
    res.json(users[userId]);
});

app.post('/api/order/open', (req, res) => {
    const { userId, type, margin, leverage } = req.body;
    const user = users[userId];
    
    // ВАЛИДАЦИЯ: Текущая цена должна быть известна
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
const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
