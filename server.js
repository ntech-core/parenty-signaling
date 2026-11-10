const express = require('express');
const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

const channels = new Map();

app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'Parenty WebRTC Signaling Server',
        activeChannels: channels.size,
        timestamp: new Date().toISOString()
    });
});

app.get('/health', (req, res) => res.status(200).send('OK'));

wss.on('connection', (ws, req) => {
    let currentChannel = null;
    ws.isAlive = true;

    ws.on('pong', () => {
        ws.isAlive = true;
    });

    ws.on('message', (raw) => {
        try {
            const data = JSON.parse(raw.toString());
            const targetChannel = data.channel || data.target;

            if (targetChannel && currentChannel !== targetChannel) {
                if (currentChannel && channels.has(currentChannel)) {
                    channels.get(currentChannel).delete(ws);
                }
                currentChannel = targetChannel;
                if (!channels.has(currentChannel)) {
                    channels.set(currentChannel, new Set());
                }
                channels.get(currentChannel).add(ws);
                console.log();
            }

            if (currentChannel && channels.has(currentChannel)) {
                const peers = channels.get(currentChannel);
                const msgStr = typeof raw === 'string' ? raw : raw.toString();
                for (const peer of peers) {
                    if (peer !== ws && peer.readyState === WebSocket.OPEN) {
                        peer.send(msgStr);
                    }
                }
            }
        } catch (err) {
            console.error('Error handling message:', err.message);
        }
    });

    ws.on('close', () => {
        if (currentChannel && channels.has(currentChannel)) {
            const peers = channels.get(currentChannel);
            peers.delete(ws);
            if (peers.size === 0) {
                channels.delete(currentChannel);
            }
            console.log();
        }
    });

    ws.on('error', (err) => {
        console.error('WebSocket client error:', err.message);
    });
});

const pingInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if (ws.isAlive === false) return ws.terminate();
        ws.isAlive = false;
        ws.ping();
    });
}, 25000);

wss.on('close', () => {
    clearInterval(pingInterval);
});

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
    console.log();
});
