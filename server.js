const express = require('express');
const http = require('http');
const { WebSocketServer, WebSocket } = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// Channels: channelName -> Set of WebSocket clients
const channels = new Map();
// Presence: kidDeviceId -> { status: 'online'|'offline', lastSeen: timestamp }
const devicePresence = new Map();

// Cloudflare TURN Configuration
const CF_KEY_ID = process.env.CF_KEY_ID || 'edb8fb3b17c870061e3273d453dbbe83';
const CF_API_TOKEN = process.env.CF_API_TOKEN || '0cc43dcb2b4b83f6f938b96a7a663a94e2fb7fcb715923609bda4b455c8751af';

let cachedIceServers = null;
let cacheExpiry = 0;

// High-reliability ICE server generator with 12-hour caching & Google STUN fallback
async function getIceServers() {
    const now = Date.now();
    if (cachedIceServers && now < cacheExpiry) {
        return cachedIceServers;
    }

    try {
        const response = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${CF_KEY_ID}/credentials/generate-ice-servers`, {
            method: 'POST',
            headers: {
                'Authorization': `Bearer ${CF_API_TOKEN}`,
                'Content-Type': 'application/json',
                'User-Agent': 'Mozilla/5.0 (ParentyServer/1.0)'
            },
            body: JSON.stringify({ ttl: 86400 })
        });

        if (response.ok) {
            const data = await response.json();
            if (data && data.iceServers && data.iceServers.length > 0) {
                // Prepend Google STUN for instant 0-latency direct P2P resolution
                const combined = [
                    {
                        urls: [
                            'stun:stun.l.google.com:19302',
                            'stun:stun1.l.google.com:19302',
                            'stun:stun2.l.google.com:19302'
                        ]
                    },
                    ...data.iceServers
                ];
                cachedIceServers = combined;
                cacheExpiry = now + (12 * 60 * 60 * 1000); // 12 hours
                console.log('✅ Refreshed Cloudflare 1TB TURN credentials successfully');
                return cachedIceServers;
            }
        } else {
            console.warn('⚠️ Cloudflare API returned status:', response.status);
        }
    } catch (err) {
        console.error('⚠️ Failed to fetch Cloudflare TURN credentials:', err.message);
    }

    // Fallback: Google STUN
    return [
        {
            urls: [
                'stun:stun.l.google.com:19302',
                'stun:stun1.l.google.com:19302',
                'stun:stun2.l.google.com:19302',
                'stun:stun3.l.google.com:19302'
            ]
        }
    ];
}

// ── HTTP Endpoints ─────────────────────────────────────────────────────────

app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'Parenty WebRTC Signaling & TURN Gateway',
        turnProvider: 'Cloudflare Realtime (1TB Global Anycast)',
        activeChannels: channels.size,
        trackedDevices: devicePresence.size,
        timestamp: new Date().toISOString()
    });
});

app.get('/health', (req, res) => res.status(200).send('OK'));

// Dynamic ICE servers endpoint for Android Parent & Kid apps
app.get('/ice-servers', async (req, res) => {
    try {
        const iceServers = await getIceServers();
        res.setHeader('Cache-Control', 'public, max-age=3600');
        res.json({ iceServers });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Device status check endpoint
app.get('/status/:kidDeviceId', (req, res) => {
    const info = devicePresence.get(req.params.kidDeviceId);
    if (!info) {
        return res.json({ status: 'unknown', isOnline: false });
    }
    const isOnline = info.status === 'online' && (Date.now() - info.lastSeen < 60000);
    res.json({
        kidDeviceId: req.params.kidDeviceId,
        status: isOnline ? 'online' : 'offline',
        isOnline: isOnline,
        lastSeen: info.lastSeen
    });
});

// ── WebSocket Signaling & Presence Engine ──────────────────────────────────

wss.on('connection', (ws, req) => {
    let currentChannel = null;
    let clientRole = 'unknown'; // 'kid' or 'parent'
    let currentKidId = null;
    ws.isAlive = true;

    ws.on('pong', () => {
        ws.isAlive = true;
        if (currentKidId && clientRole === 'kid') {
            devicePresence.set(currentKidId, { status: 'online', lastSeen: Date.now() });
        }
    });

    ws.on('message', async (raw) => {
        try {
            const data = JSON.parse(raw.toString());
            const targetChannel = data.channel || data.target;

            if (data.role) {
                clientRole = data.role;
            }

            // Client requests latest ICE servers dynamically over WebSocket
            if (data.type === 'get_ice_servers') {
                const servers = await getIceServers();
                return ws.send(JSON.stringify({
                    type: 'ice_servers',
                    iceServers: servers
                }));
            }

            // Channel joining logic
            if (targetChannel && currentChannel !== targetChannel) {
                if (currentChannel && channels.has(currentChannel)) {
                    channels.get(currentChannel).delete(ws);
                }
                currentChannel = targetChannel;
                if (!channels.has(currentChannel)) {
                    channels.set(currentChannel, new Set());
                }
                channels.get(currentChannel).add(ws);

                if (currentChannel.startsWith('signal-')) {
                    currentKidId = currentChannel.replace('signal-', '');
                }

                if (clientRole === 'kid' && currentKidId) {
                    devicePresence.set(currentKidId, { status: 'online', lastSeen: Date.now() });
                    // Broadcast online status to parents in this channel
                    broadcastToChannel(currentChannel, ws, {
                        type: 'kid_status',
                        kidDeviceId: currentKidId,
                        status: 'online',
                        timestamp: Date.now()
                    });
                }
            }

            // Update kid presence timestamp
            if (currentKidId && clientRole === 'kid') {
                devicePresence.set(currentKidId, { status: 'online', lastSeen: Date.now() });
            }

            // Forward signaling messages to other peers in this channel
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

            if (clientRole === 'kid' && currentKidId) {
                devicePresence.set(currentKidId, { status: 'offline', lastSeen: Date.now() });
                for (const peer of peers) {
                    if (peer.readyState === WebSocket.OPEN) {
                        peer.send(JSON.stringify({
                            type: 'kid_status',
                            kidDeviceId: currentKidId,
                            status: 'offline',
                            timestamp: Date.now()
                        }));
                    }
                }
            }

            if (peers.size === 0) {
                channels.delete(currentChannel);
            }
        }
    });

    ws.on('error', (err) => {
        console.error('WebSocket client error:', err.message);
    });
});

function broadcastToChannel(channelName, senderWs, obj) {
    if (!channels.has(channelName)) return;
    const msg = JSON.stringify(obj);
    for (const peer of channels.get(channelName)) {
        if (peer !== senderWs && peer.readyState === WebSocket.OPEN) {
            peer.send(msg);
        }
    }
}

// Keepalive heartbeat ping every 25 seconds
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

// Pre-fetch ICE credentials at startup
getIceServers();

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
    console.log(`🚀 Parenty Signaling & TURN Server running on port ${PORT}`);
});
