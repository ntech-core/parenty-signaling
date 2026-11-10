/**
 * ============================================================================
 * PARENTY WEBRTC SIGNALING & AUTHENTICATED PRESENCE GATEWAY (ENTERPRISE V2.1)
 * ============================================================================
 * Production Hardened:
 * 1. Real Identity Authentication:
 *    - Parent: Supabase Auth JWT verified via Supabase Auth API (with 5-min cache)
 *    - Kid: Device identity verified against Supabase device_connections (with 2-min cache)
 * 2. Strict Room Authorization:
 *    - Kid devices can ONLY join their own room (`signal-<ownDeviceId>`)
 *    - Parents can ONLY join rooms of kids they are verifiably paired with in Supabase
 *    - All unauthenticated or cross-tenant room access strictly rejected (Fail-Closed)
 * 3. Persistent Monotonic Presence Versions:
 *    - Independent registry (`presenceVersions`) never erased on device disconnect
 *    - Millisecond-monotonic epoch formula guarantees strictly increasing versions across Render restarts
 * 4. Fast Authorization Invalidation:
 *    - 2-minute targeted pairing cache ensures rapid revocation handling
 *    - Fail-closed security architecture
 * 5. Protected REST Endpoints:
 *    - `/status/:kidDeviceId` protected by Supabase Bearer token & pairing ownership
 * 6. Cloudflare 1TB Anycast TURN:
 *    - 12-hour credential caching with high-visibility failure reporting
 * 7. Zero Supabase Realtime Log Ingestion:
 *    - 100% of presence and signaling routed through this zero-cost server
 * ============================================================================
 */

const express = require('express');
const http = require('http');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// ── 1. Configuration & Secrets ───────────────────────────────────────────────

const CF_KEY_ID = process.env.CF_KEY_ID;
const CF_API_TOKEN = process.env.CF_API_TOKEN;
const SUPABASE_URL = process.env.SUPABASE_URL || 'https://vqhhfpjntifambqfzqjm.supabase.co';
const SUPABASE_ANON_KEY = process.env.SUPABASE_ANON_KEY || 'sb_publishable_WB_hkxs7N5b0ampGtD_qNA_Rtj-Om0Y';

if (!CF_KEY_ID || !CF_API_TOKEN) {
    console.warn('⚠️ WARNING: Cloudflare TURN credentials (CF_KEY_ID, CF_API_TOKEN) not set. Running on Google STUN fallback.');
}

// Timing Constants
const HEARTBEAT_TIMEOUT = 90000;       // 90-second presence lease (matches 30s heartbeat interval with 3x grace window)
const CLEANUP_INTERVAL = 1000;         // 1-second centralized sweep
const AUTH_TOKEN_CACHE_TTL = 5 * 60 * 1000; // 5-minute Parent JWT verification cache
const PAIRING_CACHE_TTL = 2 * 60 * 1000;    // 2-minute Parent-Kid pairing cache
const KID_AUTH_CACHE_TTL = 2 * 60 * 1000;   // 2-minute Kid registration check cache

// ── 2. Production In-Memory Registries ──────────────────────────────────────

// WebRTC Signaling Rooms: roomName (e.g. "signal-<kidDeviceId>") -> Set<WebSocket>
const channels = new Map();

// Active Online Devices: deviceId -> { ws, connectionId, lastSeen, status, version }
const devices = new Map();

// Persistent Monotonic Presence Versions: deviceId -> number (Preserved across disconnections!)
const presenceVersions = new Map();

// Parent Subscriptions: ws -> Set<kidDeviceId>
const parentSubscriptions = new Map();

// Token Verification Cache: tokenString -> { user: { id, email }, timestamp }
const parentAuthCache = new Map();

// Kid Device Verification Cache: deviceId -> { info: { deviceId, parentId, status }, timestamp }
const kidAuthCache = new Map();

// Pairing Ownership Cache: `${parentId}:${kidDeviceId}` -> { authorized: boolean, timestamp }
const pairingAuthCache = new Map();

// ── 3. Monotonic Versioning Engine ────────────────────────────────────────

function getNextPresenceVersion(deviceId) {
    const prev = presenceVersions.get(deviceId) || 0;
    // Strictly increasing monotonic version: max(currentTimeMs, previousVersion + 1)
    // Guarantees forward progress even after server restarts or rapid reconnections
    const next = Math.max(Date.now(), prev + 1);
    presenceVersions.set(deviceId, next);
    return next;
}

function getCurrentPresenceVersion(deviceId) {
    return presenceVersions.get(deviceId) || 0;
}

// ── 4. Cloudflare 1TB TURN & Google STUN Engine ───────────────────────────

let cachedIceServers = null;
let iceCacheExpiry = 0;

async function getIceServers() {
    const now = Date.now();
    if (cachedIceServers && now < iceCacheExpiry) {
        return cachedIceServers;
    }

    if (CF_KEY_ID && CF_API_TOKEN) {
        try {
            const response = await fetch(`https://rtc.live.cloudflare.com/v1/turn/keys/${CF_KEY_ID}/credentials/generate-ice-servers`, {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${CF_API_TOKEN}`,
                    'Content-Type': 'application/json',
                    'User-Agent': 'Mozilla/5.0 (ParentyServer/2.1)'
                },
                body: JSON.stringify({ ttl: 86400 })
            });

            if (response.ok) {
                const data = await response.json();
                if (data && data.iceServers && data.iceServers.length > 0) {
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
                    iceCacheExpiry = now + (12 * 60 * 60 * 1000); // 12-hour memory cache
                    console.log(`✅ [TURN] Refreshed Cloudflare 1TB TURN credentials (${data.iceServers.length} relay endpoints)`);
                    return cachedIceServers;
                }
            } else {
                console.error(`🚨 Cloudflare TURN API responded with HTTP ${response.status}. Falling back to Google STUN.`);
            }
        } catch (err) {
            console.error('🚨 Cloudflare TURN credential generation FAILED:', err.message, 'Falling back to Google STUN.');
        }
    }

    // High-availability fallback: Google STUN
    return [
        {
            urls: [
                'stun:stun.l.google.com:19302',
                'stun:stun1.l.google.com:19302',
                'stun:stun2.l.google.com:19302',
                'stun:stun.cloudflare.com:3478'
            ]
        }
    ];
}

// ── 5. Enterprise Authentication & Verification Layer ─────────────────────

/**
 * Verifies Supabase JWT for Parent.
 * Calls Supabase /auth/v1/user to validate cryptographic signature and expiration.
 */
async function verifyParentJwt(token) {
    if (!token || typeof token !== 'string') return null;

    const cleanToken = token.startsWith('Bearer ') ? token.slice(7) : token;
    const now = Date.now();

    // Check fast memory cache
    const cached = parentAuthCache.get(cleanToken);
    if (cached && (now - cached.timestamp < AUTH_TOKEN_CACHE_TTL)) {
        return cached.user;
    }

    try {
        const resp = await fetch(`${SUPABASE_URL}/auth/v1/user`, {
            headers: {
                'apikey': SUPABASE_ANON_KEY,
                'Authorization': `Bearer ${cleanToken}`
            }
        });

        if (resp.ok) {
            const user = await resp.json();
            if (user && user.id) {
                parentAuthCache.set(cleanToken, { user, timestamp: now });
                return user;
            }
        } else {
            console.warn(`🔒 [Auth] Supabase rejected Parent token with HTTP ${resp.status}`);
        }
    } catch (err) {
        console.error('🔒 [Auth] Supabase token verification network error:', err.message);
    }

    return null;
}

/**
 * Verifies Kid device existence and paired parent from Supabase device_connections.
 */
async function verifyKidDevice(deviceId) {
    if (!deviceId || typeof deviceId !== 'string') return null;

    const now = Date.now();
    const cached = kidAuthCache.get(deviceId);
    if (cached && (now - cached.timestamp < KID_AUTH_CACHE_TTL)) {
        return cached.info;
    }

    try {
        const url = `${SUPABASE_URL}/rest/v1/device_connections?kid_device_id=eq.${encodeURIComponent(deviceId)}&select=id,kid_device_id,parent_id,status`;
        const resp = await fetch(url, {
            headers: {
                'apikey': SUPABASE_ANON_KEY,
                'Authorization': `Bearer ${SUPABASE_ANON_KEY}`
            }
        });

        if (resp.ok) {
            const rows = await resp.json();
            if (Array.isArray(rows) && rows.length > 0) {
                const connectedRow = rows.find(r => r.status === 'CONNECTED');
                const row = connectedRow || rows[0];
                const info = {
                    deviceId: row.kid_device_id,
                    parentId: row.parent_id,
                    status: row.status
                };
                kidAuthCache.set(deviceId, { info, timestamp: now });
                return info;
            }
        }
    } catch (err) {
        console.error(`🔒 [Auth] Failed to verify kid device ${deviceId}:`, err.message);
    }

    return null;
}

/**
 * Strictly verifies whether a Parent is authorized for a specific Kid device.
 * Fail-Closed: returns false on error or missing pairing.
 */
async function isParentAuthorizedForKid(parentId, kidDeviceId) {
    if (!parentId || !kidDeviceId) return false;

    const cacheKey = `${parentId}:${kidDeviceId}`;
    const now = Date.now();
    const cached = pairingAuthCache.get(cacheKey);
    if (cached && (now - cached.timestamp < PAIRING_CACHE_TTL)) {
        return cached.authorized;
    }

    try {
        const url = `${SUPABASE_URL}/rest/v1/device_connections?parent_id=eq.${encodeURIComponent(parentId)}&kid_device_id=eq.${encodeURIComponent(kidDeviceId)}&status=eq.CONNECTED&select=id`;
        const resp = await fetch(url, {
            headers: {
                'apikey': SUPABASE_ANON_KEY,
                'Authorization': `Bearer ${SUPABASE_ANON_KEY}`
            }
        });

        if (resp.ok) {
            const rows = await resp.json();
            const authorized = Array.isArray(rows) && rows.length > 0;
            pairingAuthCache.set(cacheKey, { authorized, timestamp: now });
            return authorized;
        }
    } catch (err) {
        console.error(`🔒 [Auth] Pairing verification error for Parent ${parentId} -> Kid ${kidDeviceId}:`, err.message);
    }

    return false; // Fail-Closed
}

// ── 6. Safe Transmission & Presence Broadcasting ──────────────────────────

function safeSend(ws, payload) {
    if (ws && ws.readyState === WebSocket.OPEN) {
        ws.send(typeof payload === 'string' ? payload : JSON.stringify(payload));
    }
}

function broadcastPresence(deviceId, status, version) {
    const event = {
        type: 'PRESENCE_UPDATE',
        deviceId,
        status,
        version,
        serverTime: Date.now()
    };

    for (const [parentWs, subscribedSet] of parentSubscriptions) {
        if (subscribedSet.has(deviceId)) {
            safeSend(parentWs, event);
        }
    }
}

// Registers Kid connection (Called strictly upon successful AUTH)
function registerKid(deviceId, ws, connectionId) {
    ws.deviceId = deviceId;
    ws.role = 'kid';
    ws.isAuthenticated = true;

    const previous = devices.get(deviceId);
    const prevStatus = previous ? previous.status : 'OFFLINE';

    // Terminate stale socket if exists
    if (previous && previous.ws !== ws && previous.ws.readyState === WebSocket.OPEN) {
        previous.ws.close(4001, 'Replaced by newer connection');
    }

    const nextVersion = getNextPresenceVersion(deviceId);

    devices.set(deviceId, {
        ws,
        connectionId,
        lastSeen: Date.now(),
        status: 'ONLINE',
        version: nextVersion
    });

    if (prevStatus !== 'ONLINE' || (previous && previous.connectionId !== connectionId)) {
        broadcastPresence(deviceId, 'ONLINE', nextVersion);
        console.log(`🟢 [Presence] Device ONLINE: ${deviceId} (v${nextVersion}, conn: ${connectionId})`);
    }
}

// ── 7. HTTP REST Endpoints ────────────────────────────────────────────────

app.get('/', (req, res) => {
    res.json({
        status: 'online',
        service: 'Parenty WebRTC Signaling & Authenticated Presence Gateway',
        version: '2.1.0',
        turnProvider: CF_KEY_ID ? 'Cloudflare Realtime (1TB Global Anycast)' : 'Google STUN Fallback',
        activeRooms: channels.size,
        onlineDevices: devices.size,
        subscribedParents: parentSubscriptions.size,
        knownDeviceVersions: presenceVersions.size,
        timestamp: new Date().toISOString()
    });
});

app.get('/health', (req, res) => res.status(200).send('OK'));

app.get('/ice-servers', async (req, res) => {
    try {
        const iceServers = await getIceServers();
        res.setHeader('Cache-Control', 'public, max-age=3600');
        res.json({ iceServers });
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Authenticated Device Status Endpoint
app.get('/status/:kidDeviceId', async (req, res) => {
    const authHeader = req.headers['authorization'];
    if (!authHeader) {
        return res.status(401).json({ error: 'Missing Authorization header' });
    }

    const user = await verifyParentJwt(authHeader);
    if (!user) {
        return res.status(401).json({ error: 'Invalid or expired authentication token' });
    }

    const kidDeviceId = req.params.kidDeviceId;
    const isAuthorized = await isParentAuthorizedForKid(user.id, kidDeviceId);
    if (!isAuthorized) {
        return res.status(403).json({ error: 'Unauthorized to view status for this device' });
    }

    const device = devices.get(kidDeviceId);
    const isOnline = !!device && (Date.now() - device.lastSeen < HEARTBEAT_TIMEOUT);
    const version = getCurrentPresenceVersion(kidDeviceId);

    res.json({
        kidDeviceId,
        status: isOnline ? 'ONLINE' : 'OFFLINE',
        isOnline,
        lastSeen: device ? device.lastSeen : null,
        version
    });
});

// ── 8. WebSocket Engine (Authenticated Signaling & Presence) ──────────────

wss.on('connection', (ws, req) => {
    const connectionId = crypto.randomUUID();
    ws.connectionId = connectionId;
    ws.isAlive = true;
    ws.isAuthenticated = false;
    ws.role = 'unknown';
    ws.currentRoom = null;

    ws.on('pong', () => {
        ws.isAlive = true;
        ws.missedPings = 0;
    });

    ws.on('message', async (raw) => {
        try {
            const data = JSON.parse(raw.toString());

            // ── A. Client Authentication / Registration ──────────────────
            if (data.type === 'AUTH') {
                // 1. Parent Authentication: Requires Supabase JWT
                if (data.role === 'parent') {
                    const token = data.token;
                    if (!token) {
                        return safeSend(ws, {
                            type: 'AUTH_FAIL',
                            message: 'Authentication token required for parent role'
                        });
                    }

                    const user = await verifyParentJwt(token);
                    if (!user) {
                        return safeSend(ws, {
                            type: 'AUTH_FAIL',
                            message: 'Invalid or expired Supabase authentication token'
                        });
                    }

                    ws.role = 'parent';
                    ws.parentId = user.id; // STRICTLY DERIVED FROM VERIFIED JWT
                    ws.userEmail = user.email;
                    ws.isAuthenticated = true;

                    if (!parentSubscriptions.has(ws)) {
                        parentSubscriptions.set(ws, new Set());
                    }

                    console.log(`🔑 [Auth] Parent authenticated: ${user.id} (${user.email})`);
                    return safeSend(ws, {
                        type: 'AUTH_OK',
                        role: 'parent',
                        parentId: user.id,
                        connectionId
                    });
                }

                // 2. Kid Authentication: Requires valid registered deviceId
                if (data.role === 'kid') {
                    const deviceId = data.deviceId;
                    if (!deviceId) {
                        return safeSend(ws, {
                            type: 'AUTH_FAIL',
                            message: 'deviceId required for kid role'
                        });
                    }

                    const kidInfo = await verifyKidDevice(deviceId);
                    if (!kidInfo) {
                        return safeSend(ws, {
                            type: 'AUTH_FAIL',
                            message: `Device ${deviceId} is not registered in Supabase`
                        });
                    }

                    ws.role = 'kid';
                    ws.deviceId = kidInfo.deviceId;
                    ws.pairedParentId = kidInfo.parentId;
                    ws.isAuthenticated = true;

                    registerKid(kidInfo.deviceId, ws, connectionId);

                    return safeSend(ws, {
                        type: 'AUTH_OK',
                        role: 'kid',
                        deviceId: kidInfo.deviceId,
                        connectionId
                    });
                }

                return safeSend(ws, { type: 'AUTH_FAIL', message: 'Unknown or unsupported role' });
            }

            // ── B. Heartbeat Handler (5s interval from Kid) ───────────────
            if (data.type === 'HEARTBEAT') {
                if (!ws.isAuthenticated || ws.role !== 'kid' || !ws.deviceId) {
                    return safeSend(ws, { type: 'ERROR', code: 401, message: 'Unauthenticated heartbeat rejected' });
                }

                const current = devices.get(ws.deviceId);
                if (current && current.ws === ws && current.connectionId === connectionId) {
                    current.lastSeen = Date.now();
                    return safeSend(ws, {
                        type: 'HEARTBEAT_ACK',
                        serverTime: Date.now()
                    });
                }
                return;
            }

            // ── C. Parent Presence Subscription & Immediate Snapshot ─────
            if (data.type === 'SUBSCRIBE_PRESENCE' && data.deviceId) {
                if (!ws.isAuthenticated || ws.role !== 'parent' || !ws.parentId) {
                    return safeSend(ws, { type: 'ERROR', code: 401, message: 'Authentication required to subscribe to presence' });
                }

                // Verify parent is legitimately paired with this kid device
                const isAuthorized = await isParentAuthorizedForKid(ws.parentId, data.deviceId);
                if (!isAuthorized) {
                    console.warn(`🚨 [Security] Unauthorized subscription attempt: Parent ${ws.parentId} -> Kid ${data.deviceId}`);
                    return safeSend(ws, {
                        type: 'ERROR',
                        code: 403,
                        message: `Unauthorized subscription for device: ${data.deviceId}`
                    });
                }

                if (!parentSubscriptions.has(ws)) {
                    parentSubscriptions.set(ws, new Set());
                }
                parentSubscriptions.get(ws).add(data.deviceId);

                const currentDev = devices.get(data.deviceId);
                const isOnline = !!currentDev && (Date.now() - currentDev.lastSeen <= HEARTBEAT_TIMEOUT);
                const version = getCurrentPresenceVersion(data.deviceId);

                return safeSend(ws, {
                    type: 'PRESENCE_SNAPSHOT',
                    deviceId: data.deviceId,
                    status: isOnline ? 'ONLINE' : 'OFFLINE',
                    version,
                    lastSeen: currentDev ? currentDev.lastSeen : null,
                    serverTime: Date.now()
                });
            }

            if (data.type === 'UNSUBSCRIBE_PRESENCE' && data.deviceId) {
                if (parentSubscriptions.has(ws)) {
                    parentSubscriptions.get(ws).delete(data.deviceId);
                }
                return;
            }

            // ── D. Dynamic ICE Servers Request over WebSocket ─────────────
            if (data.type === 'get_ice_servers') {
                const servers = await getIceServers();
                return safeSend(ws, {
                    type: 'ice_servers',
                    iceServers: servers
                });
            }

            // ── E. WebRTC Room Management & Signaling Forwarding ──────────
            const targetChannel = data.channel || data.target;

            if (targetChannel) {
                // Must be authenticated before entering any room
                if (!ws.isAuthenticated) {
                    return safeSend(ws, {
                        type: 'ERROR',
                        code: 401,
                        message: 'Authentication required before joining room'
                    });
                }

                // Room Authorization Verification
                if (targetChannel.startsWith('signal-')) {
                    const roomKidId = targetChannel.replace('signal-', '');

                    // Kid can ONLY join room matching its own verified deviceId
                    if (ws.role === 'kid' && ws.deviceId !== roomKidId) {
                        console.warn(`🚨 [Security] Kid ${ws.deviceId} attempted unauthorized room: ${targetChannel}`);
                        return safeSend(ws, { type: 'ERROR', code: 403, message: 'Room access denied' });
                    }

                    // Parent can ONLY join room if paired with target kid device
                    if (ws.role === 'parent') {
                        const authorized = await isParentAuthorizedForKid(ws.parentId, roomKidId);
                        if (!authorized) {
                            console.warn(`🚨 [Security] Parent ${ws.parentId} unauthorized for room: ${targetChannel}`);
                            return safeSend(ws, { type: 'ERROR', code: 403, message: 'Unauthorized room access' });
                        }
                    }
                }

                // Join room if changed
                if (ws.currentRoom !== targetChannel) {
                    if (ws.currentRoom && channels.has(ws.currentRoom)) {
                        channels.get(ws.currentRoom).delete(ws);
                    }
                    ws.currentRoom = targetChannel;
                    if (!channels.has(targetChannel)) {
                        channels.set(targetChannel, new Set());
                    }
                    channels.get(targetChannel).add(ws);
                }
            }

            // Forward signaling messages strictly within authorized rooms
            if (ws.currentRoom && channels.has(ws.currentRoom)) {
                const peers = channels.get(ws.currentRoom);
                const msgStr = typeof raw === 'string' ? raw : raw.toString();
                for (const peer of peers) {
                    if (peer !== ws && peer.readyState === WebSocket.OPEN) {
                        peer.send(msgStr);
                    }
                }
            }

        } catch (err) {
            console.error('Error handling WebSocket message:', err.message);
        }
    });

    ws.on('close', (code, reason) => {
        // 1. Stale-Socket Protection: Only mark offline if connectionId matches current active
        if (ws.deviceId) {
            const current = devices.get(ws.deviceId);
            if (current && current.connectionId === connectionId) {
                const nextVersion = getNextPresenceVersion(ws.deviceId);
                devices.delete(ws.deviceId);
                broadcastPresence(ws.deviceId, 'OFFLINE', nextVersion);
                console.log(`🔴 [Presence] Device OFFLINE: ${ws.deviceId} (v${nextVersion}, code: ${code})`);
            } else {
                console.log(`ℹ️ Stale socket closed for ${ws.deviceId} — ignored (newer connection active)`);
            }
        }

        // 2. Clean up parent subscriptions
        if (parentSubscriptions.has(ws)) {
            parentSubscriptions.delete(ws);
        }

        // 3. Clean up room membership
        if (ws.currentRoom && channels.has(ws.currentRoom)) {
            const peers = channels.get(ws.currentRoom);
            peers.delete(ws);
            if (peers.size === 0) {
                channels.delete(ws.currentRoom);
            }
        }
    });

    ws.on('error', (err) => {
        console.error(`WebSocket error (conn: ${connectionId}):`, err.message);
    });
});

// ── 9. Centralized Presence Lease Sweep (Every 1 Second) ──────────────────

setInterval(() => {
    const now = Date.now();
    for (const [deviceId, device] of devices) {
        if (now - device.lastSeen > HEARTBEAT_TIMEOUT) {
            if (devices.get(deviceId) !== device) continue;

            const nextVersion = getNextPresenceVersion(deviceId);
            devices.delete(deviceId);
            broadcastPresence(deviceId, 'OFFLINE', nextVersion);
            console.log(`⏱️ [Lease Expired] ${deviceId} marked OFFLINE (v${nextVersion})`);

            if (device.ws.readyState === WebSocket.OPEN) {
                device.ws.terminate();
            }
        }
    }
}, CLEANUP_INTERVAL);

// ── 10. Transport-Level Keepalive Ping (Every 60 Seconds with 2-Miss Tolerance) ──

const pingInterval = setInterval(() => {
    wss.clients.forEach((ws) => {
        if ((ws.missedPings || 0) >= 2) {
            console.log(`⚠️ Terminating dead socket after 2 missed pings (conn: ${ws.connectionId})`);
            return ws.terminate();
        }
        ws.missedPings = (ws.missedPings || 0) + 1;
        ws.ping();
    });
}, 60000);

wss.on('close', () => clearInterval(pingInterval));

// Pre-warm ICE cache at boot
getIceServers();

const PORT = process.env.PORT || 8080;
server.listen(PORT, () => {
    console.log(`🚀 Parenty Signaling & Presence Gateway v2.1 running on port ${PORT}`);
});
