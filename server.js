// server.js
// Minimal WS relay with rooms, heartbeats, and basic rate limiting.

import http from 'node:http';
import { WebSocketServer } from 'ws';
import crypto from 'node:crypto';
import url from 'node:url';

const PORT = process.env.PORT || 8080;

// --- basic rate limiter (per IP) ---
const RATE_WINDOW_MS = 5_000;     // 5s window
const RATE_MAX_MESSAGES = 12;     // max messages per window
const ipBuckets = new Map();      // ip -> {count, resetAt}

function allowed(ip) {
  const now = Date.now();
  const b = ipBuckets.get(ip) || { count: 0, resetAt: now + RATE_WINDOW_MS };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + RATE_WINDOW_MS; }
  b.count++;
  ipBuckets.set(ip, b);
  return b.count <= RATE_MAX_MESSAGES;
}

// --- rooms ---
const rooms = new Map();          // roomName -> Set<ws>

// broadcast helper
function broadcast(room, data, except) {
  const set = rooms.get(room);
  if (!set) return;
  const msg = JSON.stringify(data);
  for (const client of set) {
    if (client !== except && client.readyState === client.OPEN) {
      client.send(msg);
    }
  }
}

// HTTP server (for health checks)
const server = http.createServer((req, res) => {
  if (req.url === '/health') {
    res.writeHead(200, { 'content-type': 'text/plain' });
    res.end('ok');
    return;
  }
  res.writeHead(404);
  res.end();
});

const wss = new WebSocketServer({ server, path: '/chat' });

// heartbeat/cleanup
function heartbeat() { this.isAlive = true; }

wss.on('connection', (ws, req) => {
  ws.id = crypto.randomUUID();
  ws.isAlive = true;
  ws.on('pong', heartbeat);

  // parse room & name from query
  const { query } = url.parse(req.url, true);
  const room = (query.room || 'global').toString().slice(0, 64);
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').toString();
  ws.meta = {
    ip,
    name: (query.name || 'anon').toString().slice(0, 24),
    room,
  };

  if (!rooms.has(room)) rooms.set(room, new Set());
  rooms.get(room).add(ws);

  // announce join
  broadcast(room, { type: 'system', text: `${ws.meta.name} joined`, ts: Date.now() });
  ws.send(JSON.stringify({ type: 'hello', you: ws.meta.name, room }));

  ws.on('message', (raw) => {
    if (!allowed(ip)) return; // drop if rate-limited
    let msg;
    try { msg = JSON.parse(raw.toString()); } catch { return; }

    if (typeof msg !== 'object' || !msg) return;
    // supported client events: {type:'say', text:'...'} or {type:'rename', name:'...'}
    if (msg.type === 'rename') {
      const old = ws.meta.name;
      ws.meta.name = (msg.name || 'anon').toString().slice(0, 24);
      broadcast(room, { type: 'system', text: `${old} is now ${ws.meta.name}`, ts: Date.now() });
      return;
    }
    if (msg.type === 'say') {
      const text = (msg.text || '').toString().slice(0, 400);
      if (!text.trim()) return;
      broadcast(room, {
        type: 'msg',
        from: ws.meta.name,
        text,
        ts: Date.now(),
      });
      return;
    }
  });

  ws.on('close', () => {
    const set = rooms.get(room);
    if (set) {
      set.delete(ws);
      if (!set.size) rooms.delete(room);
    }
    broadcast(room, { type: 'system', text: `${ws.meta.name} left`, ts: Date.now() });
  });
});

// ping clients to keep connections fresh
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, 30_000);

server.listen(PORT, () => {
  console.log('chat ws listening on :' + PORT + '  (path: /chat)');
});
