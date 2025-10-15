// server.js
// WebSocket chat relay with rooms, rate-limit, heartbeats, and SERVER-SIDE keepalive data frames.

import http from "node:http";
import { WebSocketServer } from "ws";
import url from "node:url";
import crypto from "node:crypto";

const PORT = process.env.PORT || 8080;

// ---------- simple per-IP rate limit ----------
const RATE_WINDOW_MS = 5_000;
const RATE_MAX_MESSAGES = 12;
const ipBuckets = new Map(); // ip -> {count, resetAt}
function allowed(ip) {
  const now = Date.now();
  const b = ipBuckets.get(ip) || { count: 0, resetAt: now + RATE_WINDOW_MS };
  if (now > b.resetAt) {
    b.count = 0;
    b.resetAt = now + RATE_WINDOW_MS;
  }
  b.count++;
  ipBuckets.set(ip, b);
  return b.count <= RATE_MAX_MESSAGES;
}

// ---------- rooms ----------
const rooms = new Map(); // roomName -> Set<ws>
function broadcast(room, payload, except) {
  const set = rooms.get(room);
  if (!set) return;
  const msg = JSON.stringify(payload);
  for (const client of set) {
    if (client !== except && client.readyState === client.OPEN) {
      try {
        client.send(msg);
      } catch {}
    }
  }
}

// ---------- tiny HTTP (for health) ----------
const server = http.createServer((req, res) => {
  if (req.url === "/" || req.url === "/health") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }
  res.writeHead(404).end();
});

// ---------- WebSocket ----------
const wss = new WebSocketServer({ server, path: "/chat" });

// ping/pong heartbeat so we can drop dead sockets
function heartbeat() {
  this.isAlive = true;
}
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    try {
      ws.ping();
    } catch {}
  });
}, 30_000);

// SERVER-SIDE KEEPALIVE: send a small DATA frame periodically
// Some proxies ignore control frames (ping/pong) for idleness.
const SERVER_KEEP_MS = 25_000;
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.readyState === ws.OPEN) {
      try {
        ws.send('{"type":"srv_keep"}');
      } catch {}
    }
  });
}, SERVER_KEEP_MS);

wss.on("connection", (ws, req) => {
  ws.id = crypto.randomUUID();
  ws.isAlive = true;
  ws.on("pong", heartbeat);

  const { query } = url.parse(req.url, true);
  const room = String(query.room || "global").slice(0, 64);
  const name = String(query.name || "anon").slice(0, 24);
  const ip = (
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    ""
  ).toString();

  ws.meta = { room, name, ip };

  if (!rooms.has(room)) rooms.set(room, new Set());
  rooms.get(room).add(ws);

  // Optional logs to Replit console (comment out if you want it quiet)
  console.log("[join]", name, "room=", room, "ip=", ip);

  ws.on("message", (raw) => {
    let m;
    try {
      m = JSON.parse(raw.toString());
    } catch {
      return;
    }

    // Ignore client keepalives (if any)
    if (m.type === "ping" || m.type === "srv_keep") return;

    if (m.type === "rename") {
      const old = ws.meta.name;
      ws.meta.name = String(m.name || "anon").slice(0, 24);
      // silent rename (no broadcast)
      console.log("[rename]", old, "->", ws.meta.name, "room=", room);
      return;
    }

    if (m.type === "say") {
      if (!allowed(ip)) return; // rate-limit
      const text = String(m.text || "").slice(0, 400);
      if (!text.trim()) return;
      broadcast(room, {
        type: "msg",
        from: ws.meta.name,
        text,
        ts: Date.now(),
      });
      console.log("[say]", ws.meta.name + ":", text, "room=", room);
      return;
    }

    // Unknown message type -> ignore silently
  });

  ws.on("close", () => {
    const set = rooms.get(room);
    if (set) {
      set.delete(ws);
      if (!set.size) rooms.delete(room);
    }
    console.log("[leave]", ws.meta.name, "room=", room);
  });
});

server.listen(PORT, () => {
  console.log("WS listening on :" + PORT + " (path /chat)");
});
