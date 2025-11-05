// server.js
// WebSocket chat relay with rooms, rate-limit, heartbeats, and SERVER-SIDE keepalive data frames.
// Adds /connections (HTML) and /connections.json (JSON) admin views showing: room, name, ip, skins.
// Extended with rolling chat logs per room: /logs.json and /logs/clear
// ✅ Extended with key-based gate + instant revocation via SSE:
//   - POST /validate
//   - GET  /revocations/stream?key=...
//   - Admin: GET/POST/DELETE /admin/keys  (x-admin-token required)
//   Keys are persisted in ./data/keys.json

import http from "node:http";
import { WebSocketServer } from "ws";
import url from "node:url";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const PORT = process.env.PORT || 8080;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";

// --- skins: nameHash -> [s1, s2]
const skinRegistry = new Map();

// Helper to stringify skins safely
function normalizeSkins(v) {
  if (!v) return ["", ""];
  const [a = "", b = ""] = v;
  return [String(a), String(b)];
}

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

// --- rolling chat logs per room ---
const roomLogs = new Map(); // room -> [{ ts, from, text }]
const MAX_LOGS = Number(process.env.MAX_LOGS || 2000);

function appendLog(room, entry) {
  if (!roomLogs.has(room)) roomLogs.set(room, []);
  const arr = roomLogs.get(room);
  arr.push({
    ts: entry.ts || Date.now(),
    from: String(entry.from || ""),
    text: String(entry.text || ""),
  });
  if (arr.length > MAX_LOGS) arr.splice(0, arr.length - MAX_LOGS);
}

// ---------- rooms ----------
const rooms = new Map(); // roomName -> Set<ws>
function broadcast(room, payload, except) {
  // Record only normal chat messages into history
  if (payload && payload.type === "msg") {
    appendLog(room, { ts: payload.ts, from: payload.from, text: payload.text });
  }

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

// =============== KEY STORE (./data/keys.json) ===============
const KEYS_FILE = path.join(process.cwd(), "data", "keys.json");
function ensureKeysFile() {
  const dir = path.dirname(KEYS_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  if (!fs.existsSync(KEYS_FILE)) fs.writeFileSync(KEYS_FILE, "[]");
}
function readKeys() {
  ensureKeysFile();
  try {
    return JSON.parse(fs.readFileSync(KEYS_FILE, "utf8") || "[]");
  } catch {
    return [];
  }
}
function writeKeys(arr) {
  fs.writeFileSync(KEYS_FILE, JSON.stringify(arr, null, 2));
}
function listKeys() {
  return readKeys();
}
function findKey(key) {
  return readKeys().find((k) => k.key === key);
}
function generateKey(label = "") {
  const arr = readKeys();
  const key = crypto.randomBytes(16).toString("hex"); // 32 hex chars
  const item = { key, label, revoked: false, createdAt: new Date().toISOString() };
  arr.push(item);
  writeKeys(arr);
  return item;
}
function revokeKey(key) {
  const arr = readKeys();
  const i = arr.findIndex((k) => k.key === key);
  if (i < 0) return null;
  arr[i].revoked = true;
  writeKeys(arr);
  return arr[i];
}

// =============== REVOCATION HUB (SSE) ===============
/**
 * Keep at most ONE active SSE client per key.
 * New connection for the same key kicks the previous one (single-session policy).
 */
const sseClients = new Map(); // key -> Set<ServerResponse>
function addSseClient(key, res) {
  if (!sseClients.has(key)) sseClients.set(key, new Set());
  const set = sseClients.get(key);
  // kick existing
  for (const r of set) {
    try {
      r.write(`event: revoked\ndata: {"reason":"duplicate"}\n\n`);
      r.end();
    } catch {}
  }
  set.clear();
  set.add(res);
}
function removeSseClient(key, res) {
  const set = sseClients.get(key);
  if (!set) return;
  set.delete(res);
  if (!set.size) sseClients.delete(key);
}
function broadcastRevoked(key) {
  const set = sseClients.get(key);
  if (!set) return;
  for (const r of set) {
    try {
      r.write(`event: revoked\ndata: {}\n\n`);
      r.end();
    } catch {}
  }
  sseClients.delete(key);
}

// =============== tiny helpers (native http) ===============
function sendJSON(res, code, obj, extraHeaders = {}) {
  res.writeHead(code, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    ...extraHeaders,
  });
  res.end(JSON.stringify(obj));
}
function sendText(res, code, text, extraHeaders = {}) {
  res.writeHead(code, {
    "content-type": "text/plain; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
    ...extraHeaders,
  });
  res.end(text);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        resolve(data ? JSON.parse(data) : {});
      } catch (e) {
        reject(e);
      }
    });
    req.on("error", reject);
  });
}

// ---------- tiny HTTP (health + admin + keys) ----------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || "/";

  // CORS preflight for our JSON endpoints
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type,x-admin-token",
      "cache-control": "no-store",
    });
    return res.end();
  }

  if (pathname === "/" || pathname === "/health") {
    return sendText(res, 200, "ok");
  }

  // === Chat log endpoints ===
  if (pathname === "/logs.json") {
    const room = (parsed.query?.room ? String(parsed.query.room) : "").slice(0, 128);
    const msgs = room ? (roomLogs.get(room) || []) : [];
    return sendJSON(res, 200, { room, count: msgs.length, messages: msgs });
  }

  if (pathname === "/logs/clear") {
    const room = (parsed.query?.room ? String(parsed.query.room) : "").slice(0, 128);
    if (room) roomLogs.set(room, []);
    return sendJSON(res, 200, { ok: true, room });
  }

  // === connections.json (for admin table) ===
  if (pathname === "/connections.json") {
    const filterRoom = parsed.query?.room ? String(parsed.query.room) : null;
    const rows = [];
    wss.clients.forEach((ws) => {
      if (ws.readyState === ws.OPEN) {
        const meta = ws.meta || {};
        if (filterRoom && meta.room !== filterRoom) return;
        const { name = "anon", ip = "", room = "global" } = meta;
        const skins = normalizeSkins(ws.skin);
        rows.push({ room, name, ip, skins });
      }
    });
    return sendJSON(res, 200, { count: rows.length, clients: rows });
  }

  // Simple HTML connections view
  if (pathname === "/connections") {
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(`<!doctype html>
<html>
<head>
<meta charset="utf-8">
<title>WS Connections</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  body{font:14px/1.4 system-ui,-apple-system,Segoe UI,Roboto,Arial,sans-serif; padding:20px;}
  table{border-collapse:collapse; width:100%; max-width:1100px;}
  th, td{border:1px solid #ddd; padding:8px; word-break:break-all;}
  th{background:#f7f7f7; text-align:left;}
  .muted{opacity:.6}
  .controls{margin:8px 0 16px}
  input[type="text"]{padding:6px 8px; width:260px; max-width:100%}
</style>
</head>
<body>
  <h1>Current WebSocket Connections</h1>
  <div class="controls">
    <label>Room filter: <input id="room" type="text" placeholder="(leave blank for all)"></label>
    <button id="apply">Apply</button>
    <span class="muted">Auto-refreshes every 2s.</span>
  </div>
  <table id="tbl">
    <thead><tr><th>#</th><th>Room</th><th>Name</th><th>IP</th><th>Skin 1</th><th>Skin 2</th></tr></thead>
    <tbody></tbody>
  </table>
<script>
let timer;
async function load() {
  const room = document.getElementById('room').value.trim();
  const qs = room ? ('?room=' + encodeURIComponent(room)) : '';
  try{
    const r = await fetch('/connections.json' + qs, {cache:'no-store'});
    const j = await r.json();
    const tb = document.querySelector('#tbl tbody');
    tb.innerHTML = '';
    j.clients.forEach((c, i) => {
      const tr = document.createElement('tr');
      const s1 = (c.skins && c.skins[0]) || '';
      const s2 = (c.skins && c.skins[1]) || '';
      tr.innerHTML = '<td>'+ (i+1) +'</td>'
                   + '<td>'+ (c.room || '') +'</td>'
                   + '<td>'+ (c.name || '') +'</td>'
                   + '<td>'+ (c.ip || '') +'</td>'
                   + '<td>'+ (s1 ? '<a href="'+s1+'" target="_blank" rel="noopener">'+s1+'</a>' : '') +'</td>'
                   + '<td>'+ (s2 ? '<a href="'+s2+'" target="_blank" rel="noopener">'+s2+'</a>' : '') +'</td>';
      tb.appendChild(tr);
    });
    document.title = 'WS Connections ('+ j.count +')';
  }catch(e){}
}
document.getElementById('apply').addEventListener('click', load);
timer = setInterval(load, 2000);
load();
</script>
</body>
</html>`);
    return;
  }

  // Serve admin dashboard (same-origin)
  if (pathname === "/admin" || pathname === "/admin.html") {
    const file = path.join(process.cwd(), "admin.html"); // put admin.html next to server.js
    fs.readFile(file, "utf8", (err, data) => {
      if (err) {
        return sendText(res, 500, "admin.html not found");
      }
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" });
      res.end(data);
    });
    return;
  }

  // === all known rooms (live + with history + optional rooms.json file) ===
  if (pathname === "/rooms.json") {
    const live = Array.from(rooms.keys());
    const logged = Array.from(roomLogs.keys());

    // Optional: merge a local rooms.json file { "rooms": ["ffa:global", "macro:global", ...] }
    let extra = [];
    try {
      const p = path.join(process.cwd(), "rooms.json");
      const txt = fs.readFileSync(p, "utf8");
      const j = JSON.parse(txt);
      if (Array.isArray(j.rooms)) extra = j.rooms.map(String);
    } catch (e) {
      // no file or invalid json -> ignore
    }

    const all = Array.from(new Set([...live, ...logged, ...extra])).sort();
    return sendJSON(res, 200, { count: all.length, rooms: all });
  }

  // ================= KEY ENDPOINTS =================

  // POST /validate  -> { ok, key } or 403
  if (pathname === "/validate" && req.method === "POST") {
    try {
      const body = await readJson(req);
      const key = String(body.key || "");
      const k = findKey(key);
      if (!k || k.revoked) return sendJSON(res, 403, { ok: false, reason: "invalid" });
      return sendJSON(res, 200, { ok: true, key: k.key });
    } catch {
      return sendJSON(res, 400, { ok: false, reason: "bad_json" });
    }
  }

  // GET /revocations/stream?key=...
  if (pathname === "/revocations/stream" && req.method === "GET") {
    const key = String(parsed.query?.key || "");
    const k = findKey(key);
    if (!k || k.revoked) {
      res.writeHead(403, {
        "content-type": "text/plain; charset=utf-8",
        "access-control-allow-origin": "*",
      });
      res.end("invalid");
      return;
    }

    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
      "access-control-allow-origin": "*",
    });
    // initial heartbeat
    try { res.write(`data: {"ok":true}\n\n`); } catch {}

    addSseClient(key, res);
    const hb = setInterval(() => {
      try { res.write(`data: {"t":${Date.now()}}\n\n`); } catch {}
    }, 25000);

    req.on("close", () => {
      clearInterval(hb);
      removeSseClient(key, res);
    });
    return;
  }

  // Admin: GET /admin/keys
  if (pathname === "/admin/keys" && req.method === "GET") {
    if (!ADMIN_TOKEN || req.headers["x-admin-token"] !== ADMIN_TOKEN) {
      return sendJSON(res, 401, { error: "unauthorized" });
    }
    return sendJSON(res, 200, listKeys());
  }

  // Admin: POST /admin/keys  body: { label }
  if (pathname === "/admin/keys" && req.method === "POST") {
    if (!ADMIN_TOKEN || req.headers["x-admin-token"] !== ADMIN_TOKEN) {
      return sendJSON(res, 401, { error: "unauthorized" });
    }
    try {
      const body = await readJson(req);
      const label = String(body.label || "");
      const item = generateKey(label);
      return sendJSON(res, 201, item);
    } catch {
      return sendJSON(res, 400, { error: "bad_json" });
    }
  }

  // Admin: DELETE /admin/keys  body: { key }
  if (pathname === "/admin/keys" && req.method === "DELETE") {
    if (!ADMIN_TOKEN || req.headers["x-admin-token"] !== ADMIN_TOKEN) {
      return sendJSON(res, 401, { error: "unauthorized" });
    }
    try {
      const body = await readJson(req);
      const key = String(body.key || "");
      const item = revokeKey(key);
      if (!item) return sendJSON(res, 404, { error: "not_found" });
      broadcastRevoked(item.key); // push to all clients -> they reload
      return sendJSON(res, 200, { ok: true });
    } catch {
      return sendJSON(res, 400, { error: "bad_json" });
    }
  }

  // 404
  res.writeHead(404, {
    "content-type": "text/plain; charset=utf-8",
    "access-control-allow-origin": "*",
  });
  res.end("not found");
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

// SERVER-SIDE KEEPALIVE frame
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
  ws.skin = ["", ""];
  ws.nameHash = "";
  ws.id = crypto.randomUUID();
  ws.isAlive = true;
  ws.on("pong", heartbeat);

  // --- send bulk skin snapshot to newcomer
  if (skinRegistry.size) {
    const data = [...skinRegistry.entries()].map(([h, [s1, s2]]) => [h, s1, s2]);
    try {
      ws.send(JSON.stringify({ t: "skin", op: "bulk", data }));
    } catch {}
  }

  const { query } = url.parse(req.url, true);
  const room = String(query.room || "global").slice(0, 64);
  const name = String(query.name || "anon").slice(0, 24);
  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString();

  ws.meta = { room, name, ip };

  if (!rooms.has(room)) rooms.set(room, new Set());
  rooms.get(room).add(ws);

  console.log("[join]", name, "room=", room, "ip=", ip);

  ws.on("message", (raw) => {
    let m;
    try {
      m = JSON.parse(raw.toString());
    } catch {
      return;
    }

    if (m.type === "ping" || m.type === "srv_keep") return;

    if (m.type === "rename") {
      const old = ws.meta.name;
      ws.meta.name = String(m.name || "anon").slice(0, 24);
      console.log("[rename]", old, "->", ws.meta.name, "room=", room);
      return;
    }

    if (m.type === "say") {
      if (!allowed(ip)) return;
      const text = String(m.text || "").slice(0, 400);
      if (!text.trim()) return;
      broadcast(room, { type: "msg", from: ws.meta.name, text, ts: Date.now() });
      console.log("[say]", ws.meta.name + ":", text, "room=", room);
      return;
    }

    // --- skin messages (same as before) ---
    if (m.t === "skin" && m.op === "announce" && typeof m.h === "string") {
      const s1 = (m.s1 || "").trim();
      const s2 = (m.s2 || "").trim();
      if (s1.length > 300 || s2.length > 300) return;
      if (s1 && !/^https?:\/\//i.test(s1)) return;
      if (s2 && !/^https?:\/\//i.test(s2)) return;
      ws.nameHash = m.h;
      ws.skin = [s1, s2];
      skinRegistry.set(m.h, [s1, s2]);
      const payload = JSON.stringify({ t: "skin", op: "update", h: m.h, s1, s2 });
      let fanout = 0;
      wss.clients.forEach((c) => {
        if (c.readyState === 1) {
          try {
            c.send(payload);
            fanout++;
          } catch {}
        }
      });
      console.log("[skin][announce]", m.h, fanout);
    }
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
  if (!ADMIN_TOKEN) console.warn("WARNING: ADMIN_TOKEN not set. Admin endpoints will reject requests.");
});
