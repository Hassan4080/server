// server.js
// WebSocket chat relay with rooms, rate-limit, heartbeats, and SERVER-SIDE keepalive data frames.
// Adds /connections (HTML) and /connections.json (JSON) admin views showing: room, name, ip, skins.
// Extended with rolling chat logs per room: /logs.json and /logs/clear

import http from "node:http";
import { WebSocketServer } from "ws";
import url from "node:url";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const PORT = process.env.PORT || 8080;

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

// ---------- tiny HTTP (health + admin) ----------
const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || "/";

  if (pathname === "/" || pathname === "/health") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }

  // === Chat log endpoints ===
  if (pathname === "/logs.json") {
    const room = (parsed.query?.room ? String(parsed.query.room) : "").slice(0, 128);
    const msgs = room ? (roomLogs.get(room) || []) : [];
    const payload = JSON.stringify({ room, count: msgs.length, messages: msgs });
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    });
    res.end(payload);
    return;
  }

  if (pathname === "/logs/clear") {
    const room = (parsed.query?.room ? String(parsed.query.room) : "").slice(0, 128);
    if (room) roomLogs.set(room, []);
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    });
    res.end(JSON.stringify({ ok: true, room }));
    return;
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
    const payload = JSON.stringify({ count: rows.length, clients: rows });
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*",
    });
    res.end(payload);
    return;
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
      res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
      res.end("admin.html not found");
      return;
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
  const payload = JSON.stringify({ count: all.length, rooms: all });
  res.writeHead(200, {
    "content-type": "application/json; charset=utf-8",
    "cache-control": "no-store",
    "access-control-allow-origin": "*",
  });
  res.end(payload);
  return;
}

  res.writeHead(404).end();
});

// ---------- WebSocket ----------
const wss = new WebSocketServer({ server, path: "/chat" });

// ping/pong heartbeat so we can drop dead sockets
function heartbeat() { this.isAlive = true; }
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  });
}, 30_000);

// SERVER-SIDE KEEPALIVE frame
const SERVER_KEEP_MS = 25_000;
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.readyState === ws.OPEN) {
      try { ws.send('{"type":"srv_keep"}'); } catch {}
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
  const ip = (
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    ""
  ).toString();

  ws.meta = { room, name, ip };

  if (!rooms.has(room)) rooms.set(room, new Set());
  rooms.get(room).add(ws);

  console.log("[join]", name, "room=", room, "ip=", ip);

  ws.on("message", (raw) => {
    let m;
    try { m = JSON.parse(raw.toString()); } catch { return; }

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
      const payload = JSON.stringify({ t:"skin", op:"update", h:m.h, s1, s2 });
      let fanout = 0;
      wss.clients.forEach(c => {
        if (c.readyState === 1) { try { c.send(payload); fanout++; } catch {} }
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
});
