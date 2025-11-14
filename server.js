// server.js
// WebSocket chat relay with rooms, rate-limit, heartbeats, keepalive,
// admin views, key management (DB-backed), one-connection-per-key,
// and revocation kicks via SSE + WS close.

import http from "node:http";
import { WebSocketServer } from "ws";
import url from "node:url";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// =================== CONFIG ===================
const PORT = process.env.PORT || 8080;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";   // for /admin/keys
const DATABASE_URL = process.env.DATABASE_URL || "";

// -------------------- DB (keys) --------------------
let KeyStore; // { listKeys, findKey, generateKey, revokeKey }

if (DATABASE_URL) {
  const { Pool } = await import("pg").then(m => m.default || m);
  const pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_keys (
      id SERIAL PRIMARY KEY,
      label TEXT NOT NULL,
      key_value TEXT UNIQUE NOT NULL,
      revoked BOOLEAN NOT NULL DEFAULT FALSE,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    CREATE INDEX IF NOT EXISTS chat_keys_key_idx ON chat_keys(key_value);
  `);

  KeyStore = {
    async listKeys() {
      const { rows } = await pool.query(
        `SELECT label, key_value AS key, revoked, created_at AS "createdAt"
         FROM chat_keys ORDER BY created_at DESC`
      );
      return rows;
    },
    async findKey(key) {
      const { rows } = await pool.query(
        `SELECT label, key_value AS key, revoked, created_at AS "createdAt"
         FROM chat_keys WHERE key_value = $1 LIMIT 1`,
        [key]
      );
      return rows[0] || null;
    },
    async generateKey(label = "") {
      const key = crypto.randomBytes(16).toString("hex"); // 32 hex
      const { rows } = await pool.query(
        `INSERT INTO chat_keys(label, key_value) VALUES($1,$2)
         RETURNING label, key_value AS key, revoked, created_at AS "createdAt"`,
        [label, key]
      );
      return rows[0];
    },
    async revokeKey(key) {
      const { rowCount } = await pool.query(
        `UPDATE chat_keys SET revoked = TRUE WHERE key_value = $1`,
        [key]
      );
      return rowCount > 0;
    }
  };
  console.log("[keys] Using PostgreSQL store");
} else {
  // JSON file fallback
  const KEYS_FILE = path.join(process.cwd(), "data", "keys.json");
  function ensureKeysFile() {
    const dir = path.dirname(KEYS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (!fs.existsSync(KEYS_FILE)) fs.writeFileSync(KEYS_FILE, "[]");
  }
  function readKeys() {
    ensureKeysFile();
    try { return JSON.parse(fs.readFileSync(KEYS_FILE, "utf8") || "[]"); }
    catch { return []; }
  }
  function writeKeys(arr) {
    ensureKeysFile();
    const tmp = KEYS_FILE + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(arr, null, 2));
    fs.renameSync(tmp, KEYS_FILE);
  }

  KeyStore = {
    async listKeys() { return readKeys(); },
    async findKey(key) { return readKeys().find(k => k.key === key) || null; },
    async generateKey(label = "") {
      const arr = readKeys();
      const key = crypto.randomBytes(16).toString("hex");
      const item = {
        key,
        label,
        revoked: false,
        createdAt: new Date().toISOString()
      };
      arr.push(item);
      writeKeys(arr);
      return item;
    },
    async revokeKey(key) {
      const arr = readKeys();
      const i = arr.findIndex(k => k.key === key);
      if (i < 0) return false;
      arr[i].revoked = true;
      writeKeys(arr);
      return true;
    }
  };
  console.log("[keys] Using file store at ./data/keys.json");
}

// =================== RATE LIMITING ===================
const RATE_WINDOW_MS = 5_000;
const RATE_MAX_MESSAGES = 12;
const ipBuckets = new Map(); // ip -> {count, resetAt}

function allowed(ip) {
  const now = Date.now();
  const bucket = ipBuckets.get(ip) || { count: 0, resetAt: now + RATE_WINDOW_MS };
  if (now > bucket.resetAt) {
    bucket.count = 0;
    bucket.resetAt = now + RATE_WINDOW_MS;
  }
  bucket.count++;
  ipBuckets.set(ip, bucket);
  return bucket.count <= RATE_MAX_MESSAGES;
}

// =================== LOGS ===================
const roomLogs = new Map(); // room -> [{ ts, from, text }]
const MAX_LOGS = Number(process.env.MAX_LOGS || 2000);

function appendLog(room, entry) {
  if (!roomLogs.has(room)) roomLogs.set(room, []);
  const arr = roomLogs.get(room);
  arr.push({
    ts: entry.ts || Date.now(),
    from: String(entry.from || ""),
    text: String(entry.text || "")
  });
  if (arr.length > MAX_LOGS) {
    arr.splice(0, arr.length - MAX_LOGS);
  }
}

// =================== ROOMS & CONNECTIONS ===================
const rooms = new Map(); // roomName -> Set<ws>

function normalizeSkins(v) {
  if (!v) return ["", ""];
  const [a = "", b = ""] = v;
  return [String(a), String(b)];
}

// key -> Set<ws>  (for one-connection-per-key + revocation kick)
const keyToSockets = new Map();

// SSE revocation subscribers: key -> Set<res>
const sseClientsByKey = new Map();

function registerKeySocket(key, ws) {
  let set = keyToSockets.get(key);
  if (!set) {
    set = new Set();
    keyToSockets.set(key, set);
  }
  // kick any existing sockets for this key
  if (set.size) {
    for (const other of set) {
      if (other !== ws && other.readyState === other.OPEN) {
        try { other.close(4001, "Key in use on another tab"); } catch {}
      }
    }
    set.clear();
  }
  set.add(ws);
}

function unregisterKeySocket(key, ws) {
  if (!key) return;
  const set = keyToSockets.get(key);
  if (!set) return;
  set.delete(ws);
  if (!set.size) keyToSockets.delete(key);
}

function broadcast(room, payload, except) {
  if (payload && payload.type === "msg") {
    appendLog(room, { ts: payload.ts, from: payload.from, text: payload.text });
  }
  const set = rooms.get(room);
  if (!set) return;
  const msg = JSON.stringify(payload);
  for (const client of set) {
    if (client !== except && client.readyState === client.OPEN) {
      try { client.send(msg); } catch {}
    }
  }
}

// Kick all sockets + notify SSE clients on revocation
function notifyRevocation(key) {
  // Close all WebSocket connections using this key
  const set = keyToSockets.get(key);
  if (set) {
    for (const ws of set) {
      try { ws.close(4001, "Key revoked"); } catch {}
    }
    keyToSockets.delete(key);
  }

  // Notify SSE subscribers
  const subs = sseClientsByKey.get(key);
  if (subs) {
    const payload = `event: revoked\ndata: ${JSON.stringify({ key })}\n\n`;
    for (const res of subs) {
      try { res.write(payload); } catch {}
      try { res.end(); } catch {}
    }
    sseClientsByKey.delete(key);
  }
}

// =================== HTTP SERVER ===================
const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || "/";
  const method = req.method || "GET";

  // Health
  if (pathname === "/" || pathname === "/health") {
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end("ok");
    return;
  }

  // --- logs.json ---
  if (pathname === "/logs.json" && method === "GET") {
    const room = (parsed.query?.room ? String(parsed.query.room) : "").slice(0, 128);
    const msgs = room ? (roomLogs.get(room) || []) : [];
    const payload = JSON.stringify({ room, count: msgs.length, messages: msgs });
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*"
    });
    res.end(payload);
    return;
  }

  // --- logs/clear ---
  if (pathname === "/logs/clear") {
    const room = (parsed.query?.room ? String(parsed.query.room) : "").slice(0, 128);
    if (room) roomLogs.set(room, []);
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*"
    });
    res.end(JSON.stringify({ ok: true, room }));
    return;
  }

  // --- connections.json ---
  if (pathname === "/connections.json" && method === "GET") {
    const filterRoom = parsed.query?.room ? String(parsed.query.room) : null;
    const rows = [];
    wss.clients.forEach((ws) => {
      if (ws.readyState === ws.OPEN) {
        const meta = ws.meta || {};
        if (filterRoom && meta.room !== filterRoom) return;
        const { name = "anon", ip = "", room = "global", key = "" } = meta;
        const skins = normalizeSkins(ws.skin);
        rows.push({ room, name, ip, key, skins });
      }
    });
    const payload = JSON.stringify({ count: rows.length, clients: rows });
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*"
    });
    res.end(payload);
    return;
  }

  // --- connections (HTML) ---
  if (pathname === "/connections" && method === "GET") {
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
</style>
</head>
<body>
<h1>Current WebSocket Connections</h1>
<table id="tbl">
<thead><tr><th>#</th><th>Room</th><th>Name</th><th>IP</th><th>Key</th></tr></thead>
<tbody></tbody>
</table>
<script>
async function load(){
  const r = await fetch('/connections.json', {cache:'no-store'});
  const j = await r.json();
  const tb = document.querySelector('#tbl tbody');
  tb.innerHTML = '';
  (j.clients || []).forEach((c,i)=>{
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>'+ (i+1) +'</td>'
      + '<td>'+ (c.room||'') +'</td>'
      + '<td>'+ (c.name||'') +'</td>'
      + '<td>'+ (c.ip||'') +'</td>'
      + '<td>'+ (c.key||'') +'</td>';
    tb.appendChild(tr);
  });
  document.title = 'WS Connections ('+ j.count +')';
}
setInterval(load, 2000);
load();
</script>
</body>
</html>`);
    return;
  }

  // --- rooms.json ---
  if (pathname === "/rooms.json" && method === "GET") {
    const live = Array.from(rooms.keys());
    const logged = Array.from(roomLogs.keys());
    const all = Array.from(new Set([...live, ...logged])).sort();
    const payload = JSON.stringify({ count: all.length, rooms: all });
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*"
    });
    res.end(payload);
    return;
  }

  // --- serve admin.html ---
  if ((pathname === "/admin" || pathname === "/admin.html") && method === "GET") {
    const file = path.join(process.cwd(), "admin.html");
    fs.readFile(file, "utf8", (err, data) => {
      if (err) {
        res.writeHead(500, { "content-type": "text/plain; charset=utf-8" });
        res.end("admin.html not found");
        return;
      }
      res.writeHead(200, {
        "content-type": "text/html; charset=utf-8",
        "cache-control": "no-store"
      });
      res.end(data);
    });
    return;
  }

  // --- admin/keys (GET/POST/DELETE) ---
  if (pathname === "/admin/keys") {
    const adminTok = req.headers["x-admin-token"] || "";
    if (!ADMIN_TOKEN || adminTok !== ADMIN_TOKEN) {
      res.writeHead(401, {
        "content-type": "application/json; charset=utf-8",
        "access-control-allow-origin": "*"
      });
      res.end(JSON.stringify({ ok: false, error: "unauthorized" }));
      return;
    }

    if (method === "GET") {
      (async () => {
        const keys = await KeyStore.listKeys();
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "access-control-allow-origin": "*"
        });
        res.end(JSON.stringify(keys));
      })();
      return;
    }

    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 1e5) req.destroy();
    });
    req.on("end", async () => {
      let payload = {};
      try { payload = JSON.parse(body || "{}"); } catch {}

      if (method === "POST") {
        const label = String(payload.label || "").slice(0, 128);
        const item = await KeyStore.generateKey(label);
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "access-control-allow-origin": "*"
        });
        res.end(JSON.stringify(item));
        return;
      }

      if (method === "DELETE") {
        const key = String(payload.key || "");
        const ok = await KeyStore.revokeKey(key);
        if (ok) notifyRevocation(key);
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "access-control-allow-origin": "*"
        });
        res.end(JSON.stringify({ ok }));
        return;
      }

      res.writeHead(405).end();
    });
    return;
  }

  // --- POST /validate (overlay key check) ---
  if (pathname === "/validate" && method === "POST") {
    let body = "";
    req.on("data", chunk => {
      body += chunk;
      if (body.length > 1e5) req.destroy();
    });
    req.on("end", async () => {
      let key = "";
      try {
        const j = JSON.parse(body || "{}");
        key = String(j.key || "").trim();
      } catch {}

      if (!key) {
        res.writeHead(400, {
          "content-type": "application/json; charset=utf-8",
          "access-control-allow-origin": "*"
        });
        res.end(JSON.stringify({ ok: false, reason: "missing key" }));
        return;
      }

      const item = await KeyStore.findKey(key);
      if (!item || item.revoked) {
        res.writeHead(403, {
          "content-type": "application/json; charset=utf-8",
          "access-control-allow-origin": "*"
        });
        res.end(JSON.stringify({ ok: false, reason: "invalid or revoked" }));
        return;
      }

      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "access-control-allow-origin": "*"
      });
      res.end(JSON.stringify({ ok: true, key: item.key }));
    });
    return;
  }

  // --- GET /revocations/stream?key=... (SSE) ---
  if (pathname === "/revocations/stream" && method === "GET") {
    const key = String(parsed.query?.key || "").trim();
    if (!key) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("key required");
      return;
    }

    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-store",
      "connection": "keep-alive",
      "access-control-allow-origin": "*"
    });
    res.write(`event: open\ndata: {}\n\n`);

    let set = sseClientsByKey.get(key);
    if (!set) {
      set = new Set();
      sseClientsByKey.set(key, set);
    }
    set.add(res);

    req.on("close", () => {
      const s = sseClientsByKey.get(key);
      if (!s) return;
      s.delete(res);
      if (!s.size) sseClientsByKey.delete(key);
    });
    return;
  }

  // Fallback
  res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
  res.end("not found");
});

// =================== WEBSOCKET SERVER ===================
const wss = new WebSocketServer({ server, path: "/chat" });

// heartbeat
function heartbeat() { this.isAlive = true; }

setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) {
      try { ws.terminate(); } catch {}
      return;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  });
}, 30_000);

// server-side keepalive message to clients
const SERVER_KEEP_MS = 25_000;
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.readyState === ws.OPEN) {
      try { ws.send('{"type":"srv_keep"}'); } catch {}
    }
  });
}, SERVER_KEEP_MS);

// skins: nameHash -> [s1,s2]
const skinRegistry = new Map();

wss.on("connection", async (ws, req) => {
  ws.skin = ["", ""];
  ws.nameHash = "";
  ws.id = crypto.randomUUID();
  ws.isAlive = true;
  ws.on("pong", heartbeat);

  const { query } = url.parse(req.url, true);
  const room = String(query.room || "global").slice(0, 64);
  const name = String(query.name || "anon").slice(0, 24);
  const providedKey = query.key ? String(query.key).trim() : "";

  const ip = (
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    ""
  ).toString();

  // require key
  if (!providedKey) {
    console.log("[reject][no-key]", ip);
    try { ws.close(1008, "Key required"); } catch {}
    return;
  }

  const keyInfo = await KeyStore.findKey(providedKey);
  if (!keyInfo || keyInfo.revoked) {
    console.log("[reject][bad-key]", providedKey.slice(0, 8) + "...", ip);
    try { ws.close(1008, "Invalid or revoked key"); } catch {}
    return;
  }

  ws.meta = { room, name, ip, key: providedKey };

  // enforce 1 connection per key
  registerKeySocket(providedKey, ws);

  // join room
  if (!rooms.has(room)) rooms.set(room, new Set());
  rooms.get(room).add(ws);

  console.log("[join]", name, "room=", room, "ip=", ip, "key=", providedKey.slice(0, 8) + "...");

  // send bulk skins
  if (skinRegistry.size) {
    const data = [...skinRegistry.entries()].map(([h, [s1, s2]]) => [h, s1, s2]);
    try {
      ws.send(JSON.stringify({ t: "skin", op: "bulk", data }));
    } catch {}
  }

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
      const msg = {
        type: "msg",
        from: ws.meta.name,
        text,
        ts: Date.now()
      };
      broadcast(room, msg);
      console.log("[say]", ws.meta.name + ":", text, "room=", room);
      return;
    }

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
      wss.clients.forEach(c => {
        if (c.readyState === 1) {
          try { c.send(payload); fanout++; } catch {}
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
    unregisterKeySocket(providedKey, ws);
    console.log("[leave]", ws.meta.name, "room=", room, "key=", providedKey.slice(0, 8) + "...");
  });
});

server.listen(PORT, () => {
  console.log("WS listening on :" + PORT + " (path /chat)");
  if (!ADMIN_TOKEN) {
    console.warn("ADMIN_TOKEN not set – /admin/keys will reject.");
  }
});
