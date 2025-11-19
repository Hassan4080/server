// server.js
// WebSocket chat relay with rooms, rate-limit, heartbeats, keepalive,
// admin views, key management (DB-backed or JSON), per-key-per-IP limit,
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

// Optional: keep or delete if no longer used
const FRONTEND_ORIGIN = process.env.FRONTEND_ORIGIN || "https://xprivate.vercel.app";

// ---- Origin allowlist ----
const ORIGIN_WHITELIST = [
  "https://xprivate.vercel.app",
  "https://delt.io",
];

function isAllowedOrigin(origin) {
  if (!origin) return false;
  return ORIGIN_WHITELIST.includes(origin.trim());
}

// ---- CORS helper ----
function setCORS(req, res) {
  const origin = req.headers.origin;

  if (isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin); // reflect allowed origin
    res.setHeader("Vary", "Origin");                      // avoid caching issues
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type, x-admin-token");
}

// =================== DB (keys) ===================
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
      arr.unshift(item);
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
const rateMap = new Map(); // ip -> [timestamps]

function canSend(ip) {
  const now = Date.now();
  let arr = rateMap.get(ip);
  if (!arr) {
    arr = [];
    rateMap.set(ip, arr);
  }
  while (arr.length && now - arr[0] > RATE_WINDOW_MS) {
    arr.shift();
  }
  if (arr.length >= RATE_MAX_MESSAGES) return false;
  arr.push(now);
  return true;
}

// =================== ROOMS & LOGS ===================
const rooms = new Map();           // roomName -> Set<ws>
const roomLogs = new Map();        // roomName -> string[]

function logRoom(room, line) {
  let arr = roomLogs.get(room);
  if (!arr) {
    arr = [];
    roomLogs.set(room, arr);
  }
  const ts = new Date().toISOString();
  arr.push(`[${ts}] ${line}`);
  if (arr.length > 200) {
    arr.splice(0, arr.length - 200);
  }
}

// skins: nameHash -> [s1,s2]
const skinRegistry = new Map();

// key -> (ip -> Set<ws>) for per-key-per-IP limit + revocation kicks
const keySessions = new Map();
const MAX_PER_KEY_PER_IP = 4;
// how many distinct IPs are allowed to use the same key at once
// e.g. main + bot = 2 IPs → allowed; a 3rd IP → revoke
const MAX_IPS_PER_KEY = 2;

// SSE revocation subscribers: key -> Set<res>
const sseClientsByKey = new Map();

function registerKeySocket(key, ip, ws) {
  let ipMap = keySessions.get(key);
  if (!ipMap) {
    ipMap = new Map(); // ip -> Set<ws>
    keySessions.set(key, ipMap);
  }
  let set = ipMap.get(ip);
  if (!set) {
    set = new Set();
    ipMap.set(ip, set);
  }
  if (set.size >= MAX_PER_KEY_PER_IP) {
    return false;
  }
  set.add(ws);
  return true;
}

function unregisterKeySocket(key, ip, ws) {
  if (!key) return;
  const ipMap = keySessions.get(key);
  if (!ipMap) return;
  const set = ipMap.get(ip);
  if (!set) return;
  set.delete(ws);
  if (!set.size) {
    ipMap.delete(ip);
  }
  if (!ipMap.size) {
    keySessions.delete(key);
  }
}

function broadcast(room, payload, except) {
  if (payload && payload.type === "msg") {
    logRoom(room, `CHAT ${payload.from}: ${payload.text}`);
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
  const ipMap = keySessions.get(key);
  if (ipMap) {
    for (const set of ipMap.values()) {
      for (const ws of set) {
        try { ws.close(4001, "Key revoked"); } catch {}
      }
    }
    keySessions.delete(key);
  }

  // Notify SSE subscribers
  const subs = sseClientsByKey.get(key);
  if (subs) {
    const payload = `event: revoked\ndata: ${JSON.stringify({ key })}\n\n`;
    for (const res of subs) {
      try { res.write(payload); } catch {}
      try { res.flushHeaders?.(); } catch {}
    }
    sseClientsByKey.delete(key);
  }
}

// =================== HTTP SERVER ===================
const server = http.createServer((req, res) => {
  setCORS(req, res);
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || "/";
  const method = req.method || "GET";

  // --- global preflight handler for CORS ---
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

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
  if (pathname === "/logs/clear" && method === "POST") {
    roomLogs.clear();
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*"
    });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // --- connections.json ---
  if (pathname === "/connections.json" && method === "GET") {
    const result = [];
    for (const [room, set] of rooms.entries()) {
      for (const ws of set) {
        const meta = ws.meta || {};
        result.push({
          room,
          name: meta.name || "",
          ip: meta.ip || "",
          key: meta.key ? meta.key.slice(0, 8) + "…" : "",
          skins: meta.skin || meta.skins || ["", ""]
        });
      }
    }
    const payload = JSON.stringify({ ok: true, connections: result });
    res.writeHead(200, {
      "content-type": "application/json; charset=utf-8",
      "cache-control": "no-store",
      "access-control-allow-origin": "*"
    });
    res.end(payload);
    return;
  }

  // --- simple HTML connections table (optional) ---
  if (pathname === "/connections" && method === "GET") {
    let html = `<!doctype html>
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
<thead>
<tr><th>Room</th><th>Name</th><th>IP</th><th>Key</th><th>Skins</th></tr>
</thead>
<tbody>
`;
    for (const [room, set] of rooms.entries()) {
      for (const ws of set) {
        const meta = ws.meta || {};
        html += `<tr>
<td>${room}</td>
<td>${meta.name || ""}</td>
<td>${meta.ip || ""}</td>
<td>${meta.key ? meta.key.slice(0, 8) + "…" : ""}</td>
<td>${(meta.skin || meta.skins || ["",""]).join(", ")}</td>
</tr>`;
      }
    }
    html += `</tbody></table>
</body></html>`;
    res.writeHead(200, { "content-type": "text/html; charset=utf-8" });
    res.end(html);
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
        "cache-control": "no-store",
        "access-control-allow-origin": "*"
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
      res.end(JSON.stringify({ ok: false, reason: "unauthorized" }));
      return;
    }

    if (method === "GET") {
      (async () => {
        const keys = KeyStore ? await KeyStore.listKeys() : [];
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "access-control-allow-origin": "*"
        });
        res.end(JSON.stringify({ ok: true, keys }));
      })();
      return;
    }

    if (method === "POST") {
      let body = "";
      req.on("data", (chunk) => { body += chunk; });
      req.on("end", async () => {
        let label = "";
        try {
          const j = JSON.parse(body || "{}");
          label = String(j.label || "").slice(0, 128);
        } catch {
          res.writeHead(400, {
            "content-type": "application/json; charset=utf-8",
            "access-control-allow-origin": "*"
          });
          res.end(JSON.stringify({ ok: false, reason: "invalid JSON" }));
          return;
        }
        if (!KeyStore) {
          res.writeHead(500, {
            "content-type": "application/json; charset=utf-8",
            "access-control-allow-origin": "*"
          });
          res.end(JSON.stringify({ ok: false, reason: "Key store not ready" }));
          return;
        }
        const rec = await KeyStore.generateKey(label);
        res.writeHead(200, {
          "content-type": "application/json; charset=utf-8",
          "access-control-allow-origin": "*"
        });
        res.end(JSON.stringify({ ok: true, key: rec }));
      });
      return;
    }

    if (method === "DELETE") {
      const key = String(parsed.query?.key || "").trim();
      if (!key) {
        res.writeHead(400, {
          "content-type": "application/json; charset=utf-8",
          "access-control-allow-origin": "*"
        });
        res.end(JSON.stringify({ ok: false, reason: "missing key" }));
        return;
      }
      if (!KeyStore) {
        res.writeHead(500, {
          "content-type": "application/json; charset=utf-8",
          "access-control-allow-origin": "*"
        });
        res.end(JSON.stringify({ ok: false, reason: "Key store not ready" }));
        return;
      }
      const changed = await KeyStore.revokeKey(key);
      if (changed) {
        notifyRevocation(key);
      }
      res.writeHead(200, {
        "content-type": "application/json; charset=utf-8",
        "access-control-allow-origin": "*"
      });
      res.end(JSON.stringify({ ok: true, revoked: changed }));
      return;
    }

    res.writeHead(405, {
      "content-type": "application/json; charset=utf-8",
      "access-control-allow-origin": "*"
    });
    res.end(JSON.stringify({ ok: false, reason: "method not allowed" }));
    return;
  }

  // --- POST /validate (overlay key check) ---
  if (pathname === "/validate" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => { body += chunk; });
    req.on("end", async () => {
      setCORS(req, res);

      let key = "";
      try {
        const j = JSON.parse(body || "{}");
        key = String(j.key || "").trim();
      } catch {
        res.writeHead(400, { "content-type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ ok: false, reason: "invalid JSON" }));
        return;
      }

      if (!KeyStore) {
        res.writeHead(500, { "content-type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ ok: false, reason: "Key store not ready" }));
        return;
      }

      const rec = await KeyStore.findKey(key);
      if (!rec || rec.revoked) {
        res.writeHead(403, { "content-type": "application/json; charset=utf-8" });
        res.end(JSON.stringify({ ok: false, reason: "invalid or revoked key" }));
        return;
      }

      res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
      res.end(JSON.stringify({ ok: true, label: rec.label || "" }));
    });
    return;
  }

  // --- SSE revocations stream ---
  if (pathname === "/revocations/stream") {
    const key = String(parsed.query?.key || "").trim();
    if (!key) {
      res.writeHead(400, { "content-type": "text/plain; charset=utf-8" });
      res.end("missing key");
      return;
    }

    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache, no-transform",
      connection: "keep-alive",
      "access-control-allow-origin": "*"
    });
    res.write(":ok\n\n");

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

  // 404 default
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

wss.on("connection", async (ws, req) => {
  const origin = req.headers.origin || "";
  if (!isAllowedOrigin(origin)) {
    try { ws.close(); } catch {}
    return;
  }

  ws.skin = ["", ""];
  ws.nameHash = "";
  ws.id = crypto.randomUUID();
  ws.isAlive = true;
  ws.on("pong", heartbeat);

  const { query } = url.parse(req.url, true);
  const room = String(query.room || "global").slice(0, 64);
  const name = String(query.name || "anon").slice(0, 24);
  const providedKey = query.key ? String(query.key).trim() : "";

  const rawIp = (
    req.headers["x-forwarded-for"] ||
    req.socket.remoteAddress ||
    ""
  ).toString();
  const clientIp = rawIp.split(",")[0].trim() || rawIp;

  // require key
  if (!providedKey) {
    console.log("[reject][no-key]", clientIp);
    try { ws.close(1008, "Key required"); } catch {}
    return;
  }

  const keyInfo = await KeyStore.findKey(providedKey);
  if (!keyInfo || keyInfo.revoked) {
    console.log("[reject][bad-key]", providedKey.slice(0, 8) + "...", clientIp);
    try { ws.close(1008, "Invalid or revoked key"); } catch {}
    return;
  }

  ws.meta = { room, name, ip: rawIp, key: providedKey };

  // === MULTI-IP PROTECTION ===
  // Allow up to MAX_IPS_PER_KEY distinct IPs per key (e.g. main + bot).
  // If a 3rd IP appears concurrently with the same key, treat as sharing/abuse
  // and revoke that key for everyone.
  const existingIpMap = keySessions.get(providedKey);
  if (existingIpMap) {
    const ips = new Set(existingIpMap.keys());
    ips.add(clientIp); // include this new connection
    if (ips.size > MAX_IPS_PER_KEY) {
      console.log(
        "[multi-ip][revoke]",
        "key has too many IPs",
        providedKey.slice(0, 8) + "...",
        "ips=",
        [...ips]
      );
      notifyRevocation(providedKey);
      try { ws.close(4002, "Key used from too many IPs"); } catch {}
      return;
    }
  }

  // per-key-per-IP limit
  if (!registerKeySocket(providedKey, clientIp, ws)) {
    console.log("[limit]", "too many sessions for key", providedKey.slice(0, 8) + "...", "ip=", clientIp);
    try { ws.close(1008, "Too many sessions for this key/IP"); } catch {}
    return;
  }

  // join room
  if (!rooms.has(room)) rooms.set(room, new Set());
  rooms.get(room).add(ws);

  ws.meta.skin = ws.meta.skin || ["", ""];
  console.log("[join]", name, "room=", room, "ip=", rawIp, "key=", providedKey.slice(0, 8) + "...");

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

    if (m.type === "ping" || m.type === "pong") {
      return;
    }

    if (m.type === "skin") {
      const s1 = typeof m.s1 === "string" ? m.s1.slice(0, 64) : "";
      const s2 = typeof m.s2 === "string" ? m.s2.slice(0, 64) : "";
      ws.skin = [s1, s2];
      const hash = m.hash ? String(m.hash).slice(0, 64) : "";
      ws.nameHash = hash;
      if (hash) {
        skinRegistry.set(hash, [s1, s2]);
      }
      return;
    }

    if (m.type === "msg") {
      const text = typeof m.text === "string" ? m.text.slice(0, 400) : "";
      if (!text.trim()) return;
      if (!canSend(clientIp)) {
        return;
      }
      const payload = {
        type: "msg",
        room,
        from: name,
        text,
        t: Date.now(),
        skins: ws.skin || ["",""],
      };
      broadcast(room, payload, ws);
      return;
    }
  });

  ws.on("close", () => {
    const room = ws.meta?.room;
    const providedKey = ws.meta?.key;
    const rawIp = ws.meta?.ip || "";
    const clientIp = rawIp.split(",")[0].trim() || rawIp;

    if (room && rooms.has(room)) {
      const set = rooms.get(room);
      set.delete(ws);
      if (!set.size) rooms.delete(room);
    }
    unregisterKeySocket(providedKey, clientIp, ws);
    console.log("[leave]", ws.meta?.name, "room=", room, "key=", providedKey ? providedKey.slice(0, 8) + "..." : "unknown");
  });
});

server.listen(PORT, () => {
  console.log("WS listening on :" + PORT + " (path /chat)");
  if (!ADMIN_TOKEN) {
    console.warn("ADMIN_TOKEN not set – /admin/keys will reject.");
  }
});
