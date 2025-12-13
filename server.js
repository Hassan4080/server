// server.js
// WebSocket chat relay with rooms, rate-limit, heartbeats, keepalive,
// admin.html support, admin key UI, DB/JSON key storage, SSE revocation,
// per-key-per-IP limit, multi-IP protection, logs, etc.

import http from "node:http";
import { WebSocketServer } from "ws";
import url from "node:url";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// =============================================================
//                         CONFIG
// =============================================================
const PORT = process.env.PORT || 8080;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const DATABASE_URL = process.env.DATABASE_URL || "";

// allowlist
const ORIGIN_WHITELIST = [
  "https://xprivate.vercel.app",
  "https://delt.io",
  "https://xpritest.vercel.app"
];

function isAllowedOrigin(origin) {
  return origin && ORIGIN_WHITELIST.includes(origin.trim());
}

function setCORS(req, res) {
  const origin = req.headers.origin;
  if (isAllowedOrigin(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
  }
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "content-type,x-admin-token,x-conn-token,x-logs-token");
}

// =============================================================
//                       KEY STORE
// =============================================================
let KeyStore;

if (DATABASE_URL) {
  // ---- PostgreSQL mode ----
  const { Pool } = await import("pg");
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
    CREATE INDEX IF NOT EXISTS chat_keys_key_idx
    ON chat_keys(key_value);
  `);

  KeyStore = {
    async listKeys() {
      const { rows } = await pool.query(`
        SELECT
          label,
          key_value AS key,
          revoked,
          created_at AS "createdAt"
        FROM chat_keys
        ORDER BY created_at DESC
      `);
      return rows;
    },

    async findKey(key) {
      const { rows } = await pool.query(
        `
        SELECT
          label,
          key_value AS key,
          revoked,
          created_at AS "createdAt"
        FROM chat_keys
        WHERE key_value = $1
        LIMIT 1
        `,
        [key]
      );
      return rows[0] || null;
    },

    async generateKey(label = "") {
      const key = crypto.randomBytes(16).toString("hex");
      const { rows } = await pool.query(
        `
        INSERT INTO chat_keys(label, key_value)
        VALUES ($1, $2)
        RETURNING
          label,
          key_value AS key,
          revoked,
          created_at AS "createdAt"
        `,
        [label, key]
      );
      return rows[0];
    },

    async revokeKey(key) {
      const { rowCount } = await pool.query(
        `
        UPDATE chat_keys
        SET revoked = TRUE
        WHERE key_value = $1
        `,
        [key]
      );
      return rowCount > 0;
    }
  };

  console.log("[keys] Using PostgreSQL store");
} else {
  // ---- JSON file mode ----
  const KEYS_FILE = path.join(process.cwd(), "data", "keys.json");

  function ensureFile() {
    const dir = path.dirname(KEYS_FILE);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    if (!fs.existsSync(KEYS_FILE)) fs.writeFileSync(KEYS_FILE, "[]");
  }

  function readKeys() {
    ensureFile();
    try {
      return JSON.parse(fs.readFileSync(KEYS_FILE, "utf8"));
    } catch {
      return [];
    }
  }

  function writeKeys(arr) {
    ensureFile();
    fs.writeFileSync(KEYS_FILE, JSON.stringify(arr, null, 2));
  }

  KeyStore = {
    async listKeys() {
      return readKeys();
    },

    async findKey(key) {
      return readKeys().find(k => k.key === key) || null;
    },

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
      const idx = arr.findIndex(k => k.key === key);
      if (idx < 0) return false;
      arr[idx].revoked = true;
      writeKeys(arr);
      return true;
    }
  };

  console.log("[keys] Using JSON file store: ./data/keys.json");
}

// =============================================================
//                     ROOMS / LOGS / SKINS
// =============================================================
const rooms = new Map();      // room -> Set<ws>
const roomLogs = new Map();   // room -> string[]
const skinRegistry = new Map();
const pidSkinRegistry = new Map();   // NEW: room -> Map<playerID, skinUrl>

function logRoom(room, line) {
  let arr = roomLogs.get(room);
  if (!arr) {
    arr = [];
    roomLogs.set(room, arr);
  }
  arr.push(`[${new Date().toISOString()}] ${line}`);
  if (arr.length > 200) arr.splice(0, arr.length - 200);
}

// =============================================================
//                 KEY SESSIONS (IP tracking)
// =============================================================
const keySessions = new Map(); // key -> (ip -> Set<ws>)
const MAX_PER_KEY_PER_IP = 4;
const MAX_IPS_PER_KEY = 2;     // main + bot allowed; 3rd IP => revoke

function registerKeySocket(key, ip, ws) {
  let ipMap = keySessions.get(key);
  if (!ipMap) {
    ipMap = new Map();
    keySessions.set(key, ipMap);
  }
  let set = ipMap.get(ip);
  if (!set) {
    set = new Set();
    ipMap.set(ip, set);
  }
  if (set.size >= MAX_PER_KEY_PER_IP) return false;
  set.add(ws);
  return true;
}

function unregisterKeySocket(key, ip, ws) {
  const ipMap = keySessions.get(key);
  if (!ipMap) return;
  const set = ipMap.get(ip);
  if (!set) return;

  set.delete(ws);
  if (set.size === 0) ipMap.delete(ip);
  if (ipMap.size === 0) keySessions.delete(key);
}

// =============================================================
//                  SSE CLIENTS (revocation)
// =============================================================
const sseClientsByKey = new Map(); // key -> Set<res>

function notifyRevocation(key) {
  // Close WebSockets
  const ipMap = keySessions.get(key);
  if (ipMap) {
    for (const set of ipMap.values()) {
      for (const ws of set) {
        try { ws.close(4001, "Key revoked"); } catch {}
      }
    }
    keySessions.delete(key);
  }

  // Notify SSE clients
  const subs = sseClientsByKey.get(key);
  if (subs) {
    const msg = `event: revoked\ndata: ${JSON.stringify({ key })}\n\n`;
    for (const res of subs) {
      try { res.write(msg); } catch {}
    }
    sseClientsByKey.delete(key);
  }
}

// =============================================================
//                     RATE LIMIT
// =============================================================
const RATE_WINDOW = 5000;
const RATE_LIMIT = 12;
const rateMap = new Map(); // ip -> timestamps[]

function canSend(ip) {
  const now = Date.now();
  let arr = rateMap.get(ip);
  if (!arr) {
    arr = [];
    rateMap.set(ip, arr);
  }
  while (arr.length && now - arr[0] > RATE_WINDOW) arr.shift();
  if (arr.length >= RATE_LIMIT) return false;
  arr.push(now);
  return true;
}

// =============================================================
//                      HTTP SERVER
// =============================================================
const server = http.createServer((req, res) => {
  setCORS(req, res);
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname;
  const method = req.method;

  if (method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  // health
  if (pathname === "/" || pathname === "/health") {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end("ok");
    return;
  }

  // logs.json
  if (pathname === "/logs.json" && method === "GET") {
    const room = String(parsed.query.room || "").slice(0, 128);
    const msgs = room ? roomLogs.get(room) || [] : [];
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, room, messages: msgs }));
    return;
  }

  // logs/clear (global)
  if (pathname === "/logs/clear" && method === "POST") {
    roomLogs.clear();
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
    return;
  }

  // connections.json
  if (pathname === "/connections.json" && method === "GET") {
    const snapshot = [];

    for (const [room, set] of rooms.entries()) {
      for (const ws of set) {
        const meta = ws.meta || {};
        snapshot.push({
          room,
          name: meta.name || "",
          key: meta.key ? meta.key.slice(0, 8) + "…" : "",
          skins: meta.skin || ["", ""]
        });
      }
    }

    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, connections: snapshot }));
    return;
  }

  // rooms.json  (used by admin.html to discover rooms)
  if (pathname === "/rooms.json" && method === "GET") {
    const list = Array.from(rooms.keys());
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true, rooms: list }));
    return;
  }

  // admin.html
  if ((pathname === "/admin" || pathname === "/admin.html") && method === "GET") {
    const file = path.join(process.cwd(), "admin.html");
    fs.readFile(file, "utf8", (err, data) => {
      if (err) {
        res.writeHead(500, { "content-type": "text/plain" });
        res.end("admin.html not found");
        return;
      }
      res.writeHead(200, { "content-type": "text/html" });
      res.end(data);
    });
    return;
  }

  // ============================
  //        /admin/keys
  // ============================
  if (pathname === "/admin/keys") {
    const adminTok = req.headers["x-admin-token"] || "";
    if (!ADMIN_TOKEN || adminTok !== ADMIN_TOKEN) {
      res.writeHead(401, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "unauthorized" }));
      return;
    }

    // GET — list keys
    if (method === "GET") {
      KeyStore.listKeys()
        .then(keys => {
          res.writeHead(200, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: true, keys }));
        })
        .catch(err => {
          console.error("[admin/keys][GET]", err);
          res.writeHead(500, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "internal error" }));
        });
      return;
    }

    // POST / DELETE — need body
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", () => {
      let json = {};
      try { json = JSON.parse(body || "{}"); } catch {}

      // POST — generate key
      if (method === "POST") {
        const label = String(json.label || "").slice(0, 128);
        KeyStore.generateKey(label)
          .then(rec => {
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: true, key: rec }));
          })
          .catch(err => {
            console.error("[admin/keys][POST]", err);
            res.writeHead(500, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: false, error: "internal error" }));
          });
        return;
      }

      // DELETE — revoke key
      if (method === "DELETE") {
        const key = String(json.key || "").trim();
        if (!key) {
          res.writeHead(400, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, error: "missing key" }));
          return;
        }

        KeyStore.revokeKey(key)
          .then(changed => {
            if (changed) notifyRevocation(key);
            res.writeHead(200, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: changed }));
          })
          .catch(err => {
            console.error("[admin/keys][DELETE]", err);
            res.writeHead(500, { "content-type": "application/json" });
            res.end(JSON.stringify({ ok: false, error: "internal error" }));
          });
        return;
      }

      // other methods
      res.writeHead(405, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, error: "method not allowed" }));
    });

    return;
  }

  // POST /validate
  if (pathname === "/validate" && method === "POST") {
    let body = "";
    req.on("data", chunk => { body += chunk; });
    req.on("end", async () => {
      let json = {};
      try { json = JSON.parse(body || "{}"); } catch {}
      const key = String(json.key || "").trim();

      const rec = await KeyStore.findKey(key);
      if (!rec || rec.revoked) {
        res.writeHead(403, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, error: "invalid or revoked key" }));
        return;
      }

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true, label: rec.label || "" }));
    });
    return;
  }

  // SSE: revocations/stream
  if (pathname === "/revocations/stream") {
    const key = String(parsed.query.key || "").trim();
    if (!key) {
      res.writeHead(400, { "content-type": "text/plain" });
      res.end("missing key");
      return;
    }

    res.writeHead(200, {
      "content-type": "text/event-stream; charset=utf-8",
      "cache-control": "no-cache",
      "connection": "keep-alive"
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
      if (s.size === 0) sseClientsByKey.delete(key);
    });

    return;
  }

  // 404
  res.writeHead(404, { "content-type": "text/plain" });
  res.end("not found");
});

// =============================================================
//                      WEBSOCKETS
// =============================================================
const wss = new WebSocketServer({ server, path: "/chat" });

function heartbeat() { this.isAlive = true; }

setInterval(() => {
  wss.clients.forEach(ws => {
    if (!ws.isAlive) {
      try { ws.terminate(); } catch {}
      return;
    }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  });
}, 30000);

// keepalive data frame (helps some proxies)
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.readyState === ws.OPEN) {
      try { ws.send('{"type":"srv_keep"}'); } catch {}
    }
  });
}, 25000);

wss.on("connection", async (ws, req) => {
  const origin = req.headers.origin || "";
  if (!isAllowedOrigin(origin)) {
    try { ws.close(); } catch {}
    return;
  }

  ws.isAlive = true;
  ws.on("pong", heartbeat);

  ws.skin = ["", ""];
  ws.nameHash = "";
  ws.pids = new Set(); // track playerIDs whose skins this socket owns

  const { query } = url.parse(req.url, true);
  const room = String(query.room || "global").slice(0, 64);
  const initialName = String(query.name || "Anon").slice(0, 24);
  const providedKey = String(query.key || "").trim();

  const rawIp = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString();
  const clientIp = rawIp.split(",")[0].trim() || rawIp;

  if (!providedKey) {
    try { ws.close(1008, "Key required"); } catch {}
    return;
  }

  const keyInfo = await KeyStore.findKey(providedKey);
  if (!keyInfo || keyInfo.revoked) {
    try { ws.close(1008, "Invalid or revoked key"); } catch {}
    return;
  }

  ws.meta = {
    room,
    name: initialName,
    key: providedKey,
    skin: ws.skin
  };

  // MULTI-IP RULE
  const existing = keySessions.get(providedKey);
  if (existing) {
    const ips = new Set(existing.keys());
    ips.add(clientIp);
    if (ips.size > MAX_IPS_PER_KEY) {
      notifyRevocation(providedKey);
      try { ws.close(4002, "Too many IPs for key"); } catch {}
      return;
    }
  }

  // per-IP tab limit
  if (!registerKeySocket(providedKey, clientIp, ws)) {
    try { ws.close(1008, "Too many sessions for this IP"); } catch {}
    return;
  }

  // join room registry
  if (!rooms.has(room)) rooms.set(room, new Set());
  rooms.get(room).add(ws);

  // send skin registry in bulk
  if (skinRegistry.size) {
    const bulk = [...skinRegistry.entries()].map(([h, [a, b]]) => [h, a, b]);
    try {
      ws.send(JSON.stringify({ t: "skin", op: "bulk", data: bulk }));
    } catch {}
  }
  // NEW: send playerID-based skins for this room
  const pidMap = pidSkinRegistry.get(room);
  if (pidMap && pidMap.size) {
    const bulkPID = [...pidMap.entries()].map(([playerID, skin]) => ({
      playerID,
      skin
    }));
    try {
      ws.send(JSON.stringify({
        type: "skinSyncByPID",
        skins: bulkPID
      }));
    } catch {}
  }

  // ------------- MESSAGE HANDLER -------------
  ws.on("message", data => {
    let msg;
    try { msg = JSON.parse(data.toString()); }
    catch { return; }

    if (msg.type === "ping" || msg.type === "pong") return;

    // skin update from client
    if (msg.type === "skin") {
      const s1 = String(msg.s1 || "").slice(0, 64);
      const s2 = String(msg.s2 || "").slice(0, 64);
      ws.skin = [s1, s2];
      ws.meta.skin = ws.skin;
      const hash = String(msg.hash || "").slice(0, 64);
      ws.nameHash = hash;
      if (hash) skinRegistry.set(hash, [s1, s2]);
      return;
    }
    // NEW: playerID-based skin updates
    if (msg.type === "skinByPID") {
      const pid = Number(msg.playerID);
      let skin = String(msg.skin || "").slice(0, 128);
    
      if (!Number.isFinite(pid) || !skin) return;
    
      // store in per-room registry
      let map = pidSkinRegistry.get(room);
      if (!map) {
        map = new Map();
        pidSkinRegistry.set(room, map);
      }

      // 👇 NEW: don't rebroadcast if skin didn't change
      const prev = map.get(pid);
      if (prev === skin) {
        return; // same skin already known for this pid in this room
      }

      map.set(pid, skin);
      ws.pids.add(pid);  // 👈 remember that this socket owns this playerID
      
      const payload = {
        type: "skinByPID",
        room,
        playerID: pid,
        skin
      };

      const set = rooms.get(room) || new Set();
      const line = JSON.stringify(payload);
      for (const c of set) {
        if (c.readyState === c.OPEN) {
          try { c.send(line); } catch {}
        }
      }
      return;
    }
    // rename support ("rename" from chat.js)
    if (msg.type === "rename") {
      const newName = String(msg.name || "").slice(0, 24) || "Anon";
      ws.meta = ws.meta || {};
      ws.meta.name = newName;
      return;
    }

    // chat messages: both legacy "say" and "msg"
    if (msg.type === "say" || msg.type === "msg") {
      const text = String(msg.text || "").slice(0, 400);
      if (!text.trim()) return;
      if (!canSend(clientIp)) return;

      const senderName = (ws.meta && ws.meta.name) || initialName;

      const payload = {
        type: "msg",
        room,
        from: senderName,
        text,
        ts: Date.now(),
        skins: ws.skin
      };
      logRoom(room, `CHAT ${senderName}: ${text}`);

      const set = rooms.get(room) || new Set();
      const line = JSON.stringify(payload);
      for (const c of set) {
        if (c.readyState === c.OPEN) {
          try { c.send(line); } catch {}
        }
      }
      return;
    }
  });

  ws.on("close", () => {
    const meta = ws.meta || {};
    const r = meta.room;
    const k = meta.key;

    if (rooms.has(r)) {
      const set = rooms.get(r);
      set.delete(ws);
      if (!set.size) rooms.delete(r);
    }
    
    // 👇 NEW: clean up playerID → skin entries for this socket
    const pidMap = pidSkinRegistry.get(r);
    if (pidMap && ws.pids && ws.pids.size) {
      for (const pid of ws.pids) {
        pidMap.delete(pid);
      }
      if (pidMap.size === 0) {
        pidSkinRegistry.delete(r);
      }
    }
    // Use clientIp from this connection, but do not store or expose it anywhere
    unregisterKeySocket(k, clientIp, ws);
  });
});

server.listen(PORT, () => {
  console.log("[OK] Running on port", PORT);
});
