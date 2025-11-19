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
import fs from "node:fs";
import path from "node:path";
import crypto from "node:crypto";

const PORT = process.env.PORT || 8080;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "changeme-in-env";

// Allowed origins for WebSocket connections (overlay + chat)
const ORIGIN_WHITELIST = new Set([
  "http://localhost",
  "http://localhost:3000",
  "http://127.0.0.1",
  "https://your-client-domain.com", // TODO: customize
  "https://your-other-client.com",  // TODO: customize
]);

// ============ SIMPLE PERSISTENCE FOR KEYS ============

const DATA_DIR = path.join(process.cwd(), "data");
const KEYS_FILE = path.join(DATA_DIR, "keys.json");

function ensureDirSync(p) {
  try {
    fs.mkdirSync(p, { recursive: true });
  } catch (e) {
    if (e.code !== "EEXIST") throw e;
  }
}

function loadKeys() {
  try {
    const raw = fs.readFileSync(KEYS_FILE, "utf8");
    const data = JSON.parse(raw);
    if (!Array.isArray(data)) return [];
    return data;
  } catch (e) {
    return [];
  }
}

function saveKeys(keys) {
  ensureDirSync(DATA_DIR);
  fs.writeFileSync(KEYS_FILE, JSON.stringify(keys, null, 2), "utf8");
}

// keys are objects: { key, label, createdAt, revokedAt? }
const KeyStore = {
  getAll() {
    return loadKeys();
  },

  findKey(key) {
    const keys = loadKeys();
    return keys.find((k) => k.key === key) || null;
  },

  createKey(label = "") {
    const keys = loadKeys();
    const key = crypto.randomBytes(16).toString("hex");
    const now = new Date().toISOString();
    const entry = { key, label: String(label || ""), createdAt: now };
    keys.push(entry);
    saveKeys(keys);
    return entry;
  },

  revokeKey(key) {
    const keys = loadKeys();
    const now = new Date().toISOString();
    let changed = false;
    for (const k of keys) {
      if (k.key === key && !k.revokedAt) {
        k.revokedAt = now;
        changed = true;
      }
    }
    if (changed) saveKeys(keys);
    return changed;
  },

  deleteKey(key) {
    const keys = loadKeys();
    const next = keys.filter((k) => k.key !== key);
    if (next.length !== keys.length) {
      saveKeys(next);
      return true;
    }
    return false;
  },
};

// ============ LOGGING UTIL ============

function logJson(res, obj, statusCode = 200) {
  const body = JSON.stringify(obj);
  res.writeHead(statusCode, {
    "Content-Type": "application/json; charset=utf-8",
    "Content-Length": Buffer.byteLength(body),
  });
  res.end(body);
}

// ============ SIMPLE ROOM LOGGING (ROLLING) ============

const MAX_LOG_LINES_PER_ROOM = 200;

const roomLogs = new Map(); // roomName -> array of strings

function logRoomEvent(room, line) {
  if (!roomLogs.has(room)) roomLogs.set(room, []);
  const arr = roomLogs.get(room);
  const ts = new Date().toISOString();
  arr.push(`[${ts}] ${line}`);
  while (arr.length > MAX_LOG_LINES_PER_ROOM) {
    arr.shift();
  }
}

// ============ ROOMS & CONNECTIONS ===================

const rooms = new Map(); // roomName -> Set<ws>

function normalizeSkins(v) {
  if (!v) return ["", ""];
  const [a = "", b = ""] = v;
  return [String(a), String(b)];
}

// key -> (ip -> Set<ws>) for per-key-per-IP limit + revocation kicks
const keySessions = new Map();

// same IP: how many tabs/sockets allowed per key
const MAX_PER_KEY_PER_IP = 4;

// how many distinct IPs are allowed to use the same key at once
// e.g. main + bot = 2 IPs → allowed
// a 3rd IP using the same key → treated as "someone else" → revoke + reload
const MAX_IPS_PER_KEY = 2;

// SSE revocation subscribers: key -> Set<res>
const sseClientsByKey = new Map();

// ============ HTTP SERVER ============

const server = http.createServer((req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || "/";

  // CORS for JSON / admin endpoints
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,x-admin-token");
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }

  if (pathname === "/healthz") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
    return;
  }

  if (pathname === "/connections.json") {
    // return JSON summary of current connections
    const out = [];
    for (const [room, set] of rooms) {
      for (const ws of set) {
        if (!ws.meta) continue;
        const { name, ip, key, skins } = ws.meta;
        out.push({
          room,
          name,
          ip,
          key,
          skins: skins || ["", ""],
        });
      }
    }
    logJson(res, { ok: true, connections: out });
    return;
  }

  if (pathname === "/connections") {
    // simple HTML view
    let html = `<!doctype html>
<html><head><meta charset="utf-8"><title>Connections</title>
<style>
body { font-family: sans-serif; background: #111; color: #eee; }
table { border-collapse: collapse; width: 100%; margin-top: 1rem; }
th, td { border: 1px solid #444; padding: 4px 6px; font-size: 13px; }
th { background: #222; }
tr:nth-child(even) { background: #181818; }
code { font-size: 11px; }
</style>
</head><body>
<h1>Active Connections</h1>
<table><thead><tr>
<th>Room</th><th>Name</th><th>IP</th><th>Key</th><th>Skins</th>
</tr></thead><tbody>
`;
    for (const [room, set] of rooms) {
      for (const ws of set) {
        if (!ws.meta) continue;
        const { name, ip, key, skins } = ws.meta;
        html += `<tr>
<td>${escapeHtml(room)}</td>
<td>${escapeHtml(name)}</td>
<td><code>${escapeHtml(ip || "")}</code></td>
<td><code>${escapeHtml(key || "")}</code></td>
<td><code>${escapeHtml((skins || []).join(", "))}</code></td>
</tr>\n`;
      }
    }
    html += `</tbody></table>
</body></html>`;
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end(html);
    return;
  }

  if (pathname === "/logs.json") {
    // dump all room logs
    const all = {};
    for (const [room, arr] of roomLogs) {
      all[room] = arr.slice();
    }
    logJson(res, { ok: true, rooms: all });
    return;
  }

  if (pathname === "/logs/clear" && req.method === "POST") {
    roomLogs.clear();
    logJson(res, { ok: true, cleared: true });
    return;
  }

  // ===== KEY VALIDATION (for overlay to check before connecting) =====
  if (pathname === "/validate" && req.method === "POST") {
    let body = "";
    req.on("data", (chunk) => {
      body += chunk;
      if (body.length > 1e5) {
        req.destroy();
      }
    });
    req.on("end", async () => {
      try {
        const parsedBody = JSON.parse(body || "{}");
        const providedKey = String(parsedBody.key || "").trim();
        if (!providedKey) {
          logJson(res, { ok: false, error: "missing key" }, 400);
          return;
        }
        const info = await KeyStore.findKey(providedKey);
        if (!info || info.revokedAt) {
          logJson(res, { ok: false, error: "invalid-or-revoked" }, 403);
          return;
        }
        logJson(res, { ok: true, label: info.label || "" });
      } catch (e) {
        logJson(res, { ok: false, error: "bad-json" }, 400);
      }
    });
    return;
  }

  // ===== SSE REVOCATION STREAM =====
  if (pathname === "/revocations/stream") {
    const key = String((parsed.query && parsed.query.key) || "").trim();
    if (!key) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("missing key");
      return;
    }

    // SSE headers
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
      "Access-Control-Allow-Origin": "*",
    });
    res.write("\n");

    if (!sseClientsByKey.has(key)) sseClientsByKey.set(key, new Set());
    const set = sseClientsByKey.get(key);
    set.add(res);

    req.on("close", () => {
      const s = sseClientsByKey.get(key);
      if (s) {
        s.delete(res);
        if (s.size === 0) sseClientsByKey.delete(key);
      }
    });

    return;
  }

  // ===== ADMIN KEY MANAGEMENT =====
  if (pathname.startsWith("/admin/keys")) {
    const token = req.headers["x-admin-token"];
    if (!token || token !== ADMIN_TOKEN) {
      logJson(res, { ok: false, error: "unauthorized" }, 401);
      return;
    }

    if (req.method === "GET") {
      const keys = KeyStore.getAll();
      logJson(res, { ok: true, keys });
      return;
    }

    if (req.method === "POST") {
      let body = "";
      req.on("data", (chunk) => {
        body += chunk;
        if (body.length > 1e5) req.destroy();
      });
      req.on("end", () => {
        try {
          const parsedBody = JSON.parse(body || "{}");
          const label = parsedBody.label || "";
          const entry = KeyStore.createKey(label);
          logJson(res, { ok: true, key: entry });
        } catch (e) {
          logJson(res, { ok: false, error: "bad-json" }, 400);
        }
      });
      return;
    }

    if (req.method === "DELETE") {
      const key = String((parsed.query && parsed.query.key) || "").trim();
      if (!key) {
        logJson(res, { ok: false, error: "missing-key" }, 400);
        return;
      }

      const changed = KeyStore.revokeKey(key);
      if (changed) {
        notifyRevocation(key);
        logJson(res, { ok: true, revoked: true });
      } else {
        logJson(res, { ok: false, revoked: false });
      }
      return;
    }

    res.writeHead(405);
    res.end("Method Not Allowed");
    return;
  }

  // default
  res.writeHead(404, { "Content-Type": "text/plain" });
  res.end("not found");
});

function escapeHtml(str) {
  return String(str || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// ============ SSE REVOCATION NOTIFIER ============

function notifyRevocation(key) {
  // close all WS using this key
  const ipMap = keySessions.get(key);
  if (ipMap) {
    for (const [ip, set] of ipMap) {
      for (const ws of set) {
        try {
          ws.close(4001, "Key revoked");
        } catch (_) {}
      }
    }
    keySessions.delete(key);
  }

  // notify SSE clients
  const set = sseClientsByKey.get(key);
  if (set && set.size > 0) {
    for (const res of set) {
      try {
        res.write(`event: revoked\ndata: ${JSON.stringify({ key })}\n\n`);
      } catch (e) {
        // ignore
      }
    }
  }
}

// ============ WEBSOCKET SERVER ============

const wss = new WebSocketServer({ noServer: true });

server.on("upgrade", (req, socket, head) => {
  const { pathname } = url.parse(req.url);
  if (pathname !== "/chat") {
    socket.destroy();
    return;
  }

  const origin = req.headers.origin;
  if (origin && !isAllowedOrigin(origin)) {
    socket.destroy();
    return;
  }

  wss.handleUpgrade(req, socket, head, (ws) => {
    wss.emit("connection", ws, req);
  });
});

function isAllowedOrigin(origin) {
  try {
    const u = new URL(origin);
    const base = `${u.protocol}//${u.hostname}` + (u.port ? `:${u.port}` : "");
    return ORIGIN_WHITELIST.has(base);
  } catch {
    return false;
  }
}

// track connections, enforce key/IP limits, handle messages
wss.on("connection", async (ws, req) => {
  const parsed = url.parse(req.url, true);
  const query = parsed.query || {};
  const room = String(query.room || "global").slice(0, 64);
  const name = String(query.name || "anon").slice(0, 24);
  const providedKey = query.key ? String(query.key).trim() : "";
  const skinsRaw = query.skins ? String(query.skins) : "";
  const skins = skinsRaw ? skinsRaw.split(",").slice(0, 2) : ["", ""];

  const rawIp =
    (req.headers["x-forwarded-for"] ||
      req.socket.remoteAddress ||
      "").toString();
  const clientIp = rawIp.split(",")[0].trim() || rawIp;

  // require key
  if (!providedKey) {
    console.log("[reject][no-key]", clientIp);
    try {
      ws.close(1008, "Key required");
    } catch {}
    return;
  }

  const keyInfo = await KeyStore.findKey(providedKey);
  if (!keyInfo || keyInfo.revokedAt) {
    console.log(
      "[reject][bad-key]",
      providedKey.slice(0, 8) + "...",
      clientIp
    );
    try {
      ws.close(1008, "Invalid or revoked key");
    } catch {}
    return;
  }

  ws.meta = { room, name, ip: rawIp, key: providedKey, skins };

  // === MULTI-IP PROTECTION ===
  // We allow up to MAX_IPS_PER_KEY distinct IPs per key (e.g. main + bot).
  // If a 3rd IP appears concurrently with the same key, we treat that as
  // "another person using the key" and revoke that key for everyone.
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

      // This will:
      //  - close all WS using this key with code 4001 ("Key revoked")
      //  - notify all SSE subscribers with event: revoked
      //  - your overlay will clear the key + reload (ask for key again)
      notifyRevocation(providedKey);

      // Also close this new socket; the user will see overlay after reload.
      try {
        ws.close(4002, "Key used from too many IPs");
      } catch {}
      return;
    }
  }

  // per-key-per-IP limit (same IP can open multiple tabs)
  if (!registerKeySocket(providedKey, clientIp, ws)) {
    console.log(
      "[limit]",
      "too many sessions for key",
      providedKey.slice(0, 8) + "...",
      "ip=",
      clientIp
    );
    try {
      ws.close(1008, "Too many sessions for this key/IP");
    } catch {}
    return;
  }

  // join room
  if (!rooms.has(room)) rooms.set(room, new Set());
  rooms.get(room).add(ws);

  console.log(
    "[join]",
    name,
    "room=",
    room,
    "ip=",
    rawIp,
    "key=",
    providedKey.slice(0, 8) + "...",
    "skins=",
    skins
  );
  logRoomEvent(room, `JOIN ${name} ip=${rawIp}`);

  // heartbeat + server-side keepalive (data frames) for Render/host
  ws.isAlive = true;
  ws.on("pong", () => {
    ws.isAlive = true;
  });

  ws.on("message", (data) => {
    let msg;
    try {
      msg = JSON.parse(data.toString());
    } catch {
      return;
    }

    if (!msg || typeof msg !== "object") return;

    if (msg.type === "chat" && typeof msg.text === "string") {
      const text = msg.text.trim();
      if (!text) return;

      if (!canSendMessage(ws, clientIp)) {
        return;
      }

      const payload = {
        type: "chat",
        room,
        from: name,
        text: text.slice(0, 400),
        t: Date.now(),
        skins: ws.meta.skins || ["", ""],
      };

      const set = rooms.get(room);
      if (set) {
        for (const client of set) {
          if (client.readyState === client.OPEN) {
            try {
              client.send(JSON.stringify(payload));
            } catch {}
          }
        }
      }

      logRoomEvent(room, `CHAT ${name}: ${text}`);
      return;
    }

    if (msg.type === "ping") {
      try {
        ws.send(JSON.stringify({ type: "pong", t: Date.now() }));
      } catch {}
      return;
    }
  });

  ws.on("close", (code, reasonBuf) => {
    const reason = reasonBuf ? reasonBuf.toString() : "";
    console.log(
      "[close]",
      name,
      "room=",
      room,
      "ip=",
      rawIp,
      "code=",
      code,
      "reason=",
      reason
    );

    if (rooms.has(room)) {
      rooms.get(room).delete(ws);
      if (rooms.get(room).size === 0) rooms.delete(room);
    }

    unregisterKeySocket(providedKey, clientIp, ws);

    logRoomEvent(room, `LEAVE ${name} code=${code} reason=${reason}`);
  });
});

// track per-key per-IP connections
function registerKeySocket(key, ip, ws) {
  if (!keySessions.has(key)) keySessions.set(key, new Map());
  const ipMap = keySessions.get(key);
  if (!ipMap.has(ip)) ipMap.set(ip, new Set());
  const set = ipMap.get(ip);

  if (set.size >= MAX_PER_KEY_PER_IP) {
    return false;
  }
  set.add(ws);
  return true;
}

function unregisterKeySocket(key, ip, ws) {
  const ipMap = keySessions.get(key);
  if (!ipMap) return;
  const set = ipMap.get(ip);
  if (!set) return;
  set.delete(ws);
  if (set.size === 0) {
    ipMap.delete(ip);
    if (ipMap.size === 0) keySessions.delete(key);
  }
}

// simple rate-limit per IP
const MESSAGE_WINDOW_MS = 5000;
const MAX_MSGS_PER_WINDOW = 12;
const messageHistoryByIp = new Map(); // ip -> array of timestamps

function canSendMessage(ws, ip) {
  const now = Date.now();
  if (!messageHistoryByIp.has(ip)) messageHistoryByIp.set(ip, []);
  const arr = messageHistoryByIp.get(ip);

  while (arr.length && now - arr[0] > MESSAGE_WINDOW_MS) {
    arr.shift();
  }

  if (arr.length >= MAX_MSGS_PER_WINDOW) {
    return false;
  }
  arr.push(now);
  return true;
}

// heartbeat for all WS (to kill dead sockets)
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (ws.isAlive === false) {
      try {
        ws.terminate();
      } catch {}
      return;
    }
    ws.isAlive = false;
    try {
      ws.ping();
    } catch {}
  });
}, 30000);

// send keepalive chat pings (data frames) every 25s to keep Render happy
setInterval(() => {
  const payload = JSON.stringify({ type: "srv_keep", t: Date.now() });
  wss.clients.forEach((ws) => {
    if (ws.readyState === ws.OPEN) {
      try {
        ws.send(payload);
      } catch {}
    }
  });
}, 25000);

server.listen(PORT, () => {
  console.log("Server listening on port", PORT);
});
