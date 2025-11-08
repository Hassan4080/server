// server.js
// WebSocket chat relay with rooms, rate-limit, heartbeats, rolling logs.
// Key management with Admin Token, key validation, and revocation SSE.
// Enforces one active session per key via SSE fanout: a new session for a key
// will immediately notify any previous session for that key to reload/logout.

import http from "node:http";
import { WebSocketServer } from "ws";
import url from "node:url";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

// ================== ENV ==================
const PORT         = process.env.PORT || 8080;
const ADMIN_TOKEN  = process.env.ADMIN_TOKEN || ""; // admin-only endpoints
const CONN_TOKEN   = process.env.CONN_TOKEN  || ""; // /connections.json, /rooms.json
const LOGS_TOKEN   = process.env.LOGS_TOKEN  || ""; // /logs.json, /logs/clear and WS monitor
const MAX_LOGS     = Number(process.env.MAX_LOGS || 2000);
const DATABASE_URL = process.env.DATABASE_URL || ""; // optional (Render PG)

// -------------------- KeyStore --------------------
let KeyStore;
if (DATABASE_URL) {
  const { Pool } = await import("pg").then(m => m.default || m);
  const pool = new Pool({ connectionString: DATABASE_URL, ssl: { rejectUnauthorized: false } });

  await pool.query(`
    CREATE TABLE IF NOT EXISTS chat_keys(
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
    async findKey(k) {
      const { rows } = await pool.query(
        `SELECT label, key_value AS key, revoked, created_at AS "createdAt"
         FROM chat_keys WHERE key_value = $1 LIMIT 1`, [k]
      );
      return rows[0] || null;
    },
    async generateKey(label = "") {
      const key = crypto.randomBytes(16).toString("hex");
      const { rows } = await pool.query(
        `INSERT INTO chat_keys(label, key_value) VALUES($1,$2)
         RETURNING label, key_value AS key, revoked, created_at AS "createdAt"`,
        [label, key]
      );
      return rows[0];
    },
    async revokeKey(k) {
      const { rowCount } = await pool.query(
        `UPDATE chat_keys SET revoked = TRUE WHERE key_value = $1`, [k]
      );
      return rowCount > 0;
    }
  };
  console.log("[keys] Using PostgreSQL store");
} else {
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
    async listKeys()  { return readKeys(); },
    async findKey(k)  { return readKeys().find(x => x.key === k) || null; },
    async generateKey(label="") {
      const arr = readKeys();
      const key = crypto.randomBytes(16).toString("hex");
      const item = { key, label, revoked:false, createdAt:new Date().toISOString() };
      arr.push(item); writeKeys(arr); return item;
    },
    async revokeKey(k) {
      const arr = readKeys();
      const i = arr.findIndex(x => x.key === k);
      if (i < 0) return false;
      arr[i].revoked = true; writeKeys(arr); return true;
    }
  };
  console.log("[keys] Using file store ./data/keys.json");
}

// -------------------- Chat state --------------------
const skinRegistry = new Map();              // nameHash -> [s1, s2]
const rooms = new Map();                     // roomName -> Set<ws>
const roomLogs = new Map();                  // room -> [{ ts, from, text }]
const RATE_WINDOW_MS = 5_000, RATE_MAX = 12; // per-IP
const ipBuckets = new Map();                 // ip -> {count, resetAt}

function normalizeSkins(v) {
  if (!v) return ["", ""];
  const [a="", b=""] = v;
  return [String(a), String(b)];
}
function allowed(ip) {
  const now = Date.now();
  const b = ipBuckets.get(ip) || { count: 0, resetAt: now + RATE_WINDOW_MS };
  if (now > b.resetAt) { b.count = 0; b.resetAt = now + RATE_WINDOW_MS; }
  b.count++; ipBuckets.set(ip, b);
  return b.count <= RATE_MAX;
}
function appendLog(room, entry) {
  if (!roomLogs.has(room)) roomLogs.set(room, []);
  const arr = roomLogs.get(room);
  arr.push({ ts: entry.ts || Date.now(), from: String(entry.from || ""), text: String(entry.text || "") });
  if (arr.length > MAX_LOGS) arr.splice(0, arr.length - MAX_LOGS);
}
function broadcast(room, payload, except) {
  if (payload?.type === "msg") appendLog(room, { ts: payload.ts, from: payload.from, text: payload.text });
  const set = rooms.get(room); if (!set) return;
  const msg = JSON.stringify(payload);
  for (const client of set) if (client !== except && client.readyState === client.OPEN) { try { client.send(msg); } catch {} }
}

// -------------------- SSE Revocation Hub (enforces 1 session/key) --------------------
const sseClients = new Map(); // key -> Set<ServerResponse>
function addSseClient(key, res) {
  if (!sseClients.has(key)) sseClients.set(key, new Set());
  const set = sseClients.get(key);
  // Enforce single session: revoke any prior listeners
  for (const r of set) { try { r.write(`event: revoked\ndata: {"reason":"duplicate"}\n\n`); r.end(); } catch {} }
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
  for (const r of set) { try { r.write(`event: revoked\ndata: {}\n\n`); r.end(); } catch {} }
  sseClients.delete(key);
}

// -------------------- HTTP helpers --------------------
function sendJSON(res, code, obj, extra={}) {
  res.writeHead(code, { "content-type": "application/json; charset=utf-8", "cache-control":"no-store", "access-control-allow-origin":"*", ...extra });
  res.end(JSON.stringify(obj));
}
function sendText(res, code, text, extra={}) {
  res.writeHead(code, { "content-type": "text/plain; charset=utf-8", "cache-control":"no-store", "access-control-allow-origin":"*", ...extra });
  res.end(text);
}
function readJson(req) {
  return new Promise((resolve, reject) => {
    let data = ""; req.on("data", c => data += c);
    req.on("end", () => { try { resolve(data ? JSON.parse(data) : {}); } catch(e){ reject(e); } });
    req.on("error", reject);
  });
}
function requireAdmin(req, res) {
  if (!ADMIN_TOKEN || req.headers["x-admin-token"] !== ADMIN_TOKEN) { sendJSON(res, 401, { error:"unauthorized" }); return false; }
  return true;
}
function requireConn(req, res) {
  if (!CONN_TOKEN || req.headers["x-conn-token"] !== CONN_TOKEN) { sendJSON(res, 403, { error:"forbidden" }); return false; }
  return true;
}
function requireLogs(req, res) {
  const tok = req.headers["x-logs-token"] || (req.url.includes("?") && new URL(req.url, "http://x").searchParams.get("token"));
  if (!LOGS_TOKEN || tok !== LOGS_TOKEN) { sendJSON(res, 403, { error:"forbidden" }); return false; }
  return true;
}

// -------------------- HTTP Server --------------------
const server = http.createServer(async (req, res) => {
  const parsed = url.parse(req.url, true);
  const pathname = parsed.pathname || "/";

  // CORS preflight
  if (req.method === "OPTIONS") {
    res.writeHead(204, {
      "access-control-allow-origin": "*",
      "access-control-allow-methods": "GET,POST,DELETE,OPTIONS",
      "access-control-allow-headers": "content-type,x-admin-token,x-conn-token,x-logs-token",
      "cache-control": "no-store",
    });
    return res.end();
  }

  if (pathname === "/" || pathname === "/health") return sendText(res, 200, "ok");

  // ---- logs (protected) ----
  if (pathname === "/logs.json") {
    if (!requireLogs(req, res)) return;
    const room = (parsed.query?.room ? String(parsed.query.room) : "").slice(0, 128);
    const msgs = room ? (roomLogs.get(room) || []) : [];
    return sendJSON(res, 200, { room, count: msgs.length, messages: msgs });
  }
  if (pathname === "/logs/clear") {
    if (!requireLogs(req, res)) return;
    const room = (parsed.query?.room ? String(parsed.query.room) : "").slice(0, 128);
    if (room) roomLogs.set(room, []);
    return sendJSON(res, 200, { ok: true, room });
  }

  // ---- connections (protected) ----
  if (pathname === "/connections.json") {
    if (!requireConn(req, res)) return;
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

  // Simple HTML stub (use your admin page file)
  if (pathname === "/admin" || pathname === "/admin.html") {
    const file = path.join(process.cwd(), "admin.html");
    fs.readFile(file, "utf8", (err, data) => {
      if (err) return sendText(res, 500, "admin.html not found");
      res.writeHead(200, { "content-type": "text/html; charset=utf-8", "cache-control":"no-store" });
      res.end(data);
    });
    return;
  }

  // ---- rooms (protected) ----
  if (pathname === "/rooms.json") {
    if (!requireConn(req, res)) return;
    const live = Array.from(rooms.keys());
    const logged = Array.from(roomLogs.keys());
    let extra = [];
    try {
      const p = path.join(process.cwd(), "rooms.json");
      const txt = fs.readFileSync(p, "utf8");
      const j = JSON.parse(txt);
      if (Array.isArray(j.rooms)) extra = j.rooms.map(String);
    } catch {}
    const all = Array.from(new Set([...live, ...logged, ...extra])).sort();
    return sendJSON(res, 200, { count: all.length, rooms: all });
  }

  // ---- key validate ----
  if (pathname === "/validate" && req.method === "POST") {
    try {
      const body = await readJson(req);
      const key = String(body.key || "");
      const found = await KeyStore.findKey(key);
      if (!found || found.revoked) return sendJSON(res, 403, { ok:false, reason:"invalid" });
      return sendJSON(res, 200, { ok:true, key: found.key });
    } catch {
      return sendJSON(res, 400, { ok:false, reason:"bad_json" });
    }
  }

  // ---- revocation stream (also used to enforce one-session-per-key) ----
  if (pathname === "/revocations/stream" && req.method === "GET") {
    const key = String(parsed.query?.key || "");
    const k = await KeyStore.findKey(key);
    if (!k || k.revoked) {
      res.writeHead(403, { "content-type":"text/plain; charset=utf-8", "access-control-allow-origin":"*" });
      res.end("invalid");
      return;
    }
    res.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      "Connection": "keep-alive",
      "access-control-allow-origin": "*",
    });
    try { res.write(`data: {"ok":true}\n\n`); } catch {}
    addSseClient(key, res);
    const hb = setInterval(() => { try { res.write(`data: {"t":${Date.now()}}\n\n`); } catch {} }, 25000);
    req.on("close", () => { clearInterval(hb); removeSseClient(key, res); });
    return;
  }

  // ---- admin key ops ----
  if (pathname === "/admin/keys" && req.method === "GET") {
    if (!requireAdmin(req, res)) return;
    return sendJSON(res, 200, await KeyStore.listKeys());
  }
  if (pathname === "/admin/keys" && req.method === "POST") {
    if (!requireAdmin(req, res)) return;
    try {
      const body = await readJson(req);
      const item = await KeyStore.generateKey(String(body.label || ""));
      return sendJSON(res, 201, item);
    } catch {
      return sendJSON(res, 400, { error: "bad_json" });
    }
  }
  if (pathname === "/admin/keys" && req.method === "DELETE") {
    if (!requireAdmin(req, res)) return;
    try {
      const body = await readJson(req);
      const ok = await KeyStore.revokeKey(String(body.key || ""));
      if (!ok) return sendJSON(res, 404, { error:"not_found" });
      broadcastRevoked(String(body.key || ""));
      return sendJSON(res, 200, { ok: true });
    } catch {
      return sendJSON(res, 400, { error: "bad_json" });
    }
  }

  // 404
  res.writeHead(404, { "content-type":"text/plain; charset=utf-8", "access-control-allow-origin":"*" });
  res.end("not found");
});

// -------------------- WebSocket (/chat) --------------------
const wss = new WebSocketServer({ server, path: "/chat" });

function heartbeat() { this.isAlive = true; }
setInterval(() => {
  wss.clients.forEach((ws) => {
    if (!ws.isAlive) return ws.terminate();
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  });
}, 30_000);

const SERVER_KEEP_MS = 25_000;
setInterval(() => {
  wss.clients.forEach((ws) => { if (ws.readyState === ws.OPEN) { try { ws.send('{"type":"srv_keep"}'); } catch {} } });
}, SERVER_KEEP_MS);

wss.on("connection", (ws, req) => {
  ws.skin = ["", ""];
  ws.nameHash = "";
  ws.id = crypto.randomUUID();
  ws.isAlive = true;
  ws.on("pong", heartbeat);

  if (skinRegistry.size) {
    const data = [...skinRegistry.entries()].map(([h, [s1, s2]]) => [h, s1, s2]);
    try { ws.send(JSON.stringify({ t:"skin", op:"bulk", data })); } catch {}
  }

  const { query } = url.parse(req.url, true);
  const room = String(query.room || "global").slice(0, 64);
  const name = String(query.name || "anon").slice(0, 24);
  const providedToken = query.token ? String(query.token) : null;

  // Optional: protect monitor sockets with LOGS_TOKEN if a token is present
  if (providedToken !== null && providedToken !== LOGS_TOKEN) { try { ws.close(); } catch {} return; }

  const ip = (req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").toString();
  ws.meta = { room, name, ip };

  if (!rooms.has(room)) rooms.set(room, new Set());
  rooms.get(room).add(ws);

  console.log("[join]", name, "room=", room, "ip=", ip);

  ws.on("message", (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
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
      broadcast(room, { type:"msg", from: ws.meta.name, text, ts: Date.now() });
      return;
    }

    // skin announce (optional)
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
      wss.clients.forEach(c => { if (c.readyState === 1) { try { c.send(payload); fanout++; } catch {} } });
      console.log("[skin][announce]", m.h, fanout);
      return;
    }
  });

  ws.on("close", () => {
    const set = rooms.get(room);
    if (set) { set.delete(ws); if (!set.size) rooms.delete(room); }
    console.log("[leave]", ws.meta.name, "room=", room);
  });
});

server.listen(PORT, () => console.log("WS listening on :" + PORT + " (path /chat)"));
