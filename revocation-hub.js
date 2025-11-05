// revocation-hub.js
// Keeps one SSE connection per key. New connection "kicks" the old one.
const clients = new Map(); // key -> Set<res>

function addClient(key, res) {
  if (!clients.has(key)) clients.set(key, new Set());
  const set = clients.get(key);

  // If there is an existing client for this key, kick it (single session policy)
  for (const r of set) {
    try {
      r.write(`event: revoked\ndata: {"reason":"duplicate"}\n\n`);
      r.end();
    } catch {}
  }
  set.clear();

  set.add(res);
}

function removeClient(key, res) {
  const set = clients.get(key);
  if (!set) return;
  set.delete(res);
  if (!set.size) clients.delete(key);
}

function broadcastRevoked(key) {
  const set = clients.get(key);
  if (!set) return;
  for (const r of set) {
    try {
      r.write(`event: revoked\ndata: {}\n\n`);
      r.end();
    } catch {}
  }
  clients.delete(key);
}

module.exports = { addClient, removeClient, broadcastRevoked };
