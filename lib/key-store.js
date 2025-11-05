// lib/keys-store.js
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const FILE = path.join(process.cwd(), 'data', 'keys.json');

function ensure(){
  if(!fs.existsSync(path.dirname(FILE))) fs.mkdirSync(path.dirname(FILE), { recursive:true });
  if(!fs.existsSync(FILE)) fs.writeFileSync(FILE, '[]');
}
function read(){ ensure(); return JSON.parse(fs.readFileSync(FILE,'utf8')||'[]'); }
function write(arr){ fs.writeFileSync(FILE, JSON.stringify(arr,null,2)); }

exports.list = () => read();
exports.find = (key) => read().find(k=>k.key===key);
exports.generate = (label='') => {
  const arr = read();
  const key = crypto.randomBytes(16).toString('hex'); // 32 hex chars
  const item = { key, label, revoked:false, createdAt:new Date().toISOString() };
  arr.push(item); write(arr); return item;
};
exports.revoke = (key) => {
  const arr = read(); const i = arr.findIndex(k=>k.key===key);
  if(i<0) return null; arr[i].revoked = true; write(arr); return arr[i];
};
