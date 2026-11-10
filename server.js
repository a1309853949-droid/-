/* ============================================================
 * server.js — 代理下单系统「云端自建后端」
 * 零依赖（仅 Node 内置模块）：http / fs / path / crypto / url
 * 功能：账号密码注册登录 + token 会话 + REST API + 静态页面托管
 * 数据持久化：data.json（JSON 文件，同步读写，单线程天然串行）
 * ============================================================ */
'use strict';

const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const DATA_FILE = path.resolve(process.env.DATA_FILE || path.join(__dirname, 'data.json'));
// 确保数据目录存在（云端沙箱重建时目录可能尚未创建）
try { fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true }); } catch (e) {}
const PUBLIC_DIR = __dirname;
const SESSION_TTL = 1000 * 60 * 60 * 24 * 30; // 30 天
// 登录令牌采用「无状态签名令牌」：payload(用户uid+过期) + HMAC 签名。
// 所有实例共用同一密钥即可独立校验，无需共享会话文件，天然适配多实例部署。
const SESSION_SECRET = process.env.SESSION_SECRET || 'aops-dingdan-secret-2026';

// ---------------- 数据存储 ----------------
function loadData() {
  try {
    const raw = fs.readFileSync(DATA_FILE, 'utf8');
    const d = JSON.parse(raw);
    d.users = d.users || [];
    d.products = d.products || [];
    d.orders = d.orders || [];
    d.notifications = d.notifications || [];
    d.sessions = d.sessions || {};
    return d;
  } catch (e) {
    return { users: [], products: [], orders: [], notifications: [], sessions: {} };
  }
}
let DATA = loadData();
function saveData() {
  fs.writeFileSync(DATA_FILE, JSON.stringify(DATA, null, 2));
}
function uid(prefix) {
  return (prefix || 'id_') + crypto.randomBytes(6).toString('hex') + Date.now().toString(36).slice(-4);
}
function nowISO() { return new Date().toISOString(); }
function adminCount() {
  return DATA.users.filter(u => u.role === 'admin').length;
}
function publicUser(u) {
  if (!u) return null;
  return { uid: u.uid, phone: u.phone, email: u.email, name: u.name, role: u.role, status: u.status, createdAt: u.createdAt };
}

// ---------------- 密码与会话 ----------------
function hashPassword(password, salt) {
  salt = salt || crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return { salt, hash };
}
function verifyPassword(password, salt, hash) {
  const h = crypto.scryptSync(String(password), salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(h, 'hex'), Buffer.from(hash, 'hex'));
}
function createSession(uid) {
  // 无状态签名令牌：payload(uid + 过期时间) + HMAC 签名
  const payload = Buffer.from(JSON.stringify({ uid: uid, exp: Date.now() + SESSION_TTL })).toString('base64url');
  const sig = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  return payload + '.' + sig;
}
function destroySession() { /* 无状态令牌：客户端丢弃即可，无需服务端注销 */ }
function userFromToken(token) {
  if (!token || typeof token !== 'string' || token.indexOf('.') < 0) return null;
  const idx = token.indexOf('.');
  const payload = token.slice(0, idx);
  const sig = token.slice(idx + 1);
  const expected = crypto.createHmac('sha256', SESSION_SECRET).update(payload).digest('base64url');
  if (sig.length !== expected.length) return null;
  try {
    if (!crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) return null;
  } catch (e) { return null; }
  let data;
  try { data = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8')); } catch (e) { return null; }
  if (!data.exp || data.exp < Date.now()) return null;
  return DATA.users.find(u => u.uid === data.uid) || null;
}
function findByIdent(ident) {
  return DATA.users.find(u => u.phone === ident || u.email === ident) || null;
}

// ---------------- HTTP 工具 ----------------
function send(res, status, obj) {
  const body = typeof obj === 'string' ? obj : JSON.stringify(obj);
  res.writeHead(status, { 'Content-Type': 'application/json; charset=utf-8' });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let buf = '';
    req.on('data', c => { buf += c; if (buf.length > 1e6) req.destroy(); });
    req.on('end', () => {
      if (!buf) return resolve({});
      try { resolve(JSON.parse(buf)); } catch (e) { reject(new Error('bad json')); }
    });
    req.on('error', reject);
  });
}
function auth(req, url) {
  let token = '';
  const h = req.headers['authorization'] || '';
  if (h.startsWith('Bearer ')) token = h.slice(7);
  // 兼容分享网关可能剥离 Authorization 头的情况：允许通过 ?token= 传递
  if (!token && url && url.searchParams) token = url.searchParams.get('token') || '';
  return userFromToken(token);
}

// ---------------- 业务逻辑 ----------------
function registerUser(ident, name, password) {
  if (!ident || !password) throw new Error('缺少账号或密码');
  if (findByIdent(ident)) throw new Error('该账号已注册，请直接登录');
  const isFirst = DATA.users.length === 0;
  const saltHash = hashPassword(password);
  const u = {
    uid: uid('u_'),
    phone: /^1\d{10}$/.test(ident) ? ident : null,
    email: /^1\d{10}$/.test(ident) ? null : ident,
    name: name || '用户',
    role: isFirst ? 'admin' : 'agent',
    status: isFirst ? 'active' : 'pending',
    salt: saltHash.salt,
    hash: saltHash.hash,
    createdAt: nowISO()
  };
  DATA.users.push(u);
  saveData();
  return u;
}
function loginUser(ident, password) {
  const u = findByIdent(ident);
  if (!u) throw new Error('账号不存在，请先注册');
  if (!verifyPassword(password, u.salt, u.hash)) throw new Error('密码错误');
  return u;
}

// ---------------- 路由 ----------------
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon'
};

function serveStatic(req, res, pathname) {
  let rel = pathname === '/' ? '/index.html' : pathname;
  // 防目录穿越
  const filePath = path.normalize(path.join(PUBLIC_DIR, rel));
  if (!filePath.startsWith(PUBLIC_DIR)) { res.writeHead(403); return res.end('forbidden'); }
  fs.readFile(filePath, (err, data) => {
    if (err) { res.writeHead(404); return res.end('not found'); }
    const ext = path.extname(filePath).toLowerCase();
    res.writeHead(200, { 'Content-Type': MIME[ext] || 'application/octet-stream' });
    res.end(data);
  });
}

async function handleApi(req, res, url) {
  const parts = url.pathname.split('/').filter(Boolean); // ['api', ...]
  const seg = parts.slice(1); // 去掉 'api'
  const method = req.method;

  // 每个请求都从文件重新载入最新数据，保证多实例/多进程部署下状态一致。
  DATA = loadData();

  // ---- 认证类（无需登录） ----
  if (seg[0] === 'auth') {
    if (seg[1] === 'register' && method === 'POST') {
      const b = await readBody(req);
      const u = registerUser(b.ident, b.name, b.password);
      const token = createSession(u.uid);
      return send(res, 200, { user: publicUser(u), token });
    }
    if (seg[1] === 'login' && method === 'POST') {
      const b = await readBody(req);
      const u = loginUser(b.ident, b.password);
      const token = createSession(u.uid);
      return send(res, 200, { user: publicUser(u), token });
    }
    if (seg[1] === 'logout' && method === 'POST') {
      return send(res, 200, { ok: true }); // 无状态令牌：客户端丢弃即可
    }
    if (seg[1] === 'me' && method === 'GET') {
      const u = auth(req, url);
      if (!u) return send(res, 401, { error: '未登录' });
      return send(res, 200, { user: publicUser(u) });
    }
    return send(res, 404, { error: 'not found' });
  }

  // ---- 以下均需要登录 ----
  const me = auth(req, url);
  if (!me) return send(res, 401, { error: '未登录' });
  function requireAdmin() { if (me.role !== 'admin') { const e = new Error('需要管理员权限'); e.code = 403; throw e; } }
  function requireAgent() { if (me.role !== 'agent') { const e = new Error('需要代理权限'); e.code = 403; throw e; } }

  try {
    // ---- 商品 ----
    if (seg[0] === 'products') {
      if (method === 'GET') {
        const list = DATA.products.slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        return send(res, 200, { products: list });
      }
      if (method === 'POST') {
        requireAdmin();
        const b = await readBody(req);
        if (!b.name || b.price == null) return send(res, 400, { error: '名称与价格必填' });
        const p = {
          id: uid('p_'), name: b.name, price: Number(b.price), unit: b.unit || '件',
          description: b.description || '', active: b.active !== false, createdAt: nowISO()
        };
        DATA.products.push(p); saveData();
        return send(res, 200, { product: p });
      }
      if (method === 'PUT' && seg[1]) {
        requireAdmin();
        const b = await readBody(req);
        const p = DATA.products.find(x => x.id === seg[1]);
        if (!p) return send(res, 404, { error: '商品不存在' });
        if (b.name != null) p.name = b.name;
        if (b.price != null) p.price = Number(b.price);
        if (b.unit != null) p.unit = b.unit;
        if (b.description != null) p.description = b.description;
        if (b.active != null) p.active = !!b.active;
        saveData();
        return send(res, 200, { product: p });
      }
      if (method === 'DELETE' && seg[1]) {
        requireAdmin();
        DATA.products = DATA.products.filter(x => x.id !== seg[1]); saveData();
        return send(res, 200, { ok: true });
      }
    }

    // ---- 代理管理 ----
    if (seg[0] === 'agents') {
      if (method === 'GET') {
        requireAdmin();
        const list = DATA.users.filter(u => u.role === 'agent')
          .sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        return send(res, 200, { agents: list.map(publicUser) });
      }
      if (method === 'PUT' && seg[1]) {
        requireAdmin();
        const b = await readBody(req);
        const u = DATA.users.find(x => x.uid === seg[1]);
        if (!u) return send(res, 404, { error: '用户不存在' });
        if (b.status != null) u.status = b.status;
        if (b.role != null) u.role = b.role;
        saveData();
        return send(res, 200, { user: publicUser(u) });
      }
    }

    // ---- 订单 ----
    if (seg[0] === 'orders') {
      if (method === 'GET') {
        let list;
        if (me.role === 'admin') list = DATA.orders.slice();
        else list = DATA.orders.filter(o => o.agentUid === me.uid);
        list.sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        return send(res, 200, { orders: list });
      }
      if (method === 'POST') {
        requireAgent();
        if (me.status !== 'active') return send(res, 403, { error: '账号待开通，无法下单' });
        const b = await readBody(req);
        const items = (b.items || []).filter(i => i && i.qty > 0);
        if (!items.length) return send(res, 400, { error: '请选择商品' });
        const total = items.reduce((s, i) => s + Number(i.price) * Number(i.qty), 0);
        const order = {
          id: uid('o_'), agentUid: me.uid, agentName: me.name, items: items,
          total: Number(total.toFixed(2)), status: 'pending', note: b.note || '',
          createdAt: nowISO(), completedAt: null
        };
        DATA.orders.push(order);
        const notif = {
          id: uid('n_'), ownerUid: me.uid, orderId: order.id,
          message: '代理「' + me.name + '」提交了新订单，合计 ¥' + order.total.toFixed(2),
          isRead: false, createdAt: nowISO()
        };
        DATA.notifications.push(notif);
        saveData();
        return send(res, 200, { order, notification: notif });
      }
      if (method === 'PUT' && seg[1]) {
        requireAdmin();
        const b = await readBody(req);
        const o = DATA.orders.find(x => x.id === seg[1]);
        if (!o) return send(res, 404, { error: '订单不存在' });
        if (b.status != null) o.status = b.status;
        if (b.status === 'completed') o.completedAt = nowISO();
        if (b.note != null) o.note = b.note;
        saveData();
        return send(res, 200, { order: o });
      }
    }

    // ---- 站内提醒（管理员） ----
    if (seg[0] === 'notifications') {
      if (method === 'GET') {
        requireAdmin();
        const list = DATA.notifications.slice().sort((a, b) => b.createdAt.localeCompare(a.createdAt));
        return send(res, 200, { notifications: list });
      }
      if (method === 'POST' && seg[1] === 'read' && seg[2]) {
        requireAdmin();
        const n = DATA.notifications.find(x => x.id === seg[2]);
        if (n) { n.isRead = true; saveData(); }
        return send(res, 200, { ok: true });
      }
    }

    // ---- 统计（管理员） ----
    if (seg[0] === 'stats' && method === 'GET') {
      requireAdmin();
      const today = new Date().toISOString().slice(0, 10);
      return send(res, 200, {
        stats: {
          products: DATA.products.length,
          agents: DATA.users.filter(u => u.role === 'agent').length,
          pending: DATA.orders.filter(o => o.status === 'pending').length,
          todayOrders: DATA.orders.filter(o => o.createdAt.slice(0, 10) === today).length
        }
      });
    }

    // ---- 重置系统（管理员，清空全部数据） ----
    if (seg[0] === 'admin' && seg[1] === 'reset' && method === 'POST') {
      requireAdmin();
      DATA = { users: [], products: [], orders: [], notifications: [], sessions: {} };
      saveData();
      return send(res, 200, { ok: true });
    }

    return send(res, 404, { error: 'not found' });
  } catch (e) {
    return send(res, e.code || 500, { error: e.message || 'server error' });
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  if (url.pathname.startsWith('/api/')) {
    handleApi(req, res, url).catch(e => send(res, 500, { error: e.message || 'server error' }));
  } else {
    serveStatic(req, res, url.pathname);
  }
});

server.listen(PORT, '0.0.0.0', () => {
  // 启动时主动落盘初始数据文件，避免首次写入延迟或权限问题
  try { saveData(); } catch (e) { console.error('初始数据写入失败:', e.message); }
  console.log('代理下单系统 已启动: http://localhost:' + PORT);
  console.log('数据文件: ' + DATA_FILE);
});
server.on('error', (e) => {
  console.error('监听失败:', e.code, e.message);
  process.exit(1);
});
