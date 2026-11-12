// dogs: a tiny Node server (no dependencies) that serves the site, games and accounts.
const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { promisify } = require('util');
const scrypt = promisify(crypto.scrypt);

const PORT = process.env.PORT || 3000;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'users.json');
const GAMES_DIR = path.join(__dirname, 'games');
// Set SESSION_SECRET on Render so logins survive restarts.
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const INDEX = fs.readFileSync(path.join(__dirname, 'index.html'));

// Null-prototype object: names like "constructor" or "__proto__" are just ordinary keys.
const users = Object.create(null);
try { Object.assign(users, JSON.parse(fs.readFileSync(DATA_FILE, 'utf8'))); } catch (e) { /* first run */ }
const save = () => {
  try {
    fs.mkdirSync(path.dirname(DATA_FILE), { recursive: true });
    fs.writeFileSync(DATA_FILE + '.tmp', JSON.stringify(users));
    fs.renameSync(DATA_FILE + '.tmp', DATA_FILE); // atomic: never leaves a half-written file
  } catch (e) { console.error('Could not save users:', e.message); }
};

const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('hex');
const makeToken = name => {
  const v = Buffer.from(name).toString('base64url');
  return v + '.' + sign(v);
};
function currentUser(req) {
  const m = /(?:^|;\s*)dogs_session=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [v, s] = m[1].split('.');
  if (!v || !s) return null;
  const a = Buffer.from(sign(v)), b = Buffer.from(s);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) return null;
  const name = Buffer.from(v, 'base64url').toString();
  return users[name] ? name : null;
}

const hashPw = async (pw, salt) => (await scrypt(pw, salt, 64)).toString('hex'); // async: doesn't block other requests
const safeEq = (x, y) => {
  const a = Buffer.from(String(x)), b = Buffer.from(String(y));
  return a.length === b.length && crypto.timingSafeEqual(a, b);
};
const DUMMY_SALT = crypto.randomBytes(16).toString('hex'); // so unknown usernames cost the same time as real ones

// Simple per-IP limit on login/signup attempts: 10 per 10 minutes.
const attempts = new Map();
setInterval(() => {
  const now = Date.now();
  for (const [ip, list] of attempts) if (!list.some(t => now - t < 600000)) attempts.delete(ip);
}, 600000).unref();
function limited(ip) {
  const now = Date.now();
  const list = (attempts.get(ip) || []).filter(t => now - t < 600000);
  list.push(now);
  attempts.set(ip, list);
  return list.length > 10;
}

function send(res, code, obj, headers = {}) {
  res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store', ...headers });
  res.end(JSON.stringify(obj));
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => { data += c; if (data.length > 10000) { reject(new Error('too big')); req.destroy(); } });
    req.on('end', () => { try { resolve(JSON.parse(data || '{}')); } catch (e) { reject(e); } });
    req.on('error', reject);
  });
}
const cookie = (req, value, maxAge) => {
  const secure = req.headers['x-forwarded-proto'] === 'https' ? '; Secure' : '';
  return `dogs_session=${value}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}${secure}`;
};

// ---- games: static files from /games, only for logged-in users ----
const MIME = {
  '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8',
  '.json': 'application/json', '.png': 'image/png', '.jpg': 'image/jpeg', '.gif': 'image/gif', '.svg': 'image/svg+xml',
  '.ico': 'image/x-icon', '.ogg': 'audio/ogg', '.m4a': 'audio/mp4', '.wav': 'audio/wav', '.mp3': 'audio/mpeg',
  '.woff': 'font/woff', '.woff2': 'font/woff2', '.ttf': 'font/ttf'
}; // anything else (.unityweb, .partN, ...) is served as application/octet-stream
async function serveGame(req, res, url) {
  if (!currentUser(req)) return send(res, 401, { error: 'Log in to play.' });
  let rel;
  try { rel = decodeURIComponent(url.slice('/games/'.length)); } catch (e) { return send(res, 400, { error: 'Bad request.' }); }
  if (rel.includes('\0')) return send(res, 400, { error: 'Bad request.' });
  let file = path.resolve(GAMES_DIR, rel);
  if (file !== GAMES_DIR && !file.startsWith(GAMES_DIR + path.sep)) return send(res, 404, { error: 'Not found.' });
  let st = await fs.promises.stat(file).catch(() => null);
  if (st && st.isDirectory()) {
    if (!url.endsWith('/')) { res.writeHead(301, { Location: url + '/' }); return res.end(); }
    file = path.join(file, 'index.html');
    st = await fs.promises.stat(file).catch(() => null);
  }
  if (!st || !st.isFile()) return send(res, 404, { error: 'Not found.' });
  const ext = path.extname(file).toLowerCase();
  res.writeHead(200, {
    'Content-Type': MIME[ext] || 'application/octet-stream',
    'Content-Length': st.size,
    'Cache-Control': 'private, max-age=86400',
    'X-Content-Type-Options': 'nosniff'
  });
  fs.createReadStream(file).on('error', () => res.destroy()).pipe(res);
}

async function handle(req, res) {
  const url = req.url.split('?')[0];
  const ip = (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();

  if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
    res.writeHead(200, {
      'Content-Type': 'text/html; charset=utf-8',
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'same-origin'
    });
    return res.end(INDEX);
  }
  if (req.method === 'GET' && url.startsWith('/games/')) return serveGame(req, res, url);
  if (req.method === 'GET' && url === '/healthz') return send(res, 200, { ok: true });
  if (req.method === 'GET' && url === '/api/me') {
    const u = currentUser(req);
    return u ? send(res, 200, { username: u }) : send(res, 401, { error: 'Not logged in.' });
  }
  if (req.method === 'POST' && url === '/api/logout') {
    return send(res, 200, { ok: true }, { 'Set-Cookie': cookie(req, '', 0) });
  }
  if (req.method === 'POST' && (url === '/api/signup' || url === '/api/login')) {
    if (limited(ip)) return send(res, 429, { error: 'Too many attempts. Wait a few minutes.' });
    let body;
    try { body = await readBody(req); } catch (e) { return send(res, 400, { error: 'Bad request.' }); }
    const name = String(body.username || '').trim().toLowerCase();
    const pw = String(body.password || '');
    if (!/^[a-z0-9_]{3,24}$/.test(name)) return send(res, 400, { error: 'Username: 3–24 letters, numbers or underscores.' });
    if (pw.length < 6 || pw.length > 64) return send(res, 400, { error: 'Password needs 6–64 characters.' });

    if (url === '/api/signup') {
      if (users[name]) return send(res, 409, { error: 'That username is taken. Try another.' });
      const salt = crypto.randomBytes(16).toString('hex');
      const hash = await hashPw(pw, salt);
      if (users[name]) return send(res, 409, { error: 'That username is taken. Try another.' }); // re-check after the await
      users[name] = { salt, hash };
      save();
    } else {
      const u = users[name];
      const hash = await hashPw(pw, u ? u.salt : DUMMY_SALT);
      if (!u || !safeEq(hash, u.hash)) return send(res, 401, { error: 'Wrong username or password.' });
    }
    return send(res, 200, { username: name }, { 'Set-Cookie': cookie(req, makeToken(name), 60 * 60 * 24 * 30) });
  }
  send(res, 404, { error: 'Not found.' });
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(e => {
    console.error('Request failed:', e);
    if (!res.headersSent) send(res, 500, { error: 'Server error.' }); else res.end();
  });
});
process.on('unhandledRejection', e => console.error('Unhandled rejection:', e));

server.listen(PORT, () => console.log(`dogs is running on port ${PORT}`));
