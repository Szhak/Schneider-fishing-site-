'use strict';

const https  = require('https');
const fs     = require('fs');
const fsp    = fs.promises;
const path   = require('path');
const crypto = require('crypto');
const bcrypt = require('bcrypt'); // npm install bcrypt

// ─────────────────────────────────────────────────────────────
//  Конфигурация
// ─────────────────────────────────────────────────────────────
const CONFIG = {
  port:           process.env.PORT || 443,
  saltRounds:     12,           // bcrypt cost factor
  rateLimit: {
    windowMs:     60_000,       // 1 минута
    maxRequests:  10,           // максимум запросов с одного IP за окно
  },
  // HTTP Basic Auth для /stats и /pwlogs
  adminUser:      'admin',
  adminPass:      'Schneider',
  bodyTimeoutMs:  5_000,        // таймаут чтения тела запроса
  maxBodyBytes:   4_096,        // максимальный размер тела (4 KB)
};

const SSL_OPTIONS = {
  key:  fs.readFileSync('C:/Certbot/live/schnelder-group.duckdns.org/privkey.pem'),
  cert: fs.readFileSync('C:/Certbot/live/schnelder-group.duckdns.org/fullchain.pem'),
};

// ─────────────────────────────────────────────────────────────
//  Пути к файлам
// ─────────────────────────────────────────────────────────────
const LOG_FILE       = path.join(__dirname, 'visitors.log');
const COUNTER_FILE   = path.join(__dirname, 'counter.json');
const KNOWN_IPS_FILE = path.join(__dirname, 'known_ips.json');
const PWCHANGE_FILE  = path.join(__dirname, 'password_changes.log');
const PWCHANGE_JSON  = path.join(__dirname, 'password_changes.json');

// ─────────────────────────────────────────────────────────────
//  Мьютекс для безопасной записи файлов при конкурентных запросах
// ─────────────────────────────────────────────────────────────
const fileLocks = new Map();

async function withFileLock(filePath, fn) {
  // Ждём, пока предыдущая запись завершится
  while (fileLocks.get(filePath)) {
    await fileLocks.get(filePath);
  }
  let resolve;
  const promise = new Promise(r => (resolve = r));
  fileLocks.set(filePath, promise);
  try {
    return await fn();
  } finally {
    fileLocks.delete(filePath);
    resolve();
  }
}

// ─────────────────────────────────────────────────────────────
//  Rate Limiter (in-memory, без внешних зависимостей)
// ─────────────────────────────────────────────────────────────
const rateLimitStore = new Map(); // ip → { count, resetAt }

function checkRateLimit(ip) {
  const now     = Date.now();
  const entry   = rateLimitStore.get(ip);
  const resetAt = now + CONFIG.rateLimit.windowMs;

  if (!entry || now > entry.resetAt) {
    rateLimitStore.set(ip, { count: 1, resetAt });
    return true; // OK
  }

  if (entry.count >= CONFIG.rateLimit.maxRequests) {
    return false; // лимит превышен
  }

  entry.count++;
  return true;
}

// ─────────────────────────────────────────────────────────────
//  HTTP Basic Auth для /stats и /pwlogs
// ─────────────────────────────────────────────────────────────
function checkBasicAuth(req) {
  const header = req.headers['authorization'] || '';
  if (!header.startsWith('Basic ')) return false;

  const decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  const [user, ...passParts] = decoded.split(':');
  const pass = passParts.join(':');

  // Сравниваем через timingSafeEqual — защита от timing-атак
  const expectedUser = Buffer.from(CONFIG.adminUser);
  const expectedPass = Buffer.from(CONFIG.adminPass);
  const actualUser   = Buffer.from(user.padEnd(CONFIG.adminUser.length, '\0').slice(0, CONFIG.adminUser.length));
  const actualPass   = Buffer.from(pass.padEnd(CONFIG.adminPass.length, '\0').slice(0, CONFIG.adminPass.length));

  return (
    expectedUser.length === actualUser.length &&
    expectedPass.length === actualPass.length &&
    crypto.timingSafeEqual(expectedUser, actualUser) &&
    crypto.timingSafeEqual(expectedPass, actualPass)
  );
}

function requireAuth(req, res) {
  if (!checkBasicAuth(req)) {
    res.writeHead(401, {
      'Content-Type': 'application/json',
      'WWW-Authenticate': 'Basic realm="Admin"',
    });
    res.end(JSON.stringify({ error: 'Unauthorized' }));
    return false;
  }
  return true;
}

// ─────────────────────────────────────────────────────────────
//  Вспомогательные функции
// ─────────────────────────────────────────────────────────────
function formatTime() {
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  return `${pad(now.getDate())}.${pad(now.getMonth()+1)}.${now.getFullYear()} ` +
         `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

function getClientIP(req) {
  const fwd = req.headers['x-forwarded-for'];
  return fwd ? fwd.split(',')[0].trim() : (req.socket.remoteAddress || 'unknown');
}

/** Читает тело запроса с таймаутом и ограничением размера */
function readBody(req) {
  return new Promise((resolve, reject) => {
    let body  = '';
    let bytes = 0;

    const timer = setTimeout(() => {
      req.destroy();
      reject(new Error('Body timeout'));
    }, CONFIG.bodyTimeoutMs);

    req.on('data', chunk => {
      bytes += chunk.length;
      if (bytes > CONFIG.maxBodyBytes) {
        req.destroy();
        clearTimeout(timer);
        reject(new Error('Body too large'));
        return;
      }
      body += chunk;
    });

    req.on('end', () => {
      clearTimeout(timer);
      resolve(body);
    });

    req.on('error', err => {
      clearTimeout(timer);
      reject(err);
    });
  });
}

// ─────────────────────────────────────────────────────────────
//  Файловые операции (async + мьютекс)
// ─────────────────────────────────────────────────────────────
async function getCounter() {
  try {
    const data = await fsp.readFile(COUNTER_FILE, 'utf8');
    return JSON.parse(data);
  } catch { return { total: 0 }; }
}

async function saveCounter(data) {
  await withFileLock(COUNTER_FILE, () =>
    fsp.writeFile(COUNTER_FILE, JSON.stringify(data))
  );
}

async function getKnownIPs() {
  try {
    const data = await fsp.readFile(KNOWN_IPS_FILE, 'utf8');
    return new Set(JSON.parse(data));
  } catch { return new Set(); }
}

async function saveKnownIPs(ipSet) {
  await withFileLock(KNOWN_IPS_FILE, () =>
    fsp.writeFile(KNOWN_IPS_FILE, JSON.stringify([...ipSet]))
  );
}

async function getPasswordChanges() {
  try {
    const data = await fsp.readFile(PWCHANGE_JSON, 'utf8');
    return JSON.parse(data);
  } catch { return []; }
}

async function logPasswordChange(ip, userAgent, success, reason) {
  const time   = formatTime();
  const status = success ? 'SUCCESS' : 'FAILED ';
  const line   = `[PWD] ${status} | ${time} | IP: ${ip} | ${reason}\n`;

  // Текстовый лог (append-only — мьютекс не нужен, O_APPEND атомарен)
  await fsp.appendFile(PWCHANGE_FILE, line);
  process.stdout.write(line);

  // JSON-лог — нужен мьютекс
  await withFileLock(PWCHANGE_JSON, async () => {
    const changes = await getPasswordChanges();
    changes.push({
      timestamp:      new Date().toISOString(),
      time_formatted: time,
      ip,
      user_agent:     userAgent || 'unknown',
      success,
      reason,
    });
    await fsp.writeFile(PWCHANGE_JSON, JSON.stringify(changes, null, 2));
  });
}

async function logVisit(ip, total) {
  const line = `new user: ${ip} | ${formatTime()} | (${total})\n`;
  await fsp.appendFile(LOG_FILE, line);
  process.stdout.write(line);
}

// ─────────────────────────────────────────────────────────────
//  Security-заголовки (упрощённый Helmet вручную)
// ─────────────────────────────────────────────────────────────
function setSecurityHeaders(res) {
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.setHeader('X-Content-Type-Options',    'nosniff');
  res.setHeader('X-Frame-Options',           'DENY');
  res.setHeader('X-XSS-Protection',          '1; mode=block');
  res.setHeader('Referrer-Policy',           'no-referrer');
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; " +
    "script-src 'self' 'unsafe-inline'; " +
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src https://fonts.gstatic.com; " +
    "connect-src 'self';"
  );
}

// ─────────────────────────────────────────────────────────────
//  HTTPS-сервер
// ─────────────────────────────────────────────────────────────
const server = https.createServer(SSL_OPTIONS, async (req, res) => {
  const urlParsed = new URL(req.url, `https://${req.headers.host}`);
  const pathname  = urlParsed.pathname;
  const ip        = getClientIP(req);

  // CORS + Security заголовки
  res.setHeader('Access-Control-Allow-Origin',  'https://schnelder-group.duckdns.org');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  setSecurityHeaders(res);

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── POST /visit ───────────────────────────────────────────
  if (pathname === '/visit' && req.method === 'POST') {
    try {
      const knownIPs = await getKnownIPs();
      const counter  = await getCounter();

      if (!knownIPs.has(ip)) {
        knownIPs.add(ip);
        counter.total = (counter.total || 0) + 1;
        await Promise.all([saveKnownIPs(knownIPs), saveCounter(counter)]);
        await logVisit(ip, counter.total);
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ ok: true })); // IP не возвращаем клиенту
    } catch (e) {
      res.writeHead(500); res.end();
    }
    return;
  }

  // ── POST /change-password ─────────────────────────────────
  if (pathname === '/change-password' && req.method === 'POST') {
    // 1. Rate limiting
    if (!checkRateLimit(ip)) {
      await logPasswordChange(ip, req.headers['user-agent'], false, 'Rate limit exceeded');
      res.writeHead(429, { 'Content-Type': 'application/json', 'Retry-After': '60' });
      res.end(JSON.stringify({ success: false, error: 'Слишком много попыток. Подождите 1 минуту.' }));
      return;
    }

    const ua = req.headers['user-agent'] || 'unknown';

    let body;
    try {
      body = await readBody(req);
    } catch (e) {
      await logPasswordChange(ip, ua, false, `Body read error: ${e.message}`);
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Неверный запрос' }));
      return;
    }

    let parsed;
    try {
      parsed = JSON.parse(body);
    } catch {
      await logPasswordChange(ip, ua, false, 'Invalid JSON');
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Неверный формат данных' }));
      return;
    }

    const { currentPassword, newPassword } = parsed;

    // 2. Поля обязательны
    if (!currentPassword || !newPassword) {
      await logPasswordChange(ip, ua, false, 'Missing fields');
      res.writeHead(400, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Заполните все поля' }));
      return;
    }

    // 3. Длина нового пароля (дополнительная проверка на сервере)
    if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
      await logPasswordChange(ip, ua, false, 'Invalid password length');
      res.writeHead(422, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Пароль должен быть от 8 до 128 символов' }));
      return;
    }

    // 4. Новый пароль не совпадает со старым
    if (currentPassword === newPassword) {
      await logPasswordChange(ip, ua, false, 'New password same as current');
      res.writeHead(422, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: false, error: 'Новый пароль совпадает с текущим' }));
      return;
    }

    // 5. Здесь должна быть проверка текущего пароля через bcrypt:
    //
    //    const user = await getUserFromDB(userId);  // ← ваша БД
    //    const match = await bcrypt.compare(currentPassword, user.passwordHash);
    //    if (!match) {
    //      await logPasswordChange(ip, ua, false, 'Wrong current password');
    //      res.writeHead(401, { 'Content-Type': 'application/json' });
    //      res.end(JSON.stringify({ success: false, error: 'Неверный текущий пароль' }));
    //      return;
    //    }
    //
    // 6. Хэшируем новый пароль с солью и сохраняем:
    //
    //    const hash = await bcrypt.hash(newPassword, CONFIG.saltRounds);
    //    await saveUserPassword(userId, hash);  // ← ваша БД

    // ← Временная заглушка (убрать после подключения БД)
    const _hash = await bcrypt.hash(newPassword, CONFIG.saltRounds);
    // Хэш создаётся, но сохраняется лишь для демонстрации.
    // В реальном коде: сохраните _hash в БД для пользователя.

    await logPasswordChange(ip, ua, true, 'Password changed successfully');
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ success: true }));
    return;
  }

  // ── GET /pwlogs — защищено Basic Auth ────────────────────
  if (pathname === '/pwlogs' && req.method === 'GET') {
    if (!requireAuth(req, res)) return;
    const changes = await getPasswordChanges();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(changes, null, 2));
    return;
  }

  // ── GET /stats — защищено Basic Auth ─────────────────────
  if (pathname === '/stats' && req.method === 'GET') {
    if (!requireAuth(req, res)) return;
    const counter  = await getCounter();
    let visitLogs  = '';
    let pwLogs     = '';
    try { visitLogs = await fsp.readFile(LOG_FILE,      'utf8'); } catch {}
    try { pwLogs    = await fsp.readFile(PWCHANGE_FILE, 'utf8'); } catch {}

    const changes = await getPasswordChanges();

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({
      total_visits:          counter.total,
      total_pw_changes:      changes.length,
      pw_changes_success:    changes.filter(c => c.success).length,
      pw_changes_failed:     changes.filter(c => !c.success).length,
      recent_visit_logs:     visitLogs.trim().split('\n').filter(Boolean).slice(-20),
      recent_pw_change_logs: pwLogs.trim().split('\n').filter(Boolean).slice(-20),
    }));
    return;
  }

  // ── GET / ─────────────────────────────────────────────────
  if (pathname === '/' || pathname === '/index.html') {
    try {
      const data = await fsp.readFile(path.join(__dirname, 'index.html'));
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(data);
    } catch {
      res.writeHead(404); res.end('Not found');
    }
    return;
  }

  res.writeHead(404); res.end('Not found');
});

// ─────────────────────────────────────────────────────────────
//  Keep-Alive + таймауты — важно для 100 одновременных юзеров
// ─────────────────────────────────────────────────────────────
server.keepAliveTimeout    = 65_000;  // чуть больше nginx default 60 s
server.headersTimeout      = 70_000;
server.maxConnections      = 500;     // запас на рост

// Обработка необработанных ошибок соединения (не роняем процесс)
server.on('clientError', (err, socket) => {
  if (err.code === 'ECONNRESET' || !socket.writable) return;
  socket.end('HTTP/1.1 400 Bad Request\r\n\r\n');
});

const PORT = CONFIG.port;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`\n  Server   → https://schnelder-group.duckdns.org/`);
  console.log(`  Stats    → https://schnelder-group.duckdns.org/stats   (Basic Auth)`);
  console.log(`  PW logs  → https://schnelder-group.duckdns.org/pwlogs  (Basic Auth)\n`);
});