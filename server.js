const https  = require('https');
const fs     = require('fs');
const path   = require('path');

const LOG_FILE       = path.join(__dirname, 'visitors.log');
const COUNTER_FILE   = path.join(__dirname, 'counter.json');
const KNOWN_IPS_FILE = path.join(__dirname, 'known_ips.json');
const PWCHANGE_FILE  = path.join(__dirname, 'password_changes.log');
const PWCHANGE_JSON  = path.join(__dirname, 'password_changes.json');
const pixelPath      = path.join(__dirname, 'image.png');

//  SSL-сертификаты
const SSL_OPTIONS = {
  key:  fs.readFileSync(path.join('C:/Certbot/live/schnelder-group.duckdns.org/privkey.pem')),
  cert: fs.readFileSync(path.join('C:/Certbot/live/schnelder-group.duckdns.org/fullchain.pem')),
};

/** Форматирует текущее время в виде DD.MM.YYYY HH:MM:SS */
function formatTime() {
  const now = new Date();
  const pad = n => String(n).padStart(2, '0');
  return `${pad(now.getDate())}.${pad(now.getMonth()+1)}.${now.getFullYear()} ` +
         `${pad(now.getHours())}:${pad(now.getMinutes())}:${pad(now.getSeconds())}`;
}

/** Возвращает реальный IP клиента (учитывает прокси X-Forwarded-For) */
function getClientIP(req) {
  const fwd = req.headers['x-forwarded-for'];
  return fwd ? fwd.split(',')[0].trim() : (req.socket.remoteAddress || 'unknown');
}

/** Проверяет, что строка похожа на SHA-256 хэш (64 hex-символа) */
function isSHA256Hash(str) {
  return typeof str === 'string' && /^[a-f0-9]{64}$/i.test(str);
}

// ─────────────────────────────────────────────────────────────
//  Счётчик посетителей
// ─────────────────────────────────────────────────────────────
function getCounter() {
  try { return JSON.parse(fs.readFileSync(COUNTER_FILE, 'utf8')); }
  catch { return { total: 0 }; }
}
function saveCounter(data) {
  fs.writeFileSync(COUNTER_FILE, JSON.stringify(data));
}

// ─────────────────────────────────────────────────────────────
//  Список известных IP-адресов (для подсчёта уникальных)
// ─────────────────────────────────────────────────────────────
function getKnownIPs() {
  try { return new Set(JSON.parse(fs.readFileSync(KNOWN_IPS_FILE, 'utf8'))); }
  catch { return new Set(); }
}
function saveKnownIPs(ipSet) {
  fs.writeFileSync(KNOWN_IPS_FILE, JSON.stringify([...ipSet]));
}

//  Логирование смен паролей
function getPasswordChanges() {
  try { return JSON.parse(fs.readFileSync(PWCHANGE_JSON, 'utf8')); }
  catch { return []; }
}

function logPasswordChange(ip, userAgent, success, reason) {
  const time   = formatTime();
  const status = success ? 'SUCCESS' : 'FAILED ';

  // Текстовый лог — только статус, время, IP, причина (без паролей и хэшей)
  const line = `[PWD] ${status} | ${time} | IP: ${ip} | ${reason}\n`;
  fs.appendFileSync(PWCHANGE_FILE, line);
  process.stdout.write(line);

  // JSON-лог для /pwlogs
  const changes = getPasswordChanges();
  changes.push({
    timestamp:      new Date().toISOString(),
    time_formatted: time,
    ip,
    user_agent:     userAgent || 'unknown',
    success,
    reason,
  });
  fs.writeFileSync(PWCHANGE_JSON, JSON.stringify(changes, null, 2));
}

//  Лог посещений
function logVisit(ip, total) {
  const line = `new user: ${ip} | ${formatTime()} | (${total})\n`;
  fs.appendFileSync(LOG_FILE, line);
  process.stdout.write(line);
}

//  HTTPS-сервер
const server = https.createServer(SSL_OPTIONS, (req, res) => {
  const urlParsed = new URL(req.url, `https://${req.headers.host}`);
  const pathname  = urlParsed.pathname;
  const query     = urlParsed.searchParams;
  const ip        = getClientIP(req);

  // CORS
  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  // ── POST /visit — учёт уникальных посетителей ─────────────────
  if (pathname === '/visit' && req.method === 'POST') {
    const knownIPs = getKnownIPs();
    const counter  = getCounter();
    let isNew      = false;

    if (!knownIPs.has(ip)) {
      knownIPs.add(ip);
      saveKnownIPs(knownIPs);
      counter.total = (counter.total || 0) + 1;
      saveCounter(counter);
      logVisit(ip, counter.total);
      isNew = true;
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ total: counter.total, ip, isNew }));
    return;
  }

  // ── POST /change-password ─────────────────────────────────────
  if (pathname === '/change-password' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      const ua = req.headers['user-agent'] || 'unknown';

      let parsed;
      try {
        parsed = JSON.parse(body);
      } catch {
        logPasswordChange(ip, ua, false, 'Invalid JSON body');
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid JSON' }));
        return;
      }

      const { currentPassword, newPassword } = parsed;

      // Оба поля обязательны
      if (!currentPassword || !newPassword) {
        logPasswordChange(ip, ua, false, 'Missing fields in request');
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Missing fields' }));
        return;
      }

      // Проверяем, что оба значения — это SHA-256 хэши (64 hex-символа).
      // Если клиент прислал plaintext — отклоняем: пароли должны хэшироваться
      // на стороне браузера, сервер не должен видеть их в открытом виде.
      if (!isSHA256Hash(currentPassword) || !isSHA256Hash(newPassword)) {
        logPasswordChange(ip, ua, false, 'Rejected: received plaintext instead of hash');
        res.writeHead(422, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: false,
          error:   'Passwords must be SHA-256 hashed before sending',
        }));
        return;
      }

      // Хэши совпадают → новый пароль совпадает со старым
      if (currentPassword === newPassword) {
        logPasswordChange(ip, ua, false, 'New password hash identical to current');
        res.writeHead(422, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          success: false,
          error:   'Новый пароль не должен совпадать с текущим',
        }));
        return;
      }

      // Всё в порядке — логируем успех (без хэшей!)
      logPasswordChange(ip, ua, true, 'Password changed successfully');
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true }));
    });
    return;
  }

  // ── GET /pwlogs — список событий смены пароля (JSON) ──────────
  if (pathname === '/pwlogs' && req.method === 'GET') {
    const changes = getPasswordChanges();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(changes, null, 2));
    return;
  }

  // ── GET /stats — общая статистика сервера ─────────────────────
  if (pathname === '/stats' && req.method === 'GET') {
    const counter = getCounter();
    let visitLogs = '';
    let pwLogs    = '';
    try { visitLogs = fs.readFileSync(LOG_FILE,      'utf8'); } catch {}
    try { pwLogs    = fs.readFileSync(PWCHANGE_FILE, 'utf8'); } catch {}

    const changes = getPasswordChanges();

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

  // ── GET / или /index.html — статичная HTML-страница ───────────
  if (pathname === '/' || pathname === '/index.html') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(404); res.end('Not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  // ── 404 ────────────────────────────────────────────────────────
  res.writeHead(404);
  res.end('Not found');
});

// ─────────────────────────────────────────────────────────────
//  Запуск
// ─────────────────────────────────────────────────────────────
const PORT = process.env.PORT || 443;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`  Server           → https://schnelder-group.duckdns.org/`);
  console.log(`  Stats            → https://schnelder-group.duckdns.org:${PORT}/stats`);
  console.log(`  PW change logs   → https://schnelder-group.duckdns.org:${PORT}/pwlogs`);
});