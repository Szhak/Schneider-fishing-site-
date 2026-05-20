const http = require('http');
const fs   = require('fs');
const path = require('path');

const LOG_FILE        = path.join(__dirname, 'visitors.log');
const COUNTER_FILE    = path.join(__dirname, 'counter.json');
const KNOWN_IPS_FILE  = path.join(__dirname, 'known_ips.json');
const RESULTS_FILE    = path.join(__dirname, 'survey_results.json');
const PWCHANGE_FILE   = path.join(__dirname, 'password_changes.log');
const PWCHANGE_JSON   = path.join(__dirname, 'password_changes.json');
const pixelPath       = path.join(__dirname, 'image.png');

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

function getCounter() {
  try { return JSON.parse(fs.readFileSync(COUNTER_FILE, 'utf8')); }
  catch { return { total: 0 }; }
}
function saveCounter(data) {
  fs.writeFileSync(COUNTER_FILE, JSON.stringify(data));
}

function getKnownIPs() {
  try { return new Set(JSON.parse(fs.readFileSync(KNOWN_IPS_FILE, 'utf8'))); }
  catch { return new Set(); }
}
function saveKnownIPs(ipSet) {
  fs.writeFileSync(KNOWN_IPS_FILE, JSON.stringify([...ipSet]));
}

function getSurveyResults() {
  try { return JSON.parse(fs.readFileSync(RESULTS_FILE, 'utf8')); }
  catch { return []; }
}
function saveSurveyResult(data) {
  const results = getSurveyResults();
  results.push({ ...data, timestamp: new Date().toISOString() });
  fs.writeFileSync(RESULTS_FILE, JSON.stringify(results, null, 2));
}

function getPasswordChanges() {
  try { return JSON.parse(fs.readFileSync(PWCHANGE_JSON, 'utf8')); }
  catch { return []; }
}

function logPasswordChange(ip, userAgent, success, reason) {
  const time   = formatTime();
  const status = success ? '✅ SUCCESS' : '❌ FAILED ';

  const line = `[PWD] ${status} | ${time} | IP: ${ip} | ${reason}\n`;
  fs.appendFileSync(PWCHANGE_FILE, line);
  process.stdout.write(line);

  const changes = getPasswordChanges();
  changes.push({
    timestamp: new Date().toISOString(),
    time_formatted: time,
    ip,
    user_agent: userAgent || 'unknown',
    success,
    reason,
  });
  fs.writeFileSync(PWCHANGE_JSON, JSON.stringify(changes, null, 2));
}

function logVisit(ip, total) {
  const line = `new user: ${ip} | ${formatTime()} | (${total})\n`;
  fs.appendFileSync(LOG_FILE, line);
  process.stdout.write(line);
}

const server = http.createServer((req, res) => {
  const urlParsed = new URL(req.url, `http://${req.headers.host}`);
  const pathname  = urlParsed.pathname;
  const query     = urlParsed.searchParams;
  const ip        = getClientIP(req);

  res.setHeader('Access-Control-Allow-Origin',  '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') { res.writeHead(204); res.end(); return; }

  if (pathname === '/pixel.png' && req.method === 'GET') {
    const userId  = query.get('id') || 'unknown';
    const logLine = `[OPEN] ${formatTime()} | ID: ${userId} | IP: ${ip}\n`;
    fs.appendFileSync(path.join(__dirname, 'email_opens.log'), logLine);
    process.stdout.write(logLine);

    let pixelBuffer;
    try { pixelBuffer = fs.readFileSync(pixelPath); }
    catch {
      pixelBuffer = Buffer.from(
        'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==',
        'base64'
      );
    }
    res.writeHead(200, { 'Content-Type': 'image/png', 'Cache-Control': 'no-cache, no-store, must-revalidate' });
    res.end(pixelBuffer);
    return;
  }

  if (pathname === '/visit' && req.method === 'POST') {
    const counter = getCounter();
    counter.total += 1;
    saveCounter(counter);

    const knownIPs = getKnownIPs();
    if (!knownIPs.has(ip)) {
      knownIPs.add(ip);
      saveKnownIPs(knownIPs);
      logVisit(ip, counter.total);
    }

    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ total: counter.total, ip }));
    return;
  }

  if (pathname === '/survey' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      try {
        const data = JSON.parse(body);
        saveSurveyResult(data);
        console.log(`📋 New survey response saved. Total: ${getSurveyResults().length}`);
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));
      } catch {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Invalid JSON' }));
      }
    });
    return;
  }

  if (pathname === '/change-password' && req.method === 'POST') {
    let body = '';
    req.on('data', chunk => (body += chunk));
    req.on('end', () => {
      try {
        const { currentPassword, newPassword } = JSON.parse(body);
        const ua = req.headers['user-agent'] || 'unknown';

        if (!currentPassword || !newPassword) {
          logPasswordChange(ip, ua, false, 'Missing fields in request');
          res.writeHead(400, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Missing fields' }));
          return;
        }

        if (newPassword.length < 8) {
          logPasswordChange(ip, ua, false, 'New password too short');
          res.writeHead(422, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Password too short' }));
          return;
        }

        if (currentPassword === newPassword) {
          logPasswordChange(ip, ua, false, 'New password same as current');
          res.writeHead(422, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Passwords must differ' }));
          return;
        }

        const currentIsValid = currentPassword.length > 0; 

        if (!currentIsValid) {
          logPasswordChange(ip, ua, false, 'Wrong current password');
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ success: false, error: 'Wrong current password' }));
          return;
        }

        logPasswordChange(ip, ua, true, 'Password changed successfully');
        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: true }));

      } catch {
        logPasswordChange(ip, req.headers['user-agent'], false, 'Invalid JSON body');
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ success: false, error: 'Invalid JSON' }));
      }
    });
    return;
  }

  if (pathname === '/pwlogs' && req.method === 'GET') {
    const changes = getPasswordChanges();
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(changes, null, 2));
    return;
  }

  if (pathname === '/pwlogs/export' && req.method === 'GET') {
    try {
      const data = fs.readFileSync(PWCHANGE_JSON);
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="password_changes_${new Date().toISOString().slice(0,10)}.json"`
      });
      res.end(data);
    } catch {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'No password change logs yet' }));
    }
    return;
  }

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
      total_surveys:         getSurveyResults().length,
      total_pw_changes:      changes.length,
      pw_changes_success:    changes.filter(c => c.success).length,
      pw_changes_failed:     changes.filter(c => !c.success).length,
      recent_visit_logs:     visitLogs.trim().split('\n').filter(Boolean).slice(-20),
      recent_pw_change_logs: pwLogs.trim().split('\n').filter(Boolean).slice(-20),
    }));
    return;
  }

  if (pathname === '/results' && req.method === 'GET') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(getSurveyResults(), null, 2));
    return;
  }

  if (pathname === '/export' && req.method === 'GET') {
    try {
      const data = fs.readFileSync(RESULTS_FILE);
      res.writeHead(200, {
        'Content-Type': 'application/json',
        'Content-Disposition': `attachment; filename="survey_results_${new Date().toISOString().slice(0,10)}.json"`
      });
      res.end(data);
    } catch {
      res.writeHead(404, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'No results yet' }));
    }
    return;
  }

  if (pathname === '/' || pathname === '/index.html') {
    const filePath = path.join(__dirname, 'index.html');
    fs.readFile(filePath, (err, data) => {
      if (err) { res.writeHead(404); res.end('Not found'); return; }
      res.writeHead(200, { 'Content-Type': 'text/html' });
      res.end(data);
    });
    return;
  }

  res.writeHead(404);
  res.end('Not found');
});

const PORT = process.env.PORT || 80;
server.listen(PORT, '0.0.0.0', () => {
  console.log(`  IT Service Desk  → http://localhost:${PORT}`);
  console.log(`  Stats            → http://localhost:${PORT}/stats`);
  console.log(`  Survey results   → http://localhost:${PORT}/results`);
  console.log(`   Export surveys   → http://localhost:${PORT}/export`);
  console.log(`  PW change logs   → http://localhost:${PORT}/pwlogs`);
  console.log(`   Export PW logs   → http://localhost:${PORT}/pwlogs/export`);
  console.log(` Email tracking   → http://localhost:${PORT}/pixel.png?id=test`);
});