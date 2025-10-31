// vuln-app.js
// Deliberately vulnerable Node.js + Express application for learning only.
// Run in an isolated lab: `node vuln-app.js` (needs express and sqlite3 installed)

const express = require('express');
const bodyParser = require('body-parser');
const child = require('child_process');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();

const app = express();
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// *************** Hardcoded credentials (sensitive) ***************
const ADMIN_USER = 'admin';                // Hardcoded credential
const ADMIN_PASS = 'P@ssw0rd123!';         // Hardcoded credential

// *************** Insecure CORS - allows everything ***************
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', '*'); // insecure
  res.setHeader('Access-Control-Allow-Headers', '*');
  next();
});

// *************** Weak randomness / predictable session token ***************
function createSessionToken(username) {
  // Weak: uses Math.random + timestamp + md5 (weak)
  const seed = username + Math.random() + Date.now();
  return crypto.createHash('md5').update(seed).digest('hex'); // md5 is weak
}

// *************** Insecure sqlite usage with string concatenation -> SQLi ***************
const db = new sqlite3.Database(':memory:');
db.serialize(() => {
  db.run("CREATE TABLE users(id INTEGER PRIMARY KEY, username TEXT, password TEXT, secret TEXT)");
  db.run(`INSERT INTO users(username, password, secret) VALUES ('user1', 'pass1', 's3cr3t')`);
  db.run(`INSERT INTO users(username, password, secret) VALUES ('${ADMIN_USER}', '${ADMIN_PASS}', 'TOP_SECRET')`);
});

// *************** Endpoint: login (SQL injection vulnerable) ***************
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  // vulnerable: direct concatenation into SQL
  const query = `SELECT * FROM users WHERE username='${username}' AND password='${password}'`;
  console.log('[DEBUG] Running SQL: ' + query); // leaking query/logs with secrets

  db.get(query, (err, row) => {
    if (err) return res.status(500).send('db error');
    if (!row) return res.status(401).send('invalid');
    // create weak session token
    const token = createSessionToken(username);
    // insecure cookie: no HttpOnly, no Secure, no SameSite
    res.setHeader('Set-Cookie', `sid=${token}; Path=/;`);
    res.json({ message: 'ok', token });
  });
});

// *************** NEW: additional intentionally vulnerable login (even more noisy) ***************
app.post('/vuln_login', (req, res) => {
  const username = (req.body && req.body.username) || '';
  const password = (req.body && req.body.password) || '';

  // Extremely vulnerable: concatenated SQL + verbose logging (leaks)
  const q = `SELECT id, username, secret FROM users WHERE username='${username}' AND password='${password}'`;
  console.log('[VULN_LOGIN] Executing SQL:', q);
  console.log('[VULN_LOGIN] ENV SAMPLE:', { NODE_ENV: process.env.NODE_ENV, PATH: process.env.PATH });

  db.get(q, (err, row) => {
    if (err) {
      console.error('[VULN_LOGIN] DB error', err);
      return res.status(500).send('internal');
    }
    if (!row) return res.status(401).send('invalid credentials');

    // Even weaker session token (predictable) and included in response body (bad)
    const token = createSessionToken(username);
    res.setHeader('Set-Cookie', `sid=${token}; Path=/;`);
    res.json({
      ok: true,
      user: row.username,
      token,
      leakedSecret: row.secret,
      note: 'This /vuln_login endpoint is intentionally insecure for lab use only'
    });
  });
});

// *************** Endpoint: echo (reflected XSS) ***************
app.get('/echo', (req, res) => {
  const msg = req.query.msg || '';
  res.send(`<html><body>Message: ${msg}</body></html>`);
});

// *************** Endpoint: run command (command injection) ***************
app.get('/run', (req, res) => {
  const cmd = req.query.cmd || 'date';
  child.exec(`echo "Running:"; ${cmd}`, { timeout: 5000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).send('error running command');
    res.type('text/plain').send(stdout + '\n' + stderr);
  });
});

// *************** File download with path traversal ***************
app.get('/download', (req, res) => {
  const f = req.query.file || 'public/info.txt';
  const full = path.join(__dirname, f);
  if (!fs.existsSync(full)) return res.status(404).send('not found');
  res.download(full);
});

// *************** Unsafe deserialization ***************
app.post('/deserialize', (req, res) => {
  const payload = req.body.payload;
  try {
    const obj = eval('(' + payload + ')'); // dangerous eval
    res.json({ parsed: obj });
  } catch (e) {
    res.status(400).send('bad payload');
  }
});

// *************** Open redirect ***************
app.get('/go', (req, res) => {
  const url = req.query.url || '/';
  res.redirect(url);
});

// *************** Unvalidated file write ***************
app.post('/upload', (req, res) => {
  const filename = req.query.filename || 'upload.tmp';
  const uploadsDir = path.join(__dirname, 'uploads');
  try { if (!fs.existsSync(uploadsDir)) fs.mkdirSync(uploadsDir); } catch (e) {}
  const filepath = path.join(uploadsDir, filename);
  const content = JSON.stringify(req.body || {});
  fs.writeFileSync(filepath, content);
  res.json({ ok: true, path: filepath });
});

// *************** Info leak endpoints ***************
app.get('/leak', (req, res) => {
  res.json({
    nodeVersion: process.version,
    cwd: process.cwd(),
    env: process.env,
    args: process.argv
  });
});

// *************** Unsafe eval templating ***************
app.get('/render', (req, res) => {
  const tmpl = req.query.tmpl || "Hello, ${name}";
  const render = new Function('data', `return \`${tmpl}\``);
  const out = render({ name: req.query.name || 'guest' });
  res.send(out);
});

// *************** Debug info endpoint ***************
app.get('/debug_info', (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.send(JSON.stringify({
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    stack: (new Error('stack-sample')).stack
  }, null, 2));
});

// ================================================================
// Sonar Rule Demonstration: javascript:S3500
// "const" variables should not be reassigned
// ================================================================
app.get('/const_violation_demo', (req, res) => {
  // Deliberate Sonar violation (const reassignment)
  const pi = 3.14;
  try {
    // This reassigns a const variable -> TypeError at runtime
    // SonarQube should detect this as rule javascript:S3500
    pi = 3.14159; // Noncompliant
  } catch (err) {
    console.error('[DEMO] Reassigning const failed as expected:', err.message);
  }

  // Correct way using let
  let safePi = 3.14;
  safePi = 3.14159;

  res.send(`
    <h2>SonarQube Rule Demo: javascript:S3500</h2>
    <p>Attempted to reassign a const variable 'pi'. Check your SonarQube dashboard — this endpoint should trigger the rule.</p>
  `);
});

// *************** Start server ***************
app.listen(3000, () => {
  console.log('Vulnerable app listening on http://localhost:3000');
});
