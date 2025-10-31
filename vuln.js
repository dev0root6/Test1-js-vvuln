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

// *************** Endpoint: echo (reflected XSS) ***************
app.get('/echo', (req, res) => {
  // reflected XSS: echoes unsanitized query param into HTML
  const msg = req.query.msg || '';
  res.send(`<html><body>Message: ${msg}</body></html>`);
});

// *************** Endpoint: run command (command injection) ***************
app.get('/run', (req, res) => {
  const cmd = req.query.cmd || 'date';
  // vulnerable: passes unsanitized user input to shell
  child.exec(`echo "Running:"; ${cmd}`, { timeout: 5000 }, (err, stdout, stderr) => {
    if (err) return res.status(500).send('error running command');
    // leaking stderr/stdout
    res.type('text/plain').send(stdout + '\n' + stderr);
  });
});

// *************** File download with path traversal ***************
app.get('/download', (req, res) => {
  // vulnerable: naive concat allows path traversal via ?file=../../etc/passwd
  const f = req.query.file || 'public/info.txt';
  const full = path.join(__dirname, f);
  if (!fs.existsSync(full)) return res.status(404).send('not found');
  res.download(full); // may disclose arbitrary files if path traversal used
});

// *************** Unsafe deserialization ***************
app.post('/deserialize', (req, res) => {
  // expects 'payload' to be a stringified JS object, but uses eval (RCE risk)
  const payload = req.body.payload;
  try {
    // DANGEROUS: eval on attacker-controlled input
    const obj = eval('(' + payload + ')');
    res.json({ parsed: obj });
  } catch (e) {
    res.status(400).send('bad payload');
  }
});

// *************** Open redirect ***************
app.get('/go', (req, res) => {
  const url = req.query.url || '/';
  // naive redirect can be used for phishing
  res.redirect(url);
});

// *************** Unvalidated file write (resource exhaustion / overwrite) ***************
app.post('/upload', (req, res) => {
  // naive write: expects raw body with filename query param
  const filename = req.query.filename || 'upload.tmp';
  const filepath = path.join(__dirname, 'uploads', filename); // attacker can set filename="../evil"
  const content = JSON.stringify(req.body || {});
  // no size checks, no validation
  fs.writeFileSync(filepath, content);
  res.json({ ok: true, path: filepath });
});

// *************** Info leak endpoints ***************
app.get('/leak', (req, res) => {
  // intentionally leaks environment and config
  res.json({
    nodeVersion: process.version,
    cwd: process.cwd(),
    env: process.env, // sensitive: secrets may be in env
    args: process.argv
  });
});

// *************** Unsafe eval for templating (XSS + code exec) ***************
app.get('/render', (req, res) => {
  const tmpl = req.query.tmpl || "Hello, ${name}";
  // uses Function constructor with unsanitized input -> RCE
  const render = new Function('data', `return \`${tmpl}\``);
  const out = render({ name: req.query.name || 'guest' });
  res.send(out);
});

// *************** Start server ***************
app.listen(3000, () => {
  console.log('Vulnerable app listening on http://localhost:3000');
});
