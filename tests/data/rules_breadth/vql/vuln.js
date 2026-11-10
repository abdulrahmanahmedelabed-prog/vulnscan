const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const session = require('express-session');
const app = express();
// expect-next: vql/cors-credentials-any-origin
app.use(cors({
  origin: true,
  credentials: true,
}));
// expect-next: vql/jwt-hardcoded-secret
const token = jwt.sign({ sub: 'u' }, 'hardcoded-secret');
// expect-next: vql/cipher-static-iv
const enc = crypto.createCipheriv('aes-256-cbc', key, Buffer.alloc(16));
// expect-next: vql/kdf-hardcoded-salt
const dk = crypto.pbkdf2Sync(pw, 'fixedsalt', 100000, 32, 'sha256');
// expect-next: vql/js-cookie-insecure
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: false } }));
app.get('/login', (req, res) => {
  // expect-next: vql/js-cookie-insecure
  res.cookie('sid', req.query.sid, { httpOnly: false });
  res.send('ok');
});
