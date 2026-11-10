const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const session = require('express-session');
const app = express();
app.use(cors({
  origin: ['https://app.corp.internal'],
  credentials: true,
}));
const token = jwt.sign({ sub: 'u' }, process.env.JWT_KEY);
const claims = jwt.verify(token, '-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE\n-----END PUBLIC KEY-----', { algorithms: ['ES256'] });
const enc = crypto.createCipheriv('aes-256-gcm', key, crypto.randomBytes(12));
const salt = crypto.randomBytes(16);
const dk = crypto.pbkdf2Sync(pw, salt, 100000, 32, 'sha256');
app.use(session({ secret: process.env.SESSION_SECRET, cookie: { secure: true, httpOnly: true } }));
app.get('/login', (req, res) => {
  res.cookie('sid', req.query.sid, { httpOnly: true, secure: true });
  res.send('ok');
});
