const crypto = require('crypto');
const cors = require('cors');
const express = require('express');
const app = express();
const allowed = new Set(['https://app.corp.internal']);
const modern = crypto.createCipheriv('aes-256-gcm', key, iv);
app.use(cors({ origin: ['https://app.corp.internal'], credentials: true }));
app.get('/data', (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', allowed.has(req.headers.origin) ? req.headers.origin : 'null');
  res.send('ok');
});
