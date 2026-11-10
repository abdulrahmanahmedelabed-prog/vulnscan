const crypto = require('crypto');
const cors = require('cors');
const express = require('express');
const app = express();
// expect-next: CRY009
const legacy = crypto.createCipheriv('des-ede3-cbc', key, iv);
// expect-next: CORS001
app.use(cors({ origin: true, credentials: true }));
app.get('/data', (req, res) => {
  // expect-next: CORS002
  res.setHeader('Access-Control-Allow-Origin', req.headers.origin);
  res.send('ok');
});
