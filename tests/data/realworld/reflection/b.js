const express = require('express'); const app = express();
const handlers = { a() { return 1; } };
app.get('/x', (req, res) => { handlers[req.query.fn](); require(req.query.mod); res.end('ok'); });
app.get('/y', (req, res) => { handlers['a'](); require('./x'); res.end('ok'); });
