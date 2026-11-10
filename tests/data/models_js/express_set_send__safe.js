// expect-none: DF013
const express = require('express');
const app = express();

const he = require('he');
app.get('/hello', (req, res) => {
  res.set('X-Frame-Options', 'DENY').send(`<p>${he.escape(req.query.q)}</p>`);
});
app.get('/plain', (req, res) => {
  res.type('text/plain').send(req.query.q);
});
