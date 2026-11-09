const express = require('express');
const escapeHtml = require('escape-html');
const app = express();
app.get('/x', (req, res) => {
  const a = req.query.a;
  const b = req.query.b;
  const s = escapeHtml(a) + b;
  res.send('<p>' + s + '</p>');
});
