const express = require('express');
const escapeHtml = require('escape-html');
const { exec } = require('child_process');
const app = express();

app.get('/search', (req, res) => {
  const q = req.query.q || '';
  res.send(`<h1>Results for ${escapeHtml(q)}</h1>`);
});

app.get('/ping', (req, res) => {
  exec('ping -c 1 ' + req.query.host, (err, out) => res.send(out));
});

app.listen(3000);
