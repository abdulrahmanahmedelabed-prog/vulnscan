// expect-none: DF013
const express = require('express');
const app = express();

const escapeHtml = require('escape-html');
app.get('/hello', (req, res) => {
  res.status(200).send('<h1>Hello ' + escapeHtml(req.query.name) + '</h1>');
});
