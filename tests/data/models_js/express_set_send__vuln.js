// expect: DF013
const express = require('express');
const app = express();

app.get('/hello', (req, res) => {
  res.set('X-Frame-Options', 'DENY').send(`<p>${req.query.q}</p>`);
});
