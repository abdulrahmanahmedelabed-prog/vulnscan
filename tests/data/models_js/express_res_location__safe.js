// expect-none: DF008
const express = require('express');
const app = express();

const ALLOWED = ['/home', '/profile'];
app.get('/go', (req, res) => {
  if (ALLOWED.includes(req.query.to)) {
    res.location(req.query.to);
  }
  res.sendStatus(302);
});
