// expect: DF008
const express = require('express');
const app = express();

app.get('/go', (req, res) => {
  res.location(req.query.to);
  res.sendStatus(302);
});
