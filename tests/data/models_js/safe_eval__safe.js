// expect-none: DF001
const express = require('express');
const app = express();

app.get('/e', (req, res) => {
  res.json({ r: JSON.parse(req.query.code) });
});
