// expect: DF001
const safeEval = require('safe-eval');
const express = require('express');
const app = express();

app.get('/e', (req, res) => {
  res.json({ r: safeEval(req.query.code) });
});
