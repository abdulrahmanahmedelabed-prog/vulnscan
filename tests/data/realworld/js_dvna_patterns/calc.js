const mathjs = require('mathjs');
const express = require('express');
const app = express();
// MISS: code injection through mathjs.eval/evaluate of user input (DVNA A1, CVE-2017-1001002 class)
app.post('/calc', function (req, res) {
  res.json({ out: mathjs.eval(req.body.eqn) });
});
// safe twin: constant expression
app.post('/calc2', function (req, res) {
  res.json({ out: mathjs.evaluate('(3+3)*2') });
});
