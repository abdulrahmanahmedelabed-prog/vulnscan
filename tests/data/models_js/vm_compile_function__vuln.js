// expect: DF001
const vm = require('node:vm');
const express = require('express');
const app = express();

app.post('/calc', (req, res) => {
  const fn = vm.compileFunction(req.body.expr, ['x']);
  res.json({ v: fn(1) });
});
