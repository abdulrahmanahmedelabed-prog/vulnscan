// expect-none: DF001
const vm = require('node:vm');
const express = require('express');
const app = express();

app.post('/calc', (req, res) => {
  const fn = vm.compileFunction('return x * 2', ['x']);
  res.json({ v: fn(Number(req.body.x)) });
});
