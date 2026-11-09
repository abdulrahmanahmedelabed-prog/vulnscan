const express = require('express');
const app = express();
const { exec } = require('child_process');
app.get('/a', (req, res) => {
  let mode = 0;
  mode++;
  if (mode === 1) { exec(req.query.c); }
});
app.get('/b', (req, res) => {
  for (const k of [1, 2]) {
    switch (req.query.t) {
      case 'x': break;
      default: exec(req.query.d);
    }
  }
});
app.get('/c', (req, res) => {
  let n = 0 ?? 5;
  if (n === 0) { exec(req.query.e); }
  let s = "3" * 2;
  if (s == 6) { exec(req.query.f); }
  let z = 5; z -= 5;
  if (z === 0) { exec(req.query.g); }
});
app.get('/d', (req, res) => {
  let k = 1;
  switch (k) {
    case 1: exec(req.query.h);
    case 2: break;
  }
});
