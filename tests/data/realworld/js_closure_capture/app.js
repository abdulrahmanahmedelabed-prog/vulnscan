const express = require('express'); const cp = require('child_process'); const fs = require('fs'); const app = express();
// MISS (dataflow): tainted local captured by a nested callback/closure. Only the regex EXE005 fires; DF002 does not.
app.get('/a', function (req, res) {
  const name = req.query.name;
  fs.stat('/tmp/x', function (err, st) { cp.execSync('ls ' + name); });
});
app.get('/c', function (req, res) {
  const name = req.query.name;
  const run = () => cp.execSync('ls ' + name);
  run();
});
// safe twin: captured value is a constant
app.get('/d', function (req, res) {
  const name = 'tmp';
  fs.stat('/tmp/x', function (err, st) { cp.execSync('ls ' + name); });
});
// contrast (reported): no closure
app.get('/e', function (req, res) { cp.execSync('ls ' + req.query.name); });
