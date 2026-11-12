const express = require('express');
const app = express();
let col;
// MISS: NoSQL $where injection (NodeGoat A1-2): tainted string inside a {$where: `...`} object passed to find()
app.get('/alloc', function (req, res) {
  const threshold = req.query.threshold;
  col.find({ $where: `this.stocks > '${threshold}'` }).toArray((e, r) => res.json(r));
});
// safe twin
app.get('/alloc2', function (req, res) {
  const threshold = parseInt(req.query.threshold, 10);
  col.find({ stocks: { $gt: threshold } }).toArray((e, r) => res.json(r));
});
