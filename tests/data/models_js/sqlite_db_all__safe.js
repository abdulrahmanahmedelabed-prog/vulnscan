// expect-none: DF004
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('app.db');
const cache = new Map();
const express = require('express');
const app = express();

app.get('/item', (req, res) => {
  cache.get(req.query.id);
  db.all('SELECT * FROM items WHERE id = ?', [req.query.id], (err, rows) => res.json(rows));
});
