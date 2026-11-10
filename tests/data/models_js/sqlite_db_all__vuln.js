// expect: DF004
const sqlite3 = require('sqlite3');
const db = new sqlite3.Database('app.db');
const express = require('express');
const app = express();

app.get('/item', (req, res) => {
  db.all("SELECT * FROM items WHERE id = " + req.query.id, (err, rows) => res.json(rows));
});
