const express = require('express');
const mysql = require('mysql');
const db = mysql.createConnection({});
const app = express();
function buildQuery(table, id) {
  return 'SELECT * FROM ' + table + ' WHERE id = ' + id;
}
app.get('/item/:id', (req, res) => {
  db.query(buildQuery('items', req.params.id), (err, rows) => res.json(rows)); // SINK
});
