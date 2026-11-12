const express = require('express');
const { exec } = require('child_process');
const db = require('../db');
const router = express.Router();

router.get('/:id', async (req, res) => {
  const rows = await db.query('SELECT * FROM users WHERE id = ' + req.params.id);
  res.json(rows);
});

router.get('/search', (req, res) => {
  const term = req.query.q;
  const lang = req.headers['accept-language'];
  db.query("SELECT name FROM users WHERE name LIKE '%" + term + "%'").then(r => res.json({ r, lang }));
});

router.post('/ping', function (req, res) {
  runPing(req.body.host, res);
});

function runPing(host, res) {
  exec('ping -c 1 ' + host, (err, out) => res.send(out));
}

module.exports = router;
