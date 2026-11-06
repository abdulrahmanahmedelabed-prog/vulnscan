const express = require('express');
const mysql = require('mysql2');
const mongoose = require('mongoose');
const { exec } = require('child_process');
const app = express();
const pool = mysql.createPool({});
const Msg = mongoose.model('Msg', new mongoose.Schema({ text: String, who: String }));

app.post('/m', async (req, res) => {
  await Msg.create({ text: req.body.text, who: 'x' });
  pool.query('INSERT INTO logs (line) VALUES (?)', [req.query.l]);
});

app.get('/m', async (req, res) => {
  const m = await Msg.findById(req.params.id);
  res.send('<b>' + m.text + '</b>');
  res.send('<b>' + m.who + '</b>');
  const [rows] = await pool.query('SELECT line FROM logs');
  exec('echo ' + rows[0].line);
});
