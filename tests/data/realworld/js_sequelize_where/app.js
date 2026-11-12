const express = require('express');
const db = require('./models');
const app = express();
// FP: Sequelize where-object values are bound parameters
app.post('/find', function (req, res) {
  db.User.findOne({ where: { login: String(req.body.login) } }).then(u => res.json(u));
});
// TP twin: raw query string
app.post('/raw', function (req, res) {
  db.sequelize.query("SELECT * FROM Users WHERE login='" + req.body.login + "'").then(u => res.json(u));
});
