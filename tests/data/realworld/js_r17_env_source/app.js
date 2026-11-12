const express = require('express'); const app = express(); const logger = require('./logger');
// FP: process.env is operator configuration, not remote input (labelled "req.env")
app.post('/profile', function (req, res) {
  res.location(process.env.BASE_PATH + '/profile');
  res.redirect(process.env.BASE_PATH + '/profile');
});
logger.info(`Server using proxy base path ${process.env.BASE_PATH} for redirects`);
// TP twin
app.get('/go', function (req, res) { res.redirect(req.query.next); });
