const express = require('express');
const app = express();
// MISS: log injection via console.log (NodeGoat A1-3); only logger.*/winston.* and arg 0 are modelled
app.post('/login', function (req, res) {
  const userName = req.body.userName;
  console.log('Error: attempt to login with invalid user: ', userName);
  res.sendStatus(401);
});
// safe twin: CR/LF stripped
app.post('/login2', function (req, res) {
  const userName = String(req.body.userName).replace(/[\r\n]/g, '');
  console.log('Error: attempt to login with invalid user: ', userName);
  res.sendStatus(401);
});
