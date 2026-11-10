// expect: DF013
const express = require('express');
const app = express();

app.get('/hello', (req, res) => {
  res.status(200).send('<h1>Hello ' + req.query.name + '</h1>');
});
