// expect-none: DF005
const express = require('express');
const app = express();

app.get('/page', (req, res) => {
  res.render('page', { title: req.query.title });
});
