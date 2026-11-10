// expect: DF005
const express = require('express');
const app = express();

app.get('/page', (req, res) => {
  res.render(req.query.page, { title: 'Home' });
});
