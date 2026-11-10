// expect: DF004
const express = require('express');
const app = express();

app.post('/purge', async (req, res) => {
  await db.collection('sessions').deleteMany({ owner: req.body.owner });
  res.end();
});
