// expect-none: DF001
const express = require('express');
const app = express();

app.get('/pref', (req, res) => {
  const prefs = JSON.parse(req.signedCookies.prefs);
  res.json(prefs);
});
