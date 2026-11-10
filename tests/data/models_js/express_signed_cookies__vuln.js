// expect: DF001
const express = require('express');
const app = express();

app.get('/pref', (req, res) => {
  eval('var prefs = ' + req.signedCookies.prefs);
  res.end();
});
