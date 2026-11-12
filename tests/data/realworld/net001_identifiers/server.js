const http = require('http');
http.createServer((req, res) => {
  const { pathname } = new URL(`http://n${req.url}`);
  const base = new URL(req.url, 'http://app.local');
  res.end('<a href="http://docs.acme.io/help">help</a>' + pathname + base.search);
}).listen(3000);
fetch('http://api.acme.io/v1/items');
