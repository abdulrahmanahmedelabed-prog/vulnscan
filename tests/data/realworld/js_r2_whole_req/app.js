const express = require('express');
const app = express();

// FP: server-side state hanging off req (session counter, req.user set by auth middleware, req.protocol)
app.get('/count', function (req, res) {
  res.send('viewed ' + req.session.views + ' times; proto ' + req.protocol);
});
// FP: handler return value `return res.render(...)` reported because `res` itself is a tainted entry param
app.get('/page', (req, res) => {
  return res.render('index', { title: 'x' });
});
// FP: error-handler (err, req, res, next): err is not user input; and res.send(object) is JSON, not HTML
app.use(function (err, req, res, next) {
  res.send({ error: err.message });
});
// TP (must stay reported): reflected user input
app.get('/echo', function (req, res) {
  res.send('hello ' + req.query.name);
});
