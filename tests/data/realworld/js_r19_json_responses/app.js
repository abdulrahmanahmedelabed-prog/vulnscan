const express = require('express'); const app = express();
// FP: object passed to res.send is serialised as application/json
app.get('/a', function (req, res) { res.status(200).send({ q: req.query.q }); });
// FP: Server-Sent Events with JSON.stringify payload (text/event-stream, JSON-encoded)
app.post('/chat', function (req, res) {
  res.setHeader('Content-Type', 'text/event-stream');
  res.write(`data: ${JSON.stringify({ content: req.body.message })}\n\n`);
  res.end();
});
// TP twin: string concatenation into an HTML body
app.get('/b', function (req, res) { res.send('<p>' + req.query.q + '</p>'); });
