const libxmljs = require('libxmljs');
const express = require('express');
const app = express();
// MISS: XXE (DVNA A4)
app.post('/xml', function (req, res) {
  const doc = libxmljs.parseXmlString(req.body.xml, { noent: true, noblanks: true });
  res.send(doc.root().text());
});
// safe twin: entities not expanded
app.post('/xml2', function (req, res) {
  const doc = libxmljs.parseXmlString(req.body.xml, { noblanks: true });
  res.json({ n: doc.root().childNodes().length });
});
