const express = require('express'); const { query } = require('express-validator'); const z = require('zod');
const cp = require('child_process'); const app = express();
app.get('/a', query('id').isInt(), (req, res) => { cp.exec('echo ' + req.query.id); res.end(); });
app.get('/b', query('id').notEmpty(), (req, res) => { cp.exec('echo ' + req.query.id); res.end(); });
app.get('/c', (req, res) => { const n = z.coerce.number().parse(req.query.n); cp.exec('echo ' + n); res.end(); });
app.get('/d', (req, res) => { const n = z.string().parse(req.query.n); cp.exec('echo ' + n); res.end(); });
