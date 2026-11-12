const express = require('express');
const session = require('express-session');
const app = express();
// MISS: hard-coded express-session signing secret (DVNA A6 / A2)
app.use(session({ secret: 'keyboard cat', resave: true, saveUninitialized: true }));
// safe twin
app.use(session({ secret: process.env.SESSION_SECRET, resave: false, saveUninitialized: false }));
