const express = require('express');
const swig = require('swig');
const app = express();
app.engine('.html', require('consolidate').swig);
swig.setDefaults({ autoescape: false });
app.post('/login', function (req, res) {
    return res.render('login', { userName: req.body.userName, loginError: 'Invalid user' });
});
app.post('/login-static', function (req, res) {
    return res.render('login', { userName: 'guest', loginError: 'Invalid user' });
});
