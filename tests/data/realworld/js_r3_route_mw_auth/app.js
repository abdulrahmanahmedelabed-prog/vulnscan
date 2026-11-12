const express = require('express');
const auth = require('./auth');
const router = express.Router();
// FP: authentication is enforced by route middleware, not a decorator
router.get('/admin', auth.isAuthenticated, function (req, res) { res.render('admin'); });
// TP twin: no middleware (should still be reported as info)
router.get('/open', function (req, res) { res.render('open'); });
module.exports = router;
