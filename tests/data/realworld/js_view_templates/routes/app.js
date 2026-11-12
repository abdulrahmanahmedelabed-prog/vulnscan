const express = require('express');
const router = express.Router();
router.post('/search', function (req, res) {
    var output = { searchTerm: req.body.name, safeTerm: req.body.other };
    res.render('app/products', { output: output, products: [] });
});
router.post('/escaped-only', function (req, res) {
    var output = { searchTerm: 'fixed', safeTerm: req.body.other };
    res.render('app/products', { output: output, products: [] });
});
router.get('/list', function (req, res) {
    res.render('app/products', { output: {}, products: [{ name: req.query.n }] });
});
router.get('/hbs', function (req, res) {
    res.render('hello', { bio: req.query.bio, name: req.query.name });
});
router.get('/hbs-safe', function (req, res) {
    res.render('hello', { bio: 'static', name: req.query.name });
});
router.get('/pug', (req, res) => res.render('page', { message: req.query.m, escaped: req.query.e }));
router.get('/pug-safe', (req, res) => res.render('page', { message: 'hi', escaped: req.query.e }));
router.post('/later', function (req, res) {
    db.find({}).then(products => {
        res.render('app/products', { output: { searchTerm: req.body.q }, products: products });
    });
});
module.exports = router;
