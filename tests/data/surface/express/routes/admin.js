const express = require('express');
const fs = require('fs');
const router = express.Router();

router.get('/logs', (req, res) => {
  res.send(fs.readFileSync('/var/log/' + req.query.file, 'utf8'));
});

router.route('/settings')
  .get(listSettings)
  .put(saveSettings);

function listSettings(req, res) {
  res.json({});
}

function saveSettings(req, res) {
  res.json({ saved: req.body.value });
}

module.exports = router;
