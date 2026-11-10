// expect: DF011
const fs = require('fs');
module.exports = (req, res) => {
  fs.symlinkSync(req.body.target, '/srv/links/current');
};
