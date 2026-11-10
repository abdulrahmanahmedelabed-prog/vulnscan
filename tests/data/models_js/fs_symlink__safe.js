// expect-none: DF011
const fs = require('fs');
module.exports = (req, res) => {
  fs.symlinkSync('/srv/releases/v2', '/srv/links/current');
};
