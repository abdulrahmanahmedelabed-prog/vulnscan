// expect-none: DF005
const fs = require('fs');
const path = require('path');
module.exports = (req, res) => {
  res.json({ exists: fs.existsSync(path.join('/srv', path.basename(req.query.p))) });
};
