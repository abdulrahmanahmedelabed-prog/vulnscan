// expect: DF005
const fs = require('fs');
module.exports = (req, res) => {
  res.json({ exists: fs.existsSync(req.query.p) });
};
