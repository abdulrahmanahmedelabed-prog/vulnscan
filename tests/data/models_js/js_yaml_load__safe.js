// expect-none: DF006
const yaml = require('js-yaml');
module.exports = (req, res) => {
  res.json(JSON.parse(req.body.config));
};
