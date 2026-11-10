// expect-none: DF007
const nunjucks = require('nunjucks');
module.exports = (req, res) => {
  res.json({ out: nunjucks.compile('Hello {{ name }}').render({ name: req.body.name }) });
};
