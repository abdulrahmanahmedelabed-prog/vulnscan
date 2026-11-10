// expect: DF007
const nunjucks = require('nunjucks');
module.exports = (req, res) => {
  res.json({ out: nunjucks.compile(req.body.tpl).render({}) });
};
