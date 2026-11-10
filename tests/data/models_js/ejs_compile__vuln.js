// expect: DF007
const ejs = require('ejs');
module.exports = (req, res) => {
  const tpl = ejs.compile('<h1>' + req.query.title + '</h1>');
  res.json({ html: tpl({}) });
};
