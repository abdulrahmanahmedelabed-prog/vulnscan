// expect-none: DF007
const ejs = require('ejs');
module.exports = (req, res) => {
  const tpl = ejs.compile('<h1><%= title %></h1>');
  res.json({ html: tpl({ title: req.query.title }) });
};
