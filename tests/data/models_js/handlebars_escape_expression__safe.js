// expect-none: DF013
const Handlebars = require('handlebars');
module.exports = (req, res) => {
  res.send('<p>' + Handlebars.escapeExpression(req.query.msg) + '</p>');
};
