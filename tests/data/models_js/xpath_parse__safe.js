// expect-none: DF015
const xpath = require('xpath');
module.exports = (req, res, doc) => {
  const expr = xpath.parse('//user[name=$name]');
  res.json(expr.select({ node: doc, variables: { name: req.query.u } }));
};
