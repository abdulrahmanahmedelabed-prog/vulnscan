// expect: DF015
const xpath = require('xpath');
module.exports = (req, res, doc) => {
  const expr = xpath.parse("//user[name='" + req.query.u + "']");
  res.json(expr.select({ node: doc }));
};
