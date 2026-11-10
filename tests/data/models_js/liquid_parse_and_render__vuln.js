// expect: DF007
const { Liquid } = require('liquidjs');
const engine = new Liquid();
module.exports = async (req, res) => {
  res.json({ out: await engine.parseAndRender(req.body.template, {}) });
};
