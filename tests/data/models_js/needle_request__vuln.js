// expect: DF010
const needle = require('needle');
module.exports = (req, res) => {
  needle('get', req.query.u, (err, resp) => res.json(resp.body));
};
