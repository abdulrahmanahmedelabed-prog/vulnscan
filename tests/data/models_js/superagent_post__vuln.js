// expect: DF010
const superagent = require('superagent');
module.exports = async (req, res) => {
  await superagent.post(req.query.url).send({});
};
