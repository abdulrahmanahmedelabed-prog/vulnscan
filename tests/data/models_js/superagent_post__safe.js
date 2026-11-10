// expect-none: DF010
const superagent = require('superagent');
module.exports = async (req, res) => {
  await superagent.post('https://api.example.com/x').send({ q: req.query.url });
};
