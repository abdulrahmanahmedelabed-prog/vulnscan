// expect: DF010
const request = require('request');
module.exports = (req, res) => {
  request(req.query.target, (e, r, body) => res.json({ len: body.length }));
};
