// expect: DF010
const got = require('got');
module.exports = (req, res) => {
  got.stream(req.query.src).pipe(res);
};
