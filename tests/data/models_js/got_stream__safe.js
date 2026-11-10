// expect-none: DF010
const got = require('got');
module.exports = (req, res) => {
  got.stream('https://cdn.example.com/' + encodeURIComponent(req.query.src)).pipe(res);
};
