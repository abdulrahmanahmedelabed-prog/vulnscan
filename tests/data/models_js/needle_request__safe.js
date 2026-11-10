// expect-none: DF010
const needle = require('needle');
module.exports = (req, res) => {
  needle('get', 'https://api.example.com', (err, resp) => res.json(resp.body));
};
