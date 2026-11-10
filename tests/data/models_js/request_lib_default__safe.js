// expect-none: DF010
const request = require('request');
module.exports = (req, res) => {
  request('https://status.example.com', (e, r, body) => res.json({ len: body.length }));
};
