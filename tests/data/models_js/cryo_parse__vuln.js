// expect: DF006
const Cryo = require('cryo');
module.exports = (req, res) => {
  const obj = Cryo.parse(req.cookies.state);
  res.json(obj);
};
