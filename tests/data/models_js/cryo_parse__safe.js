// expect-none: DF006
module.exports = (req, res) => {
  const obj = JSON.parse(req.cookies.state);
  res.json(obj);
};
