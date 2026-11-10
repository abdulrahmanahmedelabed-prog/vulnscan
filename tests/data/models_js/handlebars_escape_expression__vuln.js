// expect: DF013
module.exports = (req, res) => {
  res.send('<p>' + req.query.msg + '</p>');
};
