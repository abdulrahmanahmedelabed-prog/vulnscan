// expect: DF002
const { exec } = require('child_process');
module.exports = (req, res) => {
  exec('grep ' + req.query.pattern + ' /var/log/app.log');
};
