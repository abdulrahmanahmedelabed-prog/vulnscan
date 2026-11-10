// expect-none: DF002
const { exec } = require('child_process');
const shellescape = require('shell-escape');
module.exports = (req, res) => {
  exec('grep ' + shellescape([req.query.pattern]) + ' /var/log/app.log');
};
