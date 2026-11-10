// expect-none: DF003
const spawn = require('cross-spawn');
module.exports = function (req, res) {
  spawn.sync('git', ['--version']);
};
