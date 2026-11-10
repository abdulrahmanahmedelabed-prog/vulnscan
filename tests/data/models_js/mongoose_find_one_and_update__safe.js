// expect-none: DF004
const User = require('./models/user');
exports.promote = async (req, res) => {
  await User.findOneAndUpdate({ name: 'root' }, { role: 'admin' });
};
