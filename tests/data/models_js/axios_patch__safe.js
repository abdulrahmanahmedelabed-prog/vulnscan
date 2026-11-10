// expect-none: DF010
const axios = require('axios');
const HOOKS = ['https://hooks.example.com/a'];
module.exports = async (req, res) => {
  if (HOOKS.includes(req.body.callback)) {
    await axios.patch(req.body.callback, { ok: true });
  }
};
