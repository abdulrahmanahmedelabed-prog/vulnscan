// expect: DF010
const axios = require('axios');
module.exports = async (req, res) => {
  await axios.patch(req.body.callback, { ok: true });
};
