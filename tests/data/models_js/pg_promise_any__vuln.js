// expect: DF004
const pgp = require('pg-promise')();
const db = pgp('postgres://localhost/app');
module.exports = async (req, res) => {
  res.json(await db.any('SELECT * FROM t WHERE name = \'' + req.query.n + '\''));
};
