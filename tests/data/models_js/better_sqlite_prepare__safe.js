// expect-none: DF004
const Database = require('better-sqlite3');
const db = new Database('app.db');
module.exports = (req, res) => {
  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(req.body.email);
  res.json(row);
};
