// expect-none: DF004
const sqlite3 = require('sqlite3');
const level = require('level');
const sqlite = new sqlite3.Database('app.db');
const db = level('./kv');
module.exports = async (req, res) => {
  const cached = await db.get(req.query.name);
  sqlite.get('SELECT * FROM users WHERE name = ?', [req.query.name], (err, row) => res.json(row || cached));
};
