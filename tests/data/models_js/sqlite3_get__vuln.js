// expect: DF004
const sqlite3 = require('sqlite3');
const sqlite = new sqlite3.Database('app.db');
module.exports = (req, res) => {
  sqlite.get("SELECT * FROM users WHERE name = '" + req.query.name + "'", (err, row) => res.json(row));
};
