// expect: DF004
const mysql = require('mysql');
const connection = mysql.createConnection({});
module.exports = (req, res) => {
  connection.query('SELECT * FROM t ORDER BY ' + req.query.col);
};
