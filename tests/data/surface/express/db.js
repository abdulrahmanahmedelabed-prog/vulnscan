const mysql = require('mysql');
const pool = mysql.createPool({ host: 'localhost' });
module.exports = { query: (sql) => new Promise((ok) => pool.query(sql, (e, r) => ok(r))) };
