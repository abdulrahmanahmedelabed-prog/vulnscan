// expect-none: DF004
const { Client } = require('pg');
const client = new Client();
module.exports = async (req, res) => {
  await client.query(`SELECT * FROM t WHERE name = ${client.escapeLiteral(req.query.n)}`);
};
