// expect: DF004
const knex = require('knex')({ client: 'pg' });
const express = require('express');
const app = express();

app.get('/users', async (req, res) => {
  const rows = await knex('users').whereRaw(`name = '${req.query.name}'`);
  res.json(rows);
});
