// expect: DF004
export async function list(req, res, knex) {
  return knex('items').select('*').orderByRaw(req.query.sort + ' DESC');
}
