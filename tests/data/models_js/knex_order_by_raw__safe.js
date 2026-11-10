// expect-none: DF004
export async function list(req, res, knex) {
  const sort = ['name', 'price'].includes(req.query.sort) ? req.query.sort : 'name';
  return knex('items').select('*').orderBy(sort, 'desc');
}
