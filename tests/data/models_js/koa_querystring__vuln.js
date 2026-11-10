// expect: DF004
const Koa = require('koa');
const app = new Koa();
app.use(async (ctx) => {
  ctx.body = await db.query('SELECT * FROM logs WHERE q = \'' + ctx.querystring + '\'');
});
