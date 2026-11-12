const Koa = require('koa');
const Router = require('@koa/router');
const jwt = require('koa-jwt');
const axios = require('axios');

const app = new Koa();
const router = new Router({ prefix: '/api' });

router.get('/proxy', async (ctx) => {
  const r = await axios.get(ctx.query.url);
  ctx.body = r.data;
});

router.post('/notes', jwt({ secret: process.env.JWT_KEY }), async (ctx) => {
  ctx.body = { saved: ctx.request.body.text };
});

app.use(router.routes());
app.listen(3000);
