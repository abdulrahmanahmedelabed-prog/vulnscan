const Koa = require('koa');
const app = new Koa();
// FP: in Koa ctx.body is the RESPONSE body the app itself set; it is modelled as request input.
app.use(async (ctx, next) => {
  await next();
  const body = ctx.body;
  ctx.res.end(body);           // reported DF013, source "req.body"
});
app.use(async ctx => { ctx.body = 'static page'; });
// TP twin: the request body (koa-bodyparser) reflected
app.use(async ctx => { ctx.res.end('<p>' + ctx.request.body.name + '</p>'); });
