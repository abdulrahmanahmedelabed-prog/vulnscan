// expect-none: DF002
const { exec } = require('child_process');
module.exports = async function middleware(ctx, next) {
  exec('echo ' + parseInt(ctx.get('X-Trace-Id'), 10));
  await next();
};
